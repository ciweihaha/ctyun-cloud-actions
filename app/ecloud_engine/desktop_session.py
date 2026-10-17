"""
桌面会话保活（L2 资源登记层）—— 基于抓包逆向的 HTTP 保活。

分层说明（详见 docs/protocol-layers.md）：
  L1 账号 HTTP / L2 desktopUptime·machineConnect
  本模块只做 **L2**：
    1. POST /resource/desktopUptime  {accessToken, instanceId}
       -> 返回 "X小时X分X秒"
    2. POST /session/machineConnect  {ticket, accessToken, machineId, ...}
       -> 返回 {connectId}

【已纠偏 2026-07】旧注释「不需要 SPICE / 无 VDI 可维持桌面在线」仅对 L2 登记成立。
用户实测：仅 L2 时桌面仍会不可用/被回收 —— 即 HTTP 层探针并不能完全保证桌面在线
（若未来要更接近"真保活"，需要逆向厂商 VDI 的 SPICE 显示面心跳；当前版本未实现）。

凭证链：
  accessToken  ← 登录获得（token:<id>:<hex>accountPwd）
  instanceId   ← 桌面列表 API 返回（CCA-<32hex>）
  ticket       ← 会话票据（ticket:<id>:<hex>accountPwd）
  machineId    ← 桌面列表 API 返回（UUID）

本模块支持：
  (a) 从 cloud_pc.json 读取已保存的桌面凭证（用户从抓包/客户端提取）
  (b) 登录后自动尝试拉取桌面列表获取 instanceId/machineId
"""
import logging
import time
import uuid

import config
from ecloud_client import EcloudHttpUtil, EcloudError

log = logging.getLogger("desktop")


class DesktopSession:
    """一个云电脑桌面的会话保活器。"""

    def __init__(self, http: EcloudHttpUtil, instance_id: str,
                 machine_id: str = "", machine_name: str = "",
                 ticket: str = "", login_uid: str = ""):
        self.http = http
        self.instance_id = instance_id
        self.machine_id = machine_id
        self.machine_name = machine_name
        self.ticket = ticket
        self.last_uptime = ""
        self.last_error = ""
        self.last_error_code = ""
        self.last_error_token_expired = False
        # 会话标识（UUID，连接时生成，保活期间保持不变）
        self.connect_id = str(uuid.uuid4())
        self.login_uid = login_uid or str(uuid.uuid4())

    def report_uptime(self) -> str:
        """
        查询/刷新桌面运行时长（保活核心）。
        已通过真实抓包验证：返回 "X小时X分X秒"。

        POST /resource/desktopUptime {accessToken, instanceId}
        """
        resp = self.http.post(config.Endpoint.DESKTOP_UPTIME, {
            "instanceId": self.instance_id,
        })
        if resp is None:
            raise EcloudError({
                "errorCode": "NO_UPTIME",
                "errorMessage": "desktopUptime 未返回运行时长，桌面可能已关机",
            })
        if isinstance(resp, dict):
            uptime = (
                resp.get("uptime")
                or resp.get("upTime")
                or resp.get("runningTime")
                or resp.get("duration")
            )
            if not uptime:
                raise EcloudError({
                    "errorCode": "NO_UPTIME",
                    "errorMessage": f"desktopUptime 未返回运行时长: {resp}",
                })
        else:
            uptime = str(resp)
        if not uptime or uptime == "None":
            raise EcloudError({
                "errorCode": "NO_UPTIME",
                "errorMessage": "desktopUptime 未返回运行时长，桌面可能已关机",
            })
        self.last_uptime = uptime
        self.last_error = ""
        self.last_error_code = ""
        self.last_error_token_expired = False
        log.info("桌面 %s 运行时长: %s", self.instance_id[:16], uptime)
        return uptime

    def register_session(self) -> str:
        """
        登记桌面会话（让服务端知道这个会话存在）。
        抓包显示连接成功时调用一次。

        POST /session/machineConnect
        {ticket, accessToken, machineId, machineName, status:success, flag:true,
         clientConnectId, clientLoginUid}

        返回 {connectId}。
        """
        if not self.ticket:
            log.warning("无 ticket，跳过 session 登记")
            return ""
        resp = self.http.post(config.Endpoint.SESSION_MACHINE_CONNECT, {
            "ticket": self.ticket,
            "machineId": self.machine_id,
            "machineName": self.machine_name,
            "status": "success",
            "flag": True,
            "clientConnectId": self.connect_id,
            "clientLoginUid": self.login_uid,
        })
        if isinstance(resp, dict) and "connectId" in resp:
            self.connect_id = resp["connectId"]
            log.info("会话已登记: connectId=%s", self.connect_id)
        return self.connect_id

    def keepalive_once(self) -> bool:
        """
        执行一次桌面保活。
        策略：report_uptime 为主（已验证有效）；**静默附带**两个会话侧信号（见下方注释）。
        """
        ok = False
        try:
            self.report_uptime()
            ok = True
        except EcloudError as e:
            self.last_error = f"[{e.code}] {e.message}"
            self.last_error_code = e.code
            self.last_error_token_expired = _is_token_expired(e)
            log.warning("desktopUptime 失败: %s", e)
        # ── 静默会话侧信号（2026-09-27 用户要求：默认执行、UI 不显示、日志不显示）──────────
        # 目的：把保活信号从"查询时长"扩展到"会话在场"（两类信号见方法注释）。
        # 纪律：① 绝不写日志、绝不进 metrics/UI；② 任何失败一律吞掉，绝不影响本方法返回值；
        #      ③ 每个往返独立 try/except —— 一个信号失败不得拖累另一个。
        for signal in (self.renew_session_status, self.report_connect_event):
            try:
                signal()
            except Exception:
                pass
        return ok

    def renew_session_status(self) -> bool:
        """
        会话状态续期（静默信号 A）：POST /session/updateSessionStatus
        {instanceId, machineId, loginStatus: 1, loginUid}
        让服务端会话状态机看到"有客户端在线"——真机 2026-09-27 验证被接受（响应 "ok"）。
        注意：machineConnect 需要真实会话 ticket（仅真实连接握手产生，抓包才能拿到），
        故此处用无票的 updateSessionStatus 承载同一"会话在场"语义。
        本方法**不得**写日志、不得改动 metrics —— 由调用方吞掉异常。
        """
        if not self.instance_id or not self.machine_id:
            return False
        self.http.post(config.Endpoint.UPDATE_SESSION_STATUS, {
            "instanceId": self.instance_id,
            "machineId": self.machine_id,
            "loginStatus": 1,
            "loginUid": self.login_uid,
        })
        return True

    def report_connect_event(self) -> bool:
        """
        连接事件上报（静默信号 B）：POST /machine/pushConnectEventData
        CloudEvents 形态（真机 2026-09-27 逐字段试探确认，服务端响应 "ok"）：
        specversion / id / source / type / datacontenttype / time(毫秒) / data{instanceId, machineId}。
        本方法**不得**写日志、不得改动 metrics —— 由调用方吞掉异常。
        """
        if not self.instance_id or not self.machine_id:
            return False
        self.http.post(config.Endpoint.PUSH_CONNECT_EVENT, {
            "specversion": "1.0",
            "id": str(uuid.uuid4()),
            "source": "ecloud-cloudpc",
            "type": "machine.connect",
            "datacontenttype": "application/json",
            "time": int(time.time() * 1000),
            "data": {
                "instanceId": self.instance_id,
                "machineId": self.machine_id,
            },
        })
        return True


def _is_token_expired(err: EcloudError) -> bool:
    # 与 keepalive._is_token_expired 对齐：去掉过宽的 "access"（会误伤 accessKey /
    # access denied / "no access to desktop" 等【非】token 错误）。拿不到在线时长时，
    # 只有真正的 token 失效才应触发密码重登；桌面关机/instanceId 无效/瞬时错误绝不重登，
    # 否则会白白多打一次 /login/verify（在设备信任被撤销的账号上还可能引发短信）。
    msg = (err.message or "").lower()
    hints = ["token", "登录失效", "未登录", "请重新登录", "授权", "过期"]
    return any(h.lower() in msg for h in hints)


def run_desktop_keepalive(http: EcloudHttpUtil, instance_id: str,
                          machine_id: str = "", ticket: str = "",
                          interval: int = 300, max_rounds: int | None = None,
                          relogin_fn=None) -> None:
    """
    桌面会话保活主循环。

    :param http: 已登录的 EcloudHttpUtil
    :param instance_id: 云电脑实例 ID（CCA-开头）
    :param machine_id: 桌面机 ID（UUID，可选，session 登记用）
    :param ticket: 会话票据（可选，session 登记用）
    :param interval: 保活间隔秒数（默认 5 分钟）
    :param max_rounds: 最大轮数（None=无限）
    :param relogin_fn: token 失效时的重新登录回调
    """
    session = DesktopSession(http, instance_id, machine_id, ticket=ticket)

    # 首次：尝试登记会话（可选）
    if ticket:
        try:
            session.register_session()
        except EcloudError as e:
            log.warning("初次 session 登记失败（忽略）: %s", e)

    log.info("启动桌面保活: instance=%s, 间隔=%ds", instance_id[:20], interval)
    rounds = 0
    while max_rounds is None or rounds < max_rounds:
        rounds += 1
        try:
            alive = session.keepalive_once()
            if alive:
                log.info("[%d] 桌面保活成功", rounds)
            else:
                detail = session.last_error or "桌面保活失败"
                log.warning("[%d] 桌面保活失败: %s", rounds, detail)
                if relogin_fn and session.last_error_token_expired:
                    token = relogin_fn()
                    if token:
                        http.set_token(token)
                        log.info("[%d] 已重新登录，继续保活", rounds)
                    else:
                        log.error("[%d] 重新登录失败，退出", rounds)
                        break
        except Exception as e:
            log.exception("[%d] 保活异常: %s", rounds, e)
        if max_rounds is None or rounds < max_rounds:
            time.sleep(interval)
