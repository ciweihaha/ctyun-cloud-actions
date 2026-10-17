#!/usr/bin/env python3
"""
移动公众云电脑 · 协议侧车（stdin/stdout JSON-Lines IPC）
========================================================

本进程是 ctyun-dashboard 的**移动公众**保活内核，由 Node 主进程以子进程方式托管。
设计约束（2026-09-24 用户拍板）：

  1. **三平台保活机制互不重叠**：本侧车只承载 `ecloud`（移动公众）；天翼云的原生
     逻辑与移动爱家的 SOHO/CAG 逻辑各自留在 Node 侧，彼此不共享保活代码。
     日志也独立：本侧车所有日志经 `event:"log"` 且带 `platform:"ecloud"` 上报。
  2. **调度归 Node**：本侧车**不自建定时器**。保活频率、开关判定、配额全部由
     Node 的 `scheduler.js` + `taskGate()` 决定，这里只提供「执行一次」的原子操作。
     —— 这样才不会与既有调度器形成第二套真相。

协议（每行一个 JSON，stdout 只承载报文，日志一律走 stderr）：

  请求  {"id":"a5","op":"health","sessionId":"...","params":{...}}
  响应  {"id":"a5","ok":true,"data":{...}} | {"id":"a5","ok":false,"error":"...","detail":"..."}
  事件  {"event":"log","platform":"ecloud","level":"info","msg":"..."}   ← 主动上报

  约定：`sessionId` 既可放在报文顶层（推荐，与 Node 桥接层一致），也可放在 params 内。
  main() 会把顶层 sessionId 回填进 params，两种写法都能被 op 读到 —— 这条曾经是
  一个真实缺陷（桥接层发顶层、op 读 params ⇒ 永远"会话不存在"），已由回归组 14 守住。

ops:
  health           探活：返回引擎版本、凭据是否加载、Python 版本
  login.begin      交互式密码登录（受 10 分钟 3 次限流保护；可能返回 need_* 分支）
  login.sendSms    发送短信验证码（need_* 分支后**必须**调用，否则手机收不到码）
  login.sms        完成短信类分支（need_device_trust / need_two_factor / need_enhanced_sms）
  session.restore  用本地保存的 token 恢复会话（Node 重启后免重复登录；不含密码）
  session.relogin  密码重登刷新 token（带冷却期，防止 401 风暴 → 短信轰炸）
  desktop.list     拉桌面列表（含 instanceId / machineId / originCompanyCode / powerState）
  desktop.power    桌面电源操作（available=开机 / shutdown=关机 / restart=重启，用户显式触发）
  keepalive.l1     账号态保活探针一次（三态：ok=true/false/null）
  keepalive.l2     桌面登记保活一次（desktopUptime）
  logout           登出并清理会话（含本地落盘记录）
  shutdown         优雅退出
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
import traceback
import uuid
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# stdout 只许承载 IPC 报文 ⇒ 日志一律 stderr
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="[ecloud-engine] %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("ecloud.sidecar")

PROTOCOL_VERSION = 2


# --------------------------------------------------------------------------
# IPC 基础
# --------------------------------------------------------------------------
def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _emit_log(level: str, msg: str, **extra) -> None:
    _emit({"event": "log", "platform": "ecloud", "level": level,
           "msg": msg, "ts": int(time.time() * 1000), **extra})


def _mask_mobile(mobile: str) -> str:
    """手机号脱敏（前 3 后 4）—— 日志里绝不出现完整号码。"""
    m = (mobile or "").strip()
    if len(m) < 7:
        return "***" if m else "(无)"
    return f"{m[:3]}****{m[-4:]}"


# --------------------------------------------------------------------------
# 延迟导入：凭据缺失/依赖缺失时给出结构化错误，而不是崩在 import 上
# --------------------------------------------------------------------------
_IMPORT_ERR: str | None = None
try:
    import config as _config
    from ecloud_client import EcloudHttpUtil, EcloudError
    import device as device_mod
    import login as login_mod
    import desktop_list as desktop_list_mod
    from desktop_session import DesktopSession
    import keepalive as keepalive_mod
    import login_rate_limit as rate_limit_mod
except Exception as _e:  # 显式展开错误，绝不吞
    _IMPORT_ERR = f"{type(_e).__name__}: {_e}"
    _config = None
    traceback.print_exc(file=sys.stderr)


# --------------------------------------------------------------------------
# 会话表：sessionId(=账号 id) -> {http, token, ...}
# --------------------------------------------------------------------------
_SESSIONS: dict[str, dict] = {}

# 自动重登冷却期：即使出现"全端点 token 失效"，也不允许高频密码重登。
# 实测教训：单点 401 就重登会每 10~20 分钟打一次 /login/verify，
# 触发风控 → 手机短信轰炸。默认 20 分钟，可用环境变量收紧/放宽。
_RELOGIN_COOLDOWN_SEC = max(60, int(os.environ.get("ECLOUD_RELOGIN_COOLDOWN_SEC") or 1200))

# 会话落盘文件：**只存 token / deviceUid 等非敏感字段，绝不写密码**。
# 目的是 Node 主进程重启（或侧车被拉起重启）后不必重新走一次密码登录。
_SESSION_FILE = Path(os.environ.get(
    "ECLOUD_SESSION_FILE",
    os.path.join(_HERE, "data", "sessions.json"),
))


def _require_ready() -> None:
    if _IMPORT_ERR:
        raise RuntimeError(f"侧车内核不可用: {_IMPORT_ERR}")


def _session(session_id: str, required: bool = True) -> dict:
    s = _SESSIONS.get(session_id or "")
    if s is None and required:
        raise RuntimeError(f"会话不存在或未登录: {session_id!r}")
    return s or {}


def _new_http(device_uid: str) -> "EcloudHttpUtil":
    dev = device_mod.detect(device_uid=device_uid or None)
    return EcloudHttpUtil(dev.to_common_params())


# --------------------------------------------------------------------------
# 会话落盘（免重复登录）—— 只写非敏感字段
# --------------------------------------------------------------------------
def _persist_sessions() -> None:
    try:
        data: dict[str, dict] = {}
        for sid, s in _SESSIONS.items():
            if not s.get("accessToken"):
                continue
            data[sid] = {
                "username": s.get("username") or "",
                "deviceUid": s.get("deviceUid") or "",
                "mobile": s.get("mobile") or "",
                "accessToken": s.get("accessToken") or "",
                "savedAt": int(time.time()),
            }
        _SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _SESSION_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, _SESSION_FILE)
    except Exception as e:  # 落盘失败不影响本次运行，但必须留证
        _emit_log("warn", f"会话落盘失败（不影响运行）: {type(e).__name__}: {e}")


def _load_persisted() -> dict:
    try:
        return json.loads(_SESSION_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except Exception as e:
        _emit_log("warn", f"会话文件不可读，已忽略: {type(e).__name__}: {e}")
        return {}


# --------------------------------------------------------------------------
# ops
# --------------------------------------------------------------------------
def op_health(params: dict) -> dict:
    creds = "missing"
    cred_err = ""
    try:
        _require_ready()
        _config.ACCESS_KEY, _config.SECRET_KEY  # noqa: B018 —— 触发已加载断言
        creds = "loaded"
    except Exception as e:
        cred_err = f"{type(e).__name__}: {e}"
    return {
        "engine": "ecloud",
        "protocolVersion": PROTOCOL_VERSION,
        "credentials": creds,
        "credentialError": cred_err,
        "importError": _IMPORT_ERR or "",
        "python": sys.version.split()[0],
        "pid": os.getpid(),
        "sessions": len(_SESSIONS),
        # 契约自证：把 main() 归一后的 sessionId 回显出来。
        # 顶层 sessionId 若未被回填进 params，这里会是空串 —— 诊断"会话总是找不到"时先看它。
        "sessionId": params.get("sessionId") or "",
    }


def op_login_begin(params: dict) -> dict:
    """交互式密码登录。受 10 分钟 / 3 次限流保护（防止 UI 连点造成风控）。"""
    _require_ready()
    sid = params.get("sessionId") or ""
    username = (params.get("username") or "").strip()
    password = params.get("password") or ""
    device_uid = params.get("deviceUid") or ""
    if not sid or not username or not password:
        raise ValueError("login.begin 需要 sessionId / username / password")

    lock = rate_limit_mod.guard_login(username)
    if lock:
        _emit_log("warn", f"交互登录被限流拦截: {lock.get('error')}")
        return {
            "status": "locked",
            "locked": True,
            "error": lock.get("error") or "",
            "unlockInSec": lock.get("unlock_in_sec") or 0,
        }

    http = _new_http(device_uid)
    r = login_mod.login_with_password(http, username, password)
    status = r.get("status")

    sess = {
        "http": http, "username": username, "password": password,
        "deviceUid": device_uid, "mobile": r.get("mobile") or "",
        "loginCode": r.get("login_code"), "status": status,
        "accessToken": http.access_token, "updatedAt": time.time(),
    }
    _SESSIONS[sid] = sess
    if status == login_mod.LoginResult.SUCCESS:
        _persist_sessions()
    _emit_log("info", f"登录分支: {status}")

    return {
        "status": status,
        "mobile": r.get("mobile") or "",
        "accessToken": http.access_token or "",
        "error": r.get("error") or "",
        "errorCode": r.get("error_code") or "",
    }


def op_login_sms(params: dict) -> dict:
    """完成短信类登录分支。

    ⚠️ `branch` 必须是 `login.begin` 原样返回的 **状态值**，
    即 `login.LoginResult.NEED_*`（need_device_trust / need_two_factor /
    need_enhanced_sms）—— 这里一律用常量比对，**不得自造短名**。
    历史缺陷：曾用 trust/twoFactor/enhanced 这套自造名，与登录接口的产出对不上，
    表现为「短信验证码下发失败: 未知的短信分支: 'need_device_trust'」。
    """
    _require_ready()
    sid = params.get("sessionId") or ""
    branch = (params.get("branch") or "").strip()
    code = params.get("code") or ""
    s = _session(sid)
    http: "EcloudHttpUtil" = s["http"]
    mobile = params.get("mobile") or s.get("mobile") or ""
    username = s.get("username") or ""
    is_temp = bool(params.get("isTemporary"))

    if branch == login_mod.LoginResult.NEED_DEVICE_TRUST:
        r = login_mod.complete_device_trust(
            http, mobile, code, login_username=username,
            is_temporary=is_temp, code=s.get("loginCode"),
        )
    elif branch == login_mod.LoginResult.NEED_TWO_FACTOR:
        r = login_mod.complete_two_factor(
            http, mobile, username, s.get("password") or "", code,
            code=s.get("loginCode"),
        )
    elif branch == login_mod.LoginResult.NEED_ENHANCED_SMS:
        r = login_mod.complete_enhanced_sms(
            http, mobile, username, code, code=s.get("loginCode"),
        )
    elif branch == login_mod.LoginResult.NEED_4A:
        # 平台侧该分支尚未开放；如实拒绝，不假装能做
        raise ValueError("4A 短信验证暂未实现（平台侧尚未开放）")
    else:
        raise ValueError(
            f"未知的短信分支: {branch!r}（应为 login.LoginResult 的 need_* 值）"
        )

    if r.get("status") == login_mod.LoginResult.SUCCESS:
        s["accessToken"] = http.access_token
        s["status"] = r.get("status")
        _persist_sessions()
    s["updatedAt"] = time.time()
    return {
        "status": r.get("status"),
        "accessToken": http.access_token or "",
        "error": r.get("error") or "",
    }


def op_session_restore(params: dict) -> dict:
    """用本地保存的 token 重建会话（Node 重启后免重复密码登录）。"""
    _require_ready()
    sid = params.get("sessionId") or ""
    if not sid:
        raise ValueError("session.restore 需要 sessionId")
    username = (params.get("username") or "").strip()
    saved = _load_persisted().get(sid)
    if not saved or not saved.get("accessToken"):
        return {"restored": False, "reason": "无已保存的会话"}
    if username and saved.get("username") and saved["username"] != username:
        # 账号被改过（换号/改密）→ 旧 token 不得复用
        return {"restored": False, "reason": "已保存会话属于其它账号"}

    http = _new_http(saved.get("deviceUid") or params.get("deviceUid") or "")
    http.set_token(saved["accessToken"])
    _SESSIONS[sid] = {
        "http": http,
        "username": saved.get("username") or username,
        "password": "",  # 刻意不落盘：需要重登时由 Node 每次提供
        "deviceUid": saved.get("deviceUid") or "",
        "mobile": saved.get("mobile") or "",
        "loginCode": None,
        "status": "restored",
        "accessToken": saved["accessToken"],
        "updatedAt": time.time(),
        "restoredAt": time.time(),
    }
    _emit_log("info", "已从本地保存的 token 恢复会话（免重复登录）")
    return {"restored": True, "accessToken": saved["accessToken"]}


def op_session_relogin(params: dict) -> dict:
    """密码重登刷新 token。带冷却期 + 限流记账，杜绝 401 风暴引发短信轰炸。"""
    _require_ready()
    sid = params.get("sessionId") or ""
    s = _session(sid)
    now = time.time()
    last = float(s.get("reloginAt") or 0)
    if last and now - last < _RELOGIN_COOLDOWN_SEC:
        wait = int(_RELOGIN_COOLDOWN_SEC - (now - last))
        _emit_log("warn", f"重登被冷却期拦截（还需 {wait}s），本轮不重登")
        return {"relogged": False, "skipped": "cooldown", "nextInSec": wait}

    username = (params.get("username") or s.get("username") or "").strip()
    password = params.get("password") or s.get("password") or ""
    device_uid = params.get("deviceUid") or s.get("deviceUid") or ""
    if not username or not password:
        _emit_log("error", "重登缺少账号或密码（Node 每次都必须提供）")
        return {"relogged": False, "skipped": "no_credentials"}

    # 记账 + 冷却打点必须在真正发请求之前落定，异常路径也不会漏记
    s["reloginAt"] = now
    rate_limit_mod.record_attempt(username)

    http = _new_http(device_uid)
    r = login_mod.login_with_password(http, username, password)
    status = r.get("status")
    if status == login_mod.LoginResult.SUCCESS:
        s.update({
            "http": http, "username": username, "password": password,
            "deviceUid": device_uid, "accessToken": http.access_token,
            "status": status, "updatedAt": time.time(),
        })
        _persist_sessions()
        # quiet=true：调用方（如周期主动续期）自行落一条更准确的日志，避免"重登成功"误导排查
        if not params.get("quiet"):
            _emit_log("info", "重登成功，token 已刷新")
        return {"relogged": True, "status": status,
                "accessToken": http.access_token or ""}

    _emit_log("error", f"重登未成功: status={status} error={r.get('error') or ''}")
    return {
        "relogged": False,
        "status": status,
        "error": r.get("error") or "",
        "needInteractive": status in (
            login_mod.LoginResult.NEED_DEVICE_TRUST,
            login_mod.LoginResult.NEED_TWO_FACTOR,
            login_mod.LoginResult.NEED_ENHANCED_SMS,
            login_mod.LoginResult.NEED_4A,
        ),
        "nextInSec": _RELOGIN_COOLDOWN_SEC,
    }


def op_login_send_sms(params: dict) -> dict:
    """发送短信验证码 —— 按登录分支三路分发（codeType 必须与校验场景一致）。

    ⚠️ **这一步不可省**：官方客户端在拿到服务端返回的 mobile 后**会立刻发码**，
    服务端并不会因为密码登录返回 30002009/30002060/30002063 就替我们发短信。
    漏掉它的表现是「界面让你输验证码，但手机永远收不到」—— 静默不可用，
    与"假成功"同源。因此本 op 失败必须原样抛错，绝不吞。

    三路分发（codeType 必须与后续校验场景一致，否则真网返回 30002004）：
      - need_two_factor   : /login/special/getSecondauthSms（专用发码接口）
      - need_device_trust : /login/sendVerifySms + codeType="trust"（未授信设备）
      - need_enhanced_sms : /login/sendVerifySms + codeType="login"

    分支名一律取 `login_mod.LoginResult.NEED_*`（`login.begin` 的产出值），
    不得自造短名 —— 见 op_login_sms 的历史缺陷说明。
    """
    _require_ready()
    sid = params.get("sessionId") or ""
    branch = (params.get("branch") or "").strip()
    s = _session(sid)
    http: "EcloudHttpUtil" = s["http"]
    mobile = (params.get("mobile") or s.get("mobile") or "").strip()
    username = s.get("username") or ""
    if not mobile:
        raise ValueError("login.sendSms 需要 mobile（密码登录未返回手机号，无法发码）")

    if branch == login_mod.LoginResult.NEED_TWO_FACTOR:
        r = login_mod.send_two_factor_sms(http, mobile, username)
    elif branch == login_mod.LoginResult.NEED_DEVICE_TRUST:
        r = login_mod.send_sms(http, mobile, code_type="trust")
    elif branch == login_mod.LoginResult.NEED_ENHANCED_SMS:
        r = login_mod.send_sms(http, mobile, code_type="login")
    elif branch == login_mod.LoginResult.NEED_4A:
        # 平台侧该分支尚未开放；如实拒绝，不假装已发码
        raise ValueError("4A 短信验证暂未实现（平台侧尚未开放），无法发码")
    else:
        raise ValueError(
            f"未知的短信分支: {branch!r}（应为 login.LoginResult 的 need_* 值）"
        )

    s["mobile"] = mobile
    s["updatedAt"] = time.time()
    _emit_log("info", f"验证码已下发至 {_mask_mobile(mobile)} (branch={branch})")
    return {
        "sent": True,
        "mobile": mobile,
        "branch": branch,
        "raw": r if isinstance(r, dict) else {},
    }


def op_desktop_list(params: dict) -> dict:
    _require_ready()
    s = _session(params.get("sessionId") or "")
    desktops = desktop_list_mod.get_desktop_list(s["http"])

    # 【2026-09-25 用户要求·第七轮】逐台带上"运行中 / 已关机"的运行状态，
    # 供卡片「名下云主机」列表渲染状态徽章（与移动爱家一致）。
    #   - 状态真源：POST /user/getDesktopStatus -> machineStatusList[].resourceStatus
    #   - 归一化：desktop_list.normalize_power_state() → on / off / unknown
    # 关键：状态查询**失败不得拖垮列表本身** —— 拿不到就整批回落 'unknown'
    # （界面会如实显示"状态未知"，而不是误报"已关机"）。
    statuses = {}
    try:
        statuses = desktop_list_mod.get_desktop_status(s["http"], desktops)
    except Exception as e:  # 状态是增量信息，失败只降级、不抛出
        log.warning("查询桌面运行状态失败（列表照常返回，状态按未知处理）: %s", e)

    out = []
    for d in desktops:
        raw_status = statuses.get(d.instance_id, "") or ""
        # 【2026-09-28】平台自算的"开机操作能力"（machineOperateMap.powerOn）：
        #   operateEnable=true ⇒ 平台认为现在可以开机（即真实电源态为关/待开机）。
        #   这是比 resourceStatus 更硬的独立信号（实测：状态字段会滞后；而 09-26 关机
        #   事件中"在线时长"甚至能在关机状态下继续计时 —— 单一信号都不可全信）。
        pom = (d.operate_map or {}).get("powerOn") if isinstance(d.operate_map, dict) else None
        power_on_enable = bool(pom.get("operateEnable")) if isinstance(pom, dict) else None
        power_on_hint = str(pom.get("operateFailReason") or "") if isinstance(pom, dict) else ""
        out.append({
            "instanceId": d.instance_id,
            "machineId": d.machine_id,
            "machineName": d.machine_name,
            "originCompanyCode": d.origin_company_code,
            "resourcePoolUid": d.resource_pool_uid,
            # 服务端原始值（界面 title 里展示，便于排查对不上的新枚举）
            "resourceStatus": raw_status,
            # 归一后的三态：on / off / unknown（unknown 绝不当成 off）
            "powerState": desktop_list_mod.normalize_power_state(raw_status),
            # 平台操作层现算的"可开机"能力（None=平台未下发该表）
            "powerOnEnable": power_on_enable,
            "powerOnHint": power_on_hint,
        })
    return {"desktops": out, "count": len(out)}


# 电源操作白名单（协议取值来自官方 asar 客户端逆向，见 desktop_list.operate_desktop）：
#   available=开机（后端不认识 startup/powerOn）｜shutdown=关机｜restart=重启
_POWER_OPERATE_CN = {"available": "开机", "shutdown": "关机", "restart": "重启"}


def op_desktop_power(params: dict) -> dict:
    """桌面电源操作（开机 / 关机 / 重启）—— 用户显式触发的动作。

    与 L2 的两个静默信号不同：这是用户主动发起的操作，**允许也应当记日志**。
    真机 2026-09-28 验证：operate=available 被平台正确受理（服务端返回业务级
    "已开机不允许开机"，证明调用链通）。
    """
    _require_ready()
    s = _session(params.get("sessionId") or "")
    instance_id = str(params.get("instanceId") or "")
    machine_id = str(params.get("machineId") or "")
    machine_name = str(params.get("machineName") or "")
    operate = str(params.get("operate") or "").strip()
    if operate not in _POWER_OPERATE_CN:
        raise ValueError(f"不支持的电源操作: {operate or '(空)'}（仅 available/shutdown/restart）")
    if not machine_id:
        raise ValueError("desktop.power 需要 machineId（桌面列表里获取）")

    r = desktop_list_mod.operate_desktop(
        s["http"], machine_id, machine_name, operate,
        str(params.get("resourcePoolUid") or ""),
    )
    cn = _POWER_OPERATE_CN[operate]
    _emit_log("info", f"[{machine_name or instance_id}] 已向平台下发【{cn}】指令，平台已受理 (operate={operate})")
    s["updatedAt"] = time.time()
    return {
        "ok": True,
        "operate": operate,
        "message": f"已下发{cn}指令，平台已受理（状态落地需数秒到数十秒，稍后自动刷新）",
    }


def op_keepalive_l1(params: dict) -> dict:
    """L1 账号态保活一次。三态：ok=true/false/null（见 keepalive.keepalive_probe）。"""
    _require_ready()
    s = _session(params.get("sessionId") or "")
    outcome = keepalive_mod.keepalive_probe(s["http"])
    s["updatedAt"] = time.time()
    return {"ok": outcome.ok, "error": outcome.error or ""}


def op_keepalive_l2(params: dict) -> dict:
    """L2 桌面登记保活一次（desktopUptime；并静默附带会话侧信号，见 desktop_session.py）。"""
    _require_ready()
    s = _session(params.get("sessionId") or "")
    instance_id = params.get("instanceId") or ""
    if not instance_id:
        raise ValueError("keepalive.l2 需要 instanceId")
    # loginUid 必须跨轮稳定（服务端会话状态机据此识别同一登录会话）——按账号会话持久化
    if not s.get("loginUid"):
        s["loginUid"] = str(uuid.uuid4())
    ds = DesktopSession(
        s["http"], instance_id,
        machine_id=params.get("machineId") or "",
        machine_name=params.get("machineName") or "",
        login_uid=s["loginUid"],
    )
    alive = ds.keepalive_once()
    s["updatedAt"] = time.time()
    return {
        "ok": bool(alive),
        "uptime": ds.last_uptime or "",
        "error": ds.last_error or "",
        "tokenExpired": bool(ds.last_error_token_expired),
    }


def op_logout(params: dict) -> dict:
    sid = params.get("sessionId") or ""
    s = _SESSIONS.pop(sid, None)
    if s and not _IMPORT_ERR:
        try:
            login_mod.logout(s["http"])
        except Exception as e:  # 登出失败不影响本地清理
            _emit_log("warn", f"登出时出错（已忽略）: {type(e).__name__}: {e}")
    if s:
        _persist_sessions()
    return {"cleared": bool(s)}


_OPS = {
    "health": op_health,
    "login.begin": op_login_begin,
    "login.sendSms": op_login_send_sms,
    "login.sms": op_login_sms,
    "session.restore": op_session_restore,
    "session.relogin": op_session_relogin,
    "desktop.list": op_desktop_list,
    "desktop.power": op_desktop_power,
    "keepalive.l1": op_keepalive_l1,
    "keepalive.l2": op_keepalive_l2,
    "logout": op_logout,
}


# --------------------------------------------------------------------------
# 主循环
# --------------------------------------------------------------------------
def main() -> int:
    _emit_log("info", f"移动公众协议侧车启动 (protocol v{PROTOCOL_VERSION}, pid={os.getpid()})")
    if _IMPORT_ERR:
        _emit_log("error", f"内核导入失败: {_IMPORT_ERR}")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req_id = None
        try:
            req = json.loads(line)
            req_id = req.get("id")
            op = req.get("op")
            params = dict(req.get("params") or {})
            # 顶层 sessionId 回填进 params —— 桥接层把 sessionId 放在报文顶层，
            # 而各 op 统一从 params 读取；不做这次归一，所有会话内操作都会
            # 报"会话不存在"（这是一个曾经真实存在过的契约缺陷）。
            if req.get("sessionId") is not None and not params.get("sessionId"):
                params["sessionId"] = req.get("sessionId")

            if op == "shutdown":
                _emit({"id": req_id, "ok": True, "data": {"bye": True}})
                _emit_log("info", "侧车按指令退出")
                return 0

            handler = _OPS.get(op)
            if handler is None:
                raise ValueError(f"未知 op: {op!r}")
            data = handler(params)
            _emit({"id": req_id, "ok": True, "data": data})
        except Exception as e:  # 单个请求失败绝不能让侧车退出
            _emit({
                "id": req_id, "ok": False,
                "error": f"{type(e).__name__}: {e}",
                "detail": traceback.format_exc()[:2000],
            })
    _emit_log("info", "stdin 关闭，侧车退出")
    return 0


if __name__ == "__main__":
    sys.exit(main())
