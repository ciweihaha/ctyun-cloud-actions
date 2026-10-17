"""
桌面列表拉取 —— 自动获取 instanceId/machineId，实现全自动保活。

逆向自渲染层 bundle (index-53f3f1a5.js):
  POST /user/getDeviceInfo {accessToken, companyCode:ECloud, allCompany:true, version:1.0.0}
    -> body.machineList[]  每项含 {machineId, instanceId, machineName, originCompanyCode, ...}

  POST /user/getDesktopStatus {accessToken, instanceIdList:[...]}
    -> body.machineStatusList[]  每项含 {machineId, instanceId, resourceStatus, ...}

保活只需 instanceId（desktopUptime 接口），ticket/machineConnect 只在模拟"新连接"时才需要，
纯保活场景无需 ticket。
"""
import logging
from dataclasses import dataclass

import config
from ecloud_client import EcloudHttpUtil, EcloudError

log = logging.getLogger("desktop_list")


# ---------------------------------------------------------------------------
# 运行状态归一化（电源状态判定，唯一真源）
# ---------------------------------------------------------------------------
# 服务端 getDesktopStatus 返回的 resourceStatus 是**字符串枚举**，取值集合来自逆向观察、
# 并未穷尽。因此这里归一到三态，而不是二态：
#   on      —— 明确表示"运行中"
#   off     —— 明确表示"已关机/停止"
#   unknown —— 其余一切（含空串、接口失败、没见过的取值）
#
# ⚠️ 诚实性红线：unknown 绝不能被上层渲染成「已关机」。把"不知道"说成"已关机"
# 会误导用户以为机器掉了（比不显示状态更坏的缺陷）。上层只允许 on→运行中、
# off→已关机、unknown→状态未知。
#
# 注：本函数是**唯一**的判定入口。历史上 select_running_desktop() 内联过一份
# 等价的白名单，那样会出现两处判定、日后改一处漏一处 —— 已统一走这里。
POWER_ON_TOKENS = ("running", "active", "available", "on", "up", "1", "normal")
POWER_OFF_TOKENS = ("shutdown", "shut", "stopped", "stop", "off", "down", "0",
                    "closed", "close", "hibernat", "suspend", "deleted")

# 子串兜底：服务端可能返回 "running(PROD)" / "SHUTDOWN" / "已关机" 之类。
# 刻意**不放**裸的 "on"/"off" —— 那会把 "shutdown" 里的片段当成开机。
# 顺序上**先判 off**：中文里"未开机"也含"开机"二字，先判 on 会把"未开机"误判成开机。
_POWER_OFF_SUBSTR = ("shutdown", "stopped", "stopping", "closed", "hibernat", "suspend",
                     "关机", "未开机", "未运行", "停止")
_POWER_ON_SUBSTR = ("running", "active", "available", "normal", "运行中", "已开机", "开机")


def normalize_power_state(resource_status) -> str:
    """把服务端 resourceStatus 归一到 'on' / 'off' / 'unknown'。

    无法确定时**一律返回 'unknown'**，绝不猜成 'off'。
    """
    s = str(resource_status or "").strip().lower()
    if not s:
        return "unknown"
    if s in POWER_ON_TOKENS:
        return "on"
    if s in POWER_OFF_TOKENS:
        return "off"
    if any(t in s for t in _POWER_OFF_SUBSTR):
        return "off"
    if any(t in s for t in _POWER_ON_SUBSTR):
        return "on"
    return "unknown"


@dataclass
class Desktop:
    """一个云电脑桌面。"""
    instance_id: str          # CCA-xxx，desktopUptime 必需
    machine_id: str           # UUID，machineConnect 用
    machine_name: str = ""
    origin_company_code: str = ""   # CMSSZTE / ZTE / H3C / Inspur
    resource_pool_uid: str = ""
    status: str = ""          # 来自 getDesktopStatus
    # machineList[].customLoginParams (dict|raw) → region CAG
    custom_login_params: dict | str | None = None
    # 【2026-09-28】平台自算的操作能力表（machineOperateMap）：
    #   powerOn.operateEnable 是平台操作层现算的"现在能不能开机"——比 resourceStatus
    #   更贴近真实电源态（状态字段会滞后/撒谎，操作表由操作层实时判定）。
    operate_map: dict | None = None

    def __repr__(self):
        return (f"Desktop(instance={self.instance_id[:20]}..., "
                f"name={self.machine_name}, status={self.status})")


def get_desktop_list(http: EcloudHttpUtil) -> list[Desktop]:
    """
    拉取桌面列表 (复刻 index-53f3f1a5.js 的 St 函数)。
    返回 Desktop 列表。失败抛 EcloudError。
    """
    resp = http.post(config.Endpoint.GET_DEVICE_INFO, {
        "companyCode": config.COMPANY_CODE,
        "allCompany": True,
        "version": "1.0.0",
    })
    # resp 是已解密的 body（dict）
    machine_list = resp.get("machineList", []) if isinstance(resp, dict) else []
    desktops = []
    for m in machine_list:
        if not isinstance(m, dict):
            continue
        clp = m.get("customLoginParams")
        if clp is None:
            clp = m.get("custom_login_params")
        op_map = m.get("machineOperateMap") if isinstance(m.get("machineOperateMap"), dict) else {}
        d = Desktop(
            instance_id=m.get("instanceId", ""),
            machine_id=m.get("machineId", ""),
            machine_name=m.get("machineName", ""),
            origin_company_code=m.get("originCompanyCode", ""),
            resource_pool_uid=m.get("resourcePoolUid", ""),
            custom_login_params=clp if clp not in ("", None) else None,
            operate_map=op_map,
        )
        if d.instance_id or d.machine_id:
            desktops.append(d)
    log.info("拉取到 %d 个桌面", len(desktops))
    return desktops


def get_desktop_status(http: EcloudHttpUtil, desktops: list[Desktop]) -> dict[str, str]:
    """
    查询桌面运行状态 (复刻 getDesktopStatus 调用)。
    返回 {instanceId: resourceStatus} 映射。
    """
    if not desktops:
        return {}
    instance_ids = [d.instance_id for d in desktops if d.instance_id]
    if not instance_ids:
        return {}
    resp = http.post(config.Endpoint.GET_DESKTOP_STATUS, {
        "instanceIdList": instance_ids,
    })
    status_list = resp.get("machineStatusList", []) if isinstance(resp, dict) else []
    result = {}
    for s in status_list:
        if isinstance(s, dict):
            iid = s.get("instanceId", "")
            result[iid] = s.get("resourceStatus", "")
    log.info("桌面状态: %s", result)
    return result


def operate_desktop(http: EcloudHttpUtil, machine_id: str, machine_name: str,
                    operate: str, resource_pool_uid: str = "") -> dict:
    """
    桌面操作：开机/关机/重启/重装/迁移。
    :param operate: "available"(开机) | "shutdown" | "restart" | "reload" | "transfer"
    注意：后端未知 "startup"/"powerOn"；asar 客户端用 operate=available 表示开机。
    复刻 asar Ts→ri→POST /resource/operate。
    """
    import platform
    # os.uname() is POSIX-only and raises AttributeError on Windows (a supported
    # client platform). platform.system() is cross-platform.
    sdk_type = 5 if platform.system() == "Darwin" else 4
    return http.post(config.Endpoint.RESOURCE_OPERATE, {
        "machineId": machine_id,
        "machineName": machine_name,
        "operate": operate,
        "deviceUid": http.common_params.get("deviceUid", ""),
        "resourcePoolUid": resource_pool_uid,
        "sdkType": sdk_type,
    })


def select_running_desktop(http: EcloudHttpUtil) -> Desktop | None:
    """
    自动选一个正在运行的桌面用于保活。
    优先选 resourceStatus 表示"运行中"的桌面。
    """
    desktops = get_desktop_list(http)
    if not desktops:
        log.warning("没有可用桌面")
        return None

    # 查状态选运行中的。即使只有一个桌面，也不能把 shutdown 当作可保活目标。
    try:
        statuses = get_desktop_status(http, desktops)
        for d in desktops:
            st = statuses.get(d.instance_id, "")
            d.status = st
            # 判定统一走 normalize_power_state —— 与侧车下发给界面的口径**完全同源**，
            # 杜绝"界面说运行中、这里却认为关机"这类两处判定不一致。
            # 注意：只有明确 'on' 才是可保活目标；'unknown' 不能当成"在运行"，
            # 否则会朝一台可能已关机的机器发 desktopUptime。
            if normalize_power_state(st) == "on":
                log.info("选中运行中的桌面: %s (status=%s)", d, st)
                return d
        if statuses:
            log.warning("没有正在运行的桌面: %s", statuses)
            return None
    except EcloudError as e:
        log.warning("查询桌面状态失败（忽略）: %s", e)

    # 状态接口不可用时保持兼容：返回第一个。
    log.info("无法确定运行状态，默认选第一个: %s", desktops[0])
    return desktops[0]
