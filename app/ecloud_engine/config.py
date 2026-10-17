"""
移动公众云电脑 协议常量与端点表（侧车内）。

📌 签名常量：内置公开值 + 可覆盖（2026-09-28 用户拍板，取代原「方案 B 全外置」）
--------------------------------------------------------------------------
本文件**本身不含任何签名凭据字面值**；四个值 `ACCESS_KEY` / `SECRET_KEY` /
`PUBLIC_KEY_PEM` / `PRIVATE_KEY_PEM` 在导入时按下面的优先级解析：

  1) 环境变量（最高优先）
       ECLOUD_ACCESS_KEY        AccessKey 字符串
       ECLOUD_SECRET_KEY        SecretKey 字符串
       ECLOUD_RSA_PUBLIC_PEM    客户端公钥 PEM 内容（或指向它的 *_FILE）
       ECLOUD_RSA_PRIVATE_PEM   客户端私钥 PEM 内容（或指向它的 *_FILE）
  2) 覆盖文件
       ECLOUD_CRED_FILE 指向的 JSON；未设置时默认 <本目录>/credentials.json
       {
         "accessKey": "...",
         "secretKey": "...",
         "rsaPublicPem":  "-----BEGIN PUBLIC KEY-----\\n...",
         "rsaPrivatePem": "-----BEGIN PRIVATE KEY-----\\n..."
       }
       部署对照：Docker 镜像内 ECLOUD_CRED_FILE=/app/data/ecloud_credentials.json
       （即宿主机 compose 目录下的 data/ecloud_credentials.json）。
  3) 内置公开常量（兜底，保证开箱即用）
       <本目录>/public_credentials.json —— 官方公众线客户端内置的固定材料，
       属公开信息，随仓库与镜像分发。平台轮换该套 Key 时替换此文件即可。

这四个值是"官方公众线客户端"的固定签名材料（HmacSHA1 签名 + 整体 RSA-1024 的
组成部分，技术上无法像 token 那样动态获取），**不含任何账号信息**；账号凭据
（手机号 / 密码 / 会话 token）只存在本地 data/ 目录，从不随仓库或镜像分发。

优先级之外的兜底行为：三者都取不到时**必须报错**（`CredentialMissing`），
绝不静默降级 —— 静默降级会让整条保活链在"看似正常"的状态下失败。

其余常量（地址、端点、签名方式、超时、错误码）均为协议公开信息，随源码入库。
"""

from __future__ import annotations

import json
import os
from pathlib import Path

__all__ = [
    "BASE_URL", "API_PATH", "BACKUP_DOMAINS", "ACCESS_KEY", "SECRET_KEY",
    "PUBLIC_KEY_PEM", "PRIVATE_KEY_PEM", "RSA_ENCRYPT_CHUNK", "RSA_DECRYPT_CHUNK",
    "SIGN_METHOD", "SIGN_VERSION", "HMAC_KEY_PREFIX", "API_TIMEOUT", "LOGIN_TIMEOUT",
    "USER_AGENT", "Endpoint", "LOGIN_PATHS", "COMPANY_CODE", "CLIENT_VERSION",
    "CHANNEL_VERSION", "LoginError", "LoginType", "CredentialMissing",
]


class CredentialMissing(RuntimeError):
    """凭据缺失：不静默降级，直接让侧车启动失败。"""


def _read_pem(env_content: str, env_file: str, label: str) -> str | None:
    """按 内容 → 文件 的顺序取 PEM。"""
    content = os.environ.get(env_content)
    if content and content.strip():
        return content
    path = os.environ.get(env_file)
    if path and Path(path).is_file():
        return Path(path).read_text("utf-8")
    return None


def _load_credentials() -> tuple[str, str, str, str]:
    """返回 (access_key, secret_key, public_pem, private_pem)；缺失即 CredentialMissing。"""
    ak = os.environ.get("ECLOUD_ACCESS_KEY")
    sk = os.environ.get("ECLOUD_SECRET_KEY")
    pub = _read_pem("ECLOUD_RSA_PUBLIC_PEM", "ECLOUD_RSA_PUBLIC_PEM_FILE", "公钥")
    priv = _read_pem("ECLOUD_RSA_PRIVATE_PEM", "ECLOUD_RSA_PRIVATE_PEM_FILE", "私钥")

    # 环境变量未给全 → 依次回落到「覆盖文件」与「内置公开常量」
    #   · 覆盖文件：ECLOUD_CRED_FILE 指定，或默认 <本目录>/credentials.json（可不存在）
    #   · 内置文件：<本目录>/public_credentials.json（随仓库与镜像分发，保证开箱即用）
    cred_file = os.environ.get("ECLOUD_CRED_FILE") or str(
        Path(__file__).resolve().with_name("credentials.json")
    )
    bundled_file = str(Path(__file__).resolve().with_name("public_credentials.json"))
    for label, path in (("覆盖文件", cred_file), ("内置公开常量", bundled_file)):
        if ak and sk and pub and priv:
            break
        p = Path(path)
        if not p.is_file():
            # 覆盖文件不存在是常态（首次部署 / 未自定义），交给下一级兜底，不算错误
            continue
        try:
            d = json.loads(p.read_text("utf-8"))
        except Exception as e:  # 显式展开，不吞错
            raise CredentialMissing(
                f"凭据文件解析失败（{label}）: {path} ({type(e).__name__}: {e})"
            ) from e
        ak = ak or d.get("accessKey")
        sk = sk or d.get("secretKey")
        pub = pub or d.get("rsaPublicPem")
        priv = priv or d.get("rsaPrivatePem")

    missing = [
        name for name, val in (
            ("AccessKey", ak), ("SecretKey", sk),
            ("RSA 公钥", pub), ("RSA 私钥", priv),
        ) if not val
    ]
    if missing:
        raise CredentialMissing(
            "移动公众协议凭据缺失: " + " / ".join(missing) +
            " —— 请通过环境变量提供，或检查覆盖文件与内置常量文件是否完整"
            f"（覆盖: {cred_file}；内置: {bundled_file}）。"
        )
    return ak, sk, pub, priv


_ACCESS_KEY, _SECRET_KEY, _PUBLIC_KEY_PEM, _PRIVATE_KEY_PEM = _load_credentials()

# ---------------------------------------------------------------------------
# 服务端地址
# ---------------------------------------------------------------------------
BASE_URL = "https://cloudpc.ecloud.10086.cn"
API_PATH = "/api/cem/gateway/outer/cem-webapi"
BACKUP_DOMAINS = [
    "https://cloudpc1.ecloud.10086.cn",
    "https://cloudpc2.ecloud.10086.cn",
]

# ↑ 由 _load_credentials() 在导入时填充（外置，不入库）
ACCESS_KEY = _ACCESS_KEY
SECRET_KEY = _SECRET_KEY

# ---------------------------------------------------------------------------
# RSA 密钥（1024-bit, PKCS1 padding）
#   - 公钥: 加密每个请求的 JSON body -> {"params": base64}
#   - 私钥: 解密响应 body 的 RSA 密文
# ---------------------------------------------------------------------------
PUBLIC_KEY_PEM = _PUBLIC_KEY_PEM
PRIVATE_KEY_PEM = _PRIVATE_KEY_PEM

# RSA 分块大小 (RSA-1024: 加密块 117 字节，解密块 128 字节)
RSA_ENCRYPT_CHUNK = 117   # modulusLength/8 - 11
RSA_DECRYPT_CHUNK = 128   # modulusLength/8

# ---------------------------------------------------------------------------
# 签名常量
# ---------------------------------------------------------------------------
SIGN_METHOD = "HmacSHA1"
SIGN_VERSION = "V2.0"
HMAC_KEY_PREFIX = "BC_SIGNATURE&"   # 拼在 secretKey 前作为 HMAC key

# ---------------------------------------------------------------------------
# HTTP 客户端常量
# ---------------------------------------------------------------------------
API_TIMEOUT = 30
LOGIN_TIMEOUT = 10
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "EcloudCloudComputer/3.8.2"
)

# ---------------------------------------------------------------------------
# API 端点
# ---------------------------------------------------------------------------
class Endpoint:
    # 登录
    LOGIN_CHECK_USER_PASSWORD = "/login/verify"
    LOGIN_GET_TOKEN           = "/login/verifyAccessTicket"
    LOGIN_CHECK_MOBILE        = "/login/checkMobile"
    LOGIN_SEND_SMS            = "/login/sendVerifySms"
    LOGIN_VERIFY_SMS          = "/login/verifySms"
    LOGIN_QR_CODE             = "/login/getQRCode"
    LOGIN_QR_LOGIN_RESULT     = "/login/getQRLoginResult"
    LOGIN_TRUST_DEVICE        = "/login/trustDevice"
    LOGIN_TEMPORARY_DEVICE    = "/login/trustOrTemporaryDevice"
    LOGIN_AUTH_TWOFACTOR_GET  = "/login/special/getSecondauthSms"
    LOGIN_AUTH_TWOFACTOR      = "/login/verifyTwoFactorAuthSms"
    LOGIN_AUTH_4A_SMS         = "/user/getUserNameBySmsAuth"
    LOGIN_AUTH_4A             = "/login/special/secondauthBy4a"
    LOGIN_ENHANCE_SMS         = "/login/verifyLoginEnhanceSms"
    LOGIN_AD_LOGIN            = "/login/adUserLogin"
    LOGIN_AD_RESULT           = "/login/getAdLoginResult"
    LOGIN_SIM_CODE            = "/login/simVerify"
    LOGIN_SIM_LOGIN_RESULT    = "/login/getSimLoginResult"
    LOGIN_NEW_BY_CODE         = "/login/loginByCode"
    LOGOUT                    = "/login/logout"

    # 用户/设备
    USER_GET_INFO             = "/user/getLoginUserInfo"
    GET_SYS_CONFIG            = "/client/getSysConfig"
    USER_GET_DEVICE_INFO      = "/user/getDeviceInfo"
    GET_SYS_TIME              = "/user/getSysTime"
    SET_NEW_PWD               = "/user/setNewPwd"

    # 探针上报 (登录态保活)
    PROBE_QKK_BATCHPUSH       = "/login/batchPushLoginQkk"

    # 桌面会话保活（抓包逆向，见 desktop_session.py）
    DESKTOP_UPTIME            = "/resource/desktopUptime"
    SESSION_MACHINE_CONNECT   = "/session/machineConnect"
    PUSH_CONNECT_EVENT        = "/machine/pushConnectEventData"
    GET_DESKTOP_LIST          = "/resource/getDesktopList"

    # 桌面列表与操作
    GET_DEVICE_INFO           = "/user/getDeviceInfo"
    GET_DESKTOP_STATUS        = "/user/getDesktopStatus"
    RESOURCE_OPERATE          = "/resource/operate"
    UPDATE_SESSION_STATUS     = "/session/updateSessionStatus"

# 登录类端点 (10s 超时 + 备用域名重试)
LOGIN_PATHS = {
    Endpoint.LOGIN_CHECK_USER_PASSWORD,
    Endpoint.LOGIN_QR_CODE,
    Endpoint.LOGIN_CHECK_MOBILE,
    Endpoint.LOGIN_AD_LOGIN,
}

# ---------------------------------------------------------------------------
# 业务常量
# ---------------------------------------------------------------------------
COMPANY_CODE   = "ECloud"
CLIENT_VERSION = "3.8.2"
CHANNEL_VERSION = "23"

# 登录错误码
class LoginError:
    UNTRUSTED_DEVICE   = "30002009"   # 未授信设备 -> 需短信信任
    TWO_FACTOR_AUTH    = "30002060"   # 二次验证
    ENHANCED_STRATEGY  = "30002063"   # 增强策略短信
    FEISHU_BIND        = "10002039"
    REFRESH_FS_QRCODE  = "30002026"

# 登录方式
class LoginType:
    PASSWORD     = 0
    SMS          = 1
    QRCODE       = 2
    SIM          = 3
    FORGET_PWD   = 4
    AD_CONNECTOR = 5
    FEISHU_QR    = 6
    MULTI_ACCT   = 7
