# 天翼云电脑 GitHub Actions 版

每天定时：签到、AI问答、1小时挂机。

## 设置

1. 本仓库已是 Public（无限 Actions 分钟）
2. Settings → Secrets and variables → Actions → New repository secret：
   - `CTYUN_USER`：天翼云账号（手机号）
   - `CTYUN_PASS`：天翼云密码
3. Actions 页面可手动触发验证

## 定时

- 北京时间 8:00 和 20:00 自动跑
- 1小时挂机断线自动重连，服务端累计计时不丢

## Secrets 与环境变量

GitHub Actions（daily.yml）所需 Secrets：

| 名称 | 用途 |
| --- | --- |
| `CTYUN_USER` | 天翼云账号（手机号），仅注入 `node cli.js` 步骤 |
| `CTYUN_PASS` | 天翼云账号密码，同上 |
| `CTYUN_SESSION` | 可选：导出的 savedLoginInfo JSON，会话优先登录（无头免验证码）；结构非法时自动回落账号密码直登 |
| `CTYUN_DEVICE_CODE` | 可选：固定设备码；未设时每次运行生成临时设备码，以"新设备"登录可能触发设备绑定/短信验证 |

仪表盘服务（server.js）关键环境变量：

| 名称 | 默认 | 说明 |
| --- | --- | --- |
| `PORT` / `HOST` | `8571` / `127.0.0.1` | 监听地址；Docker 部署才设 `HOST=0.0.0.0` |
| `CTYUN_DATA_DIR` | `./data` | 配置、主密钥、会话与日志目录 |
| `CTYUN_DASHBOARD_ADMIN_PASSWORD` | （随机生成） | 初始管理员口令；未设时随机生成并写入 `data/.admin-init-password.log`（0600） |
| `CTYUN_CORS_ORIGINS` | （空） | 额外允许的跨域来源，逗号分隔；同源请求恒放行 |
| `CTYUN_FATAL_EXCEPTION_THRESHOLD` | `5` | 10 分钟窗口内未捕获异常达到该次数后进程主动退出，交守护重启 |
| `CTYUN_ZTE_UAS_KEY` / `CTYUN_ZTE_UAS_IV` / `CTYUN_ZTE_CSAP_ID` | （内置默认值） | 中兴 CAG 对称密钥覆盖；厂商轮换密钥时用此更新，无需改代码（见下「中兴 CAG 对称密钥声明」） |

## 仪表盘前端说明

仪表盘前端文件（`app/static/`，即 `GET /` 返回的控制台页面）**不在本仓库中**：按当前仓库检出部署，`GET /` 会返回 404，只有 API 与 `/desktop-view`（桌面视图）可用。如你持有前端文件，将其放入 `app/static/`（`index.html` 为入口）后重启服务即可恢复控制台 UI；本仓库不虚构前端来源，如需确认前端仓库请联系仓库维护者。

## 中兴 CAG 对称密钥声明

`app/ydpc/cag_boot.js` 中的 `ZTE_UAS_KEY` / `ZTE_UAS_IV` / `ZTE_CSAP_ID` 是中兴 CAG 网关与官方客户端之间的**固定对称密钥**，来自官方客户端安装包自带的 `installinfo.ini`（公开分发材料），**不是按用户签发的凭据**，也不含任何账号信息。风险口径：

- 该密钥可被任意人用于构造仿冒客户端或解密网关流量；不要把它当作"秘密"依赖。
- 厂商轮换该密钥时，所有未更新的部署会同时失效；届时用上表环境变量注入新值即可恢复，无需改代码。
- 默认值保留在代码中是为了保证现有部署开箱即用；删除默认值会导致所有现有部署立即失效。

## TLS 与部署安全

仪表盘服务本身仅提供 HTTP（无内置 HTTPS 监听）：

- 默认监听 `127.0.0.1`，仅本机可访问，风险有限。
- Docker 或局域网部署（`HOST=0.0.0.0`）时，**必须**在前面加反向代理（Nginx/Caddy 等）提供 TLS：会话 token 与配置导出中的明文密码会在局域网明文传输，不要把 HTTP 端口直接暴露到不可信网络。

## 测试

```bash
npm ci --omit=dev
npm test   # node --test，全部为 mock/本地模拟，无真实账号动作
```

daily.yml 在执行真实任务前先跑同一套测试作为门禁；另有 ci.yml 在 push/PR 时运行。

## 排障

- **登录被限速（429）**：同一 IP+用户名 10 分钟内失败 10 次会拦截，等待窗口过期或用正确密码成功登录清零。
- **改密后其他设备掉线**：预期行为——改密/管理员重置会吊销该用户全部旧会话（自助改密保留当前会话）。
- **账号密码突然不可用且日志出现「密码解密失败」**：多为主密钥丢失/不匹配，见「备份与回滚」恢复 `.master.key`；无法恢复时需重新录入账号密码。
- **代理 401/403**：`/api/ctyun-proxy` 现要求仪表盘登录会话，且目标仅限 `https://*.ctyun.cn` 的 443/8810/8816 端口；桌面页会自动附带会话 token。
- **Webhook 被拦截**：目标会做 DNS 解析逐地址校验与重定向逐跳复检，解析到内网/保留地址（含重定向跳转）一律拒绝，属预期安全行为。
- **进程反复退出**：未捕获异常熔断触发（阈值见上表），先查日志中首个异常堆栈定位根因，不要只调大阈值掩盖问题。

## 备份与回滚

必须备份（位于 `CTYUN_DATA_DIR`，均为 0600）：

- `app_config.json` 与 `app_config.json.bak`：主配置（密码为 AES-256-GCM 密文落盘）。
- `.master.key` 与 `.master.key.bak`：解密主密钥。**密钥与配置必须成对备份**；只有配置没有密钥，账号密码将永久不可解。
- `auth_sessions.json`：免登录会话（可选备份，丢失仅需重新登录）。

回滚代码：所有修复都在常规 git 历史中，按提交粒度 `git revert`；数据库/配置格式本轮未变更，旧版本可直接读新版本落盘的配置（密码策略只约束新设密码，存量登录不受影响）。

恢复步骤：停服 → 放回成对的 `app_config.json` 与 `.master.key` → 启服 → 登录后逐账号验证可用性。
