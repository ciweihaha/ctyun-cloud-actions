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

仪表盘服务（server.js）关键环境变量：

| 名称 | 默认 | 说明 |
| --- | --- | --- |
| `PORT` / `HOST` | `8571` / `127.0.0.1` | 监听地址；Docker 部署才设 `HOST=0.0.0.0` |
| `CTYUN_DATA_DIR` | `./data` | 配置、主密钥、会话与日志目录 |
| `CTYUN_DASHBOARD_ADMIN_PASSWORD` | （随机生成） | 初始管理员口令；未设时随机生成并写入 `data/.admin-init-password.log`（0600） |
| `CTYUN_CORS_ORIGINS` | （空） | 额外允许的跨域来源，逗号分隔；同源请求恒放行 |
| `CTYUN_FATAL_EXCEPTION_THRESHOLD` | `5` | 10 分钟窗口内未捕获异常达到该次数后进程主动退出，交守护重启 |

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
