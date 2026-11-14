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
| `CTYUN_REDEEM` | 自动兑换配置（redeemConfig JSON，见下节）；不配时兑换跳过，其他任务不受影响 |

## 自动兑换配置（CTYUN_REDEEM）

`CTYUN_REDEEM` 是 redeemConfig 的 JSON 字符串，与 dashboard 里账号的 `redeemConfig` 同格式。配好后，每天早班（08:00 CST）跑到兑换日就会真实下单；晚班（20:00）不执行兑换，防同一天重复下单。兑换日期由仓库根目录的 `redeem-state.json` 自动维护：兑完成功后 workflow 会把当天日期写回该文件并推回 main 分支，下次跑就能读到最新日期，不用再手动填。

示例（每月最后一天兑 1G数据盘永久扩容，1200 积分）：

```json
{"enabled":true,"targetType":"redeem","desktopId":"","desktopName":"","prodId":17024101,"prodName":"1G数据盘永久扩容 (1200积分)","prodType":"pointsdiskupgrade","costPoints":1200,"maxRedeemTimes":1,"scheduleType":"monthly_days","monthlyDays":[-1],"intervalDays":1,"pointType":1,"lastRedeemDate":""}
```

关键字段：

| 字段 | 说明 |
| --- | --- |
| `prodId` / `prodName` / `prodType` / `costPoints` | 商品 ID / 名称 / 类型 / 单价积分。常用：17023101 是 8C16G升配包1天（500 积分），17023111 是 16C32G升配包1天（1000 积分），17024101 是 1G数据盘永久扩容（1200 积分）；`prodType` 对应 `pointstplupgrade` / `pointsdiskupgrade` |
| `desktopId` / `desktopName` | 升配/扩容类商品必须绑定的目标云电脑。`desktopId` 从 dashboard 账号页绑定的云电脑取（账号详情里显示的云电脑 ID）；填了才会下单，找不到有效设备时本次跳过，不会误兑 |
| `scheduleType` / `monthlyDays` / `intervalDays` | 兑换周期：`monthly_days`（默认，按 `monthlyDays` 里的日期兑，`-1` 代表月末最后一天）/ `daily`（每天）/ `interval_days`（按 `intervalDays` 间隔天数兑） |
| `maxRedeemTimes` | 单次兑换份数（总价 = `costPoints × maxRedeemTimes`，单笔下单一次扣完） |
| `lastRedeemDate` | 上次兑换日期（`YYYY-MM-DD`），当天已兑过会跳过；留空表示从未兑过。现在由 `redeem-state.json` 自动维护（文件里的日期优先于 Secret 里的同字段），Secret 里的值只作为初始值/后备，一般不用再手动改 |
| `enabled` | `false` 时不兑换；不填视为启用（建了这个 Secret 即表示要开兑换） |

行为说明：

- 没配 `CTYUN_REDEEM`、JSON 非法、未到兑换日、积分不足、需绑定云电脑但无有效 `desktopId` 时，本次兑换跳过并写明原因，签到/AI/挂机照常跑，workflow 不会因此失败。
- 下单用与 dashboard 相同的 S11 安全重试口径：明确业务错误才有限重试；网络异常等结果不明确时绝不重试，汇总里会标“结果不明确，请人工核对订单与积分变动”。
- 兑换成功后，当天北京时间日期会自动写进 `redeem-state.json` 并由 workflow 推回 main 分支，不用再手动填 Secret；月末策略下月仍会正常触发，符合预期。
- `redeem-state.json` 是 `lastRedeemDate` 的唯一事实来源：每次跑先读它覆盖 Secret 里的同字段；文件不存在/不合法、或文件里没记日期时沿用 Secret 的值。回写步骤只在文件有变化时提交，没变化时不提交、不报错。

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
