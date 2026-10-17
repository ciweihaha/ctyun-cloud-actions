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
