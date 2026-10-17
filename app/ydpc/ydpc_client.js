const { SohoClient } = require('./soho_client');
const { performCagAuthHold } = require('./cag_client');
const { MqttKeepAliveClient } = require('./mqtt_client');
// 【2026-09-23 G1/G2】底座路由判定与失败分级的纯函数层（零网络、零凭据）。
// 判定与分级全部为纯函数：输入官方字段、输出三分类结论，零网络、零凭据、零副作用。
const {
  resolveVmRoute,
  routeFromPersistedVendor,
  routeVendorLabel,
  routeGate,
  classifyZteError,
  resolveInnerRoute
} = require('./product_route');
// 【2026-09-23 G5】IPv4 内层主机的数据面通道（TLS + CAGMux + raw SPICE）。
// 仅此一处 require：地址族分流在 startDataPlaneTask 内按 resolveInnerRoute 的结果决定。
const { runTlsSpiceSession } = require('./zte_cag_tls');
// 【2026-09-26】SCG（深信服）数据面 —— 与 ZTE **完全不同的第二套通道**。
// 数据面与开机共用 CEM 控制面（cemBootVm：OAuth → getConnectInfo 触发开机 → ready 轮询）。
const { runScgSession, describeScgMaterialPresence, cemBootVm } = require('./scg_keepalive');

// ============================================================================
// 数据面"假活跃"防线：连续失败多少次后判定**隧道并不存在**
//
// 【2026-09-26 现场事故，用户原话："我一台已经开机了，为什么无法保活？一直自动关机"】
// 数据面保活在场时会**抑制**控制面（SOHO 心跳 + CAG 握手），理由是"HTTP 心跳不能真保活、
// 数据面在场时它只是冗余流量"。但抑制的判据曾是 `task.running` —— 而一个**每轮都抛错、
// 从没建立过隧道**的重试循环同样是 running。于是形成最坏组合：
//     数据面（做不成事）在跑 ⇒ 控制面被压住 ⇒ 这台机器**一条保活动作都没有**
//   ⇒ 平台按"无活动"把它关机 ⇒ 而告警里还写着"数据面保活=活跃"（假活跃，与"假成功"同源）。
// ⇒ 判据改为"**连续失败次数**"：连续 DATA_PLANE_FAIL_LIMIT 次没建立起隧道，就当它不在场，
//    立刻把控制面交还回来（宁可多一条冗余心跳，也不能一条都没有）。
const DATA_PLANE_FAIL_LIMIT = 2;

// ============================================================================
// 保活"有效性"独立核验看门狗的默认节拍
//
// 【2026-09-23 事故修复】这三个常量此前**只被引用、从未被定义**（全仓 0 处赋值），
// 而它们被用作 `startEffectWatchdog()` 的默认参数值 → 无参调用时默认参数求值即抛
// `ReferenceError: EFFECT_VERIFY_INTERVAL_MS is not defined`。
//
// 致命之处在于调用位置：`startKeepAliveWorker()` 先打了"看门狗已启动"日志、并把
// `workerRunning` 置为 true，然后才调 `startEffectWatchdog()` 抛错 → 后面的
// `setTimeout(runCycle, 2000)` 永远执行不到 → **保活循环从未被排程**；而
// `if (this.workerRunning) return;` 守卫又让后续每次重试都直接 return →
// **该账号的移动云保活永久静默停摆**（无错误日志、无心跳、lastKeepAliveAt 冻结）。
// 实测日志正是：一条"看门狗已启动"，然后彻底安静。
//
// 教训已固化为两条约束（见 tests/regression.test.js 组 13）：
//   ① 启动流程必须能被行为测试真实执行一次（实例化 + 调用），仅靠"符号存在"的静态断言抓不到运行期 ReferenceError；
//   ② 附加能力（核验看门狗）失败**绝不允许**拖垮主保活循环。
// ============================================================================
const EFFECT_VERIFY_INTERVAL_MS = Math.max(
  60 * 1000,
  (parseInt(process.env.CTYUN_EFFECT_VERIFY_MINUTES, 10) || 30) * 60 * 1000
);
const EFFECT_VERIFY_FIRST_DELAY_MS = Math.max(
  1000,
  (parseInt(process.env.CTYUN_EFFECT_VERIFY_FIRST_MINUTES, 10) || 5) * 60 * 1000
);
const EFFECT_VERIFY_SAMPLE_SEC = Math.max(
  10,
  parseInt(process.env.CTYUN_EFFECT_VERIFY_SAMPLE_SEC, 10) || 60
);

// 【2026-09-22】移动云侧的开机能力曾按用户要求下线；2026-09-28 起改走官方通道恢复
// （ZTE：app/ydpc/cag_boot.js 的 CAG HTTPS；SCG：app/ydpc/scg_keepalive.js 的 CEM 接口）。
// 账号登录、SOHO 心跳、ZTEC CAG 握手、官方 MQTT 长连接、状态监控与官方【关机 / 重启】不变。

function getBeijingTimeString() {
  const d = new Date();
  return d.toLocaleString('sv-SE', { timeZone: 'Asia/Shanghai' });
}

function getBeijingTimeOnly() {
  const d = new Date();
  return d.toLocaleTimeString('sv-SE', { timeZone: 'Asia/Shanghai' });
}

function isYdpcVmOff(vm) {
  if (!vm) return false;
  const st = String(vm.vmStatus || vm.vmStatusShow || '').trim();
  if (st.includes('关机') || st.includes('停止') || st.includes('未开机') || st.includes('到期') || st.includes('未知')) return true;
  if (st === '23' || st === '16' || st === '0') return true;
  if (vm.vmStatus === 23 || vm.vmStatus === 16 || vm.vmStatus === 0 || vm.vmStatusCode === 23 || vm.vmStatusCode === 16 || vm.vmStatusCode === 0) return true;
  return false;
}

class YdpcClient {
  constructor(account, { appendLog, sendNotification, saveConfig }) {
    this.account = account;
    this.appendLog = appendLog || (() => {});
    this.sendNotification = sendNotification || (() => {});
    this.saveConfig = saveConfig || (() => {});

    this.sohoClient = new SohoClient({
      deviceId: account.deviceCode,
      accountType: account.accountType || 'main'
    });

    this.metrics = {
      status: 'offline', // 'online' | 'offline'
      vmStatus: account.stats?.vmStatus || '未知',
      durationMode: account.stats?.durationMode || 'permanent',
      remainHours: account.stats?.remainHours || 0,
      remainText: account.stats?.remainText || '♾️ 永久使用',
      lastHeartbeatTime: account.stats?.lastKeepAliveTime || '',
      lastHeartbeatResult: '保活巡检待命中',
      successCount: 0,
      errorCount: 0,
      vms: account.vms || [],
      // 【2026-09-23 按主机维度】userServiceId → { text, level, at }
      // 账号级 lastHeartbeatResult 无法区分"多台主机各自在做什么"；多机独立周期下
      // 它还会长期停留在初始文案（"保活巡检待命中"）——这就是界面上"当前动作一直待命"的根因。
      // 本表只存在于内存，随 metrics 一起下发给前端，不落盘。
      vmActions: {}
    };

    this.workerRunning = false;
    this.loopTimer = null;
    this.mqttClient = null;
    // 数据面保活任务表：userServiceId → { running, stopFlag, socket }
    this.dataPlaneTasks = new Map();
    // 上一次独立观测到的"是否关机"（userServiceId → boolean），用于检测 运行中→已关机 转移
    this._vmPrevOffState = new Map();
  }

  async login() {
    const accName = this.account.name || this.account.user;
    try {
      this.appendLog('SOHO', `[${accName}] 正在向中国移动 SOHO 认证中心登录 (类型: ${this.account.accountType === 'sub' ? '独立子账号' : '和家亲主账号'})...`, 'info', accName, 'ydpc');
      const res = await this.sohoClient.login(this.account.user, this.account.password, this.account.accountType || 'main');
      this.appendLog('SOHO', `[${accName}] ✅ SOHO 鉴权登录成功 (UserId: ${res.userId})`, 'success', accName, 'ydpc');
      return { success: true, data: res };
    } catch (err) {
      this.appendLog('SOHO', `[${accName}] ❌ SOHO 登录失败: ${err.message}`, 'error', accName, 'ydpc');
      return { success: false, error: err.message };
    }
  }

  async refreshVms() {
    const accName = this.account.name || this.account.user;
    try {
      if (!this.sohoClient.sohoToken) {
        await this.login();
      }
      const vms = await this.sohoClient.listCloudPcs();

      // 自动嗅探识别每台主机的底层架构底座 (深信服 SCG vs 中兴 ZTE)
      //
      // 【2026-09-23 边沿粘性】底座类型只在探测成功时缓存，避免逐轮漂移与反复失败
      // 底座判定结果一旦确定就写入 vm.vendor 并持久化，后续默认跳过 HTTP 探测，
      // 减少 CAG2↔IAG 一类底座抖动导致的反复重探。
      // 强制重探：把 vm.vendorProbeStale 置为 true（或删除 vm.vendor）即可。
      //
      // ⚠️ 本轮**真正探测过**的机器要单独记账：下面的差量合并会按 `_` 前缀把旧对象的
      // 状态整体搬回来（其中就包含旧的 `_route` / `vendor`），若不重新写一遍，
      // 「强制重探」得到的新结论会被旧结论原地覆盖 —— 探了等于没探。
      const freshProbe = new Map();
      for (const vm of vms) {
        const needProbe = !vm.vendor || vm.vendorProbeStale === true;
        if (needProbe) {
          let auth = null;
          let probeErr = '';
          try {
            auth = await this.sohoClient.getFirmAuth(vm.userServiceId);
          } catch (e) {
            probeErr = e.message || String(e);
          }
          const probeFailed = !auth;

          // 【2026-09-23 G1 底座闸门】按官方字段做一次互斥判定，判不明即拒绝执行
          // 判定收敛到纯函数 resolveVmRoute（app/ydpc/product_route.js）：
          //   ① `spuCode` 前缀（官方口径，不随开关机漂移）优先；
          //   ② 缺 `spuCode` 或未登记时回退既有 firm-auth 规则（行为等价）；
          //   ③ 两级都判不出 → UNKNOWN，**拒绝猜测**（不再"默认当 ZTE"）。
          //
          // 与旧实现的关键差别：旧代码在 getFirmAuth 抛错时用 `vmName/skuName` 正则兜底，
          // 名称里出现"家庭"就判 SCG、否则一律判 ZTE —— 那是猜。猜测的代价是：一台真 SCG
          // 机器会被硬判成 ZTE 并每轮盲拨 ZTE 握手（`vm.vendor` 此前只用于界面展示，
          // **从未被任何执行路径当过闸门**）。G1 把判定变成可执行的闸门，见 runCycle / bootVmViaCag。
          const route = resolveVmRoute(vm, auth);

          if (probeFailed && route.kind === 'UNKNOWN') {
            // 探测通道本身失败 + 没有任何可用信号：**不写入判定**，标记下轮重探。
            // 否则一次瞬时网络故障会把"底座未知"固化进 vendor（vendor 一旦有值就不再重探），
            // 继而被动闸门永久拒绝保活 —— 必须避免这种自我封锁。
            vm.vendorProbeStale = true;
            continue;
          }

          const label = routeVendorLabel(route);
          vm._route = route;
          vm._routeAt = Date.now();
          vm.vendor = label.vendor;
          vm.vendorName = label.vendorName;
          vm._firmAuthError = probeErr;
          vm.vendorProbedAt = Date.now();
          vm.vendorProbeStale = false;
          freshProbe.set(String(vm.userServiceId), {
            route,
            vendor: vm.vendor,
            vendorName: vm.vendorName,
            vendorProbedAt: vm.vendorProbedAt
          });

          // 【可观测性 · presence-only】SCG 通道完全依赖"官方是否真下发 scgIp/scAuthCode"，
          // 而这在离线无法验证 ⇒ 每次探测到 SCG 就把 presence 落进日志（**只落布尔，不落值**）。
          // 这样"材料到底有没有下发"从此可自证，不必再靠猜。
          if (route.kind === 'SCG') {
            const pr = describeScgMaterialPresence(auth);
            const note = `SCG 材料探测：scgIp=${pr.scgIp} scgTcpPort=${pr.scgTcpPort} ` +
              `scAuthCode=${pr.scAuthCode} vmId=${pr.vmId}（cagIp=${pr.cagIp}）`;
            // 【2026-09-26】去重状态必须挂在 client 上（跨刷新持久）—— 之前挂在 vm 对象上，
            // 而 vm 每次刷新都是新对象 ⇒ 每轮 refreshVms 都重打一遍（一分钟两条 × 每台机器）。
            // 现在只在材料状态真正变化（如开机后 scAuthCode 出现/消失）时才落一条。
            this._scgPresenceNotes = this._scgPresenceNotes || new Map();
            if (this._scgPresenceNotes.get(String(vm.userServiceId)) !== note) {
              this._scgPresenceNotes.set(String(vm.userServiceId), note);
              this.appendLog('SCG', `[${accName}][${vm.vmName}] ${note}`, 'info', accName, 'ydpc');
            }
          }
        }
      }

      // 差量合并引擎 (Diff-Merge)：严格保留本地已有的单机独立保活与独立周期设置
      const oldVmsMap = new Map((this.account.vms || []).map(v => [String(v.userServiceId), v]));
      for (const vm of vms) {
        const old = oldVmsMap.get(String(vm.userServiceId));
        if (old) {
          // 【2026-09-24】泛化保留**所有**本机运行时状态。
          // 约定：`_` 前缀 = 本系统自用状态，不来自接口响应。
          // 此前是逐字段列举，漏掉了 _hasNotifiedOff / _hasNotifiedBooting / _hasWarnedExhausted
          // → 每次 refreshVms 重建 vm 对象后去重标记被清空 → 「已关机（未开启自动开机守护），
          //   本次不自动拉起」这条提示在每个保活周期（约 61 秒）重复刷屏（实测一天 8 次/台）。
          // 改为按前缀统一保留，从机制上杜绝"新增一个本机状态字段又忘了加进白名单"。
          for (const k of Object.keys(old)) {
            if (k.startsWith('_') && old[k] !== undefined) vm[k] = old[k];
          }
          if (old.keepaliveEnabled !== undefined) vm.keepaliveEnabled = old.keepaliveEnabled;
          if (old.keepaliveInterval !== undefined) vm.keepaliveInterval = old.keepaliveInterval;
          if (old.lastKeepAliveAt !== undefined) vm.lastKeepAliveAt = old.lastKeepAliveAt;
          if (old._durationExhausted !== undefined) vm._durationExhausted = old._durationExhausted;
          // 时长恢复时清除耗尽标记（下个计费周期 remainDurationTime 会恢复 > 0，
          // 否则 _durationExhausted 会永久卡住，数据面保活永远无法恢复）
          // 【2026-09-24】同时复位"时长已用完"提示的去重标记 —— 时长恢复后再耗尽，
          // 该提示应当重新出现一次（同理，这是一次状态变化而非重复噪声）。
          if (typeof vm.remainHours === 'number' && vm.remainHours > 0) {
            vm._durationExhausted = false;
            vm._hasWarnedExhausted = false;
          }
          // 2026-09-23：这些是本系统自己的本机状态，必须跨 refresh 保留，否则开关会被刷掉
          if (old.autoBootEnabled !== undefined) vm.autoBootEnabled = old.autoBootEnabled;
          if (old.vendor !== undefined) vm.vendor = old.vendor;
          if (old.vendorName !== undefined) vm.vendorName = old.vendorName;
          if (old.vendorProbedAt !== undefined) vm.vendorProbedAt = old.vendorProbedAt;
          if (old.vendorProbeStale !== undefined) vm.vendorProbeStale = old.vendorProbeStale;
          if (old._lastAutoBootAt !== undefined) vm._lastAutoBootAt = old._lastAutoBootAt;
        } else {
          if (vm.keepaliveEnabled === undefined) vm.keepaliveEnabled = true;
          if (vm.autoBootEnabled === undefined) vm.autoBootEnabled = false;
        }
      }

      // 本轮真正探测过的机器：用**新结论**覆盖差量合并搬回来的旧结论（见上方 freshProbe 说明）。
      // 底座判定必须由"最近一次真实探测"说了算，不能被旧值原地覆盖。
      //
      // 【2026-09-26 修复 fail-open 空洞】判定所需的**输入**（vendor/vendorName/spuCode/
      // vendorProbeStale）都会落盘，而判定**结果** `vm._route` 带 `_` 前缀（本机状态）**不落盘**。
      // 于是进程重启后：vendor 还在 ⇒ 上面 needProbe=false ⇒ 那段判定整体跳过 ⇒
      // `vm._route` 永远 undefined ⇒ runCycle 里 `routeGate(vm._route || null)` 命中
      // fail-open 放行 ⇒ 一台 SCG 机器照样被 ZTE 握手盲拨，每 30s 抛一次
      // 「该机器未暴露 CAG 连接材料（cagIp 缺失），无法开机」。
      // 实测：爱家样本账号两台 `spuCode=sc-cloud-pc`（家庭云电脑畅享版 / 高级版）。
      // ⇒ 对"没有判定但 vendor 已存在"的机器补一次**零网络**重建（spuCode 优先，
      //    否则按已持久化的 vendor 翻译），让闸门重启后依然是一道**有效**闸门。
      for (const vm of vms) {
        const fresh = freshProbe.get(String(vm.userServiceId));
        if (fresh) {
          vm._route = fresh.route;
          vm.vendor = fresh.vendor;
          vm.vendorName = fresh.vendorName;
          vm.vendorProbedAt = fresh.vendorProbedAt;
          vm.vendorProbeStale = false;
          continue;
        }
        if (!vm._route && vm.vendor) {
          const rebuilt = resolveVmRoute(vm, null);
          vm._route = rebuilt.source === 'spuCode' ? rebuilt : routeFromPersistedVendor(vm.vendor);
        }
      }

      this.account.vms = vms;
      this.metrics.vms = vms;

      if (vms.length > 0) {
        const first = vms[0];
        const anyRunning = vms.some(v => !isYdpcVmOff(v));
        this.metrics.status = anyRunning ? 'online' : 'offline';
        this.metrics.vmStatus = first.vmStatus;
        this.metrics.durationMode = first.durationMode;
        this.metrics.remainHours = first.remainHours;
        this.metrics.remainText = first.remainText;
        
        this.account.stats = this.account.stats || {};
        this.account.stats.keepAliveStatus = this.metrics.status;
        this.account.stats.vmStatus = first.vmStatus;
        this.account.stats.durationMode = first.durationMode;
        this.account.stats.remainHours = first.remainHours;
        this.account.stats.remainText = first.remainText;

        if (!anyRunning) {
          this.metrics.lastHeartbeatResult = `云电脑处于已关机状态 (${first.remainText || ''})`;
        } else {
          // 【2026-09-23 修订】运行中同样要刷新账号级摘要。原先只在"全部关机"时写这个
          // 字段，导致机器正常运行时它永远停在初始值「保活巡检待命中」——这正是用户
          // 看到"当前动作一直在待命"的直接原因。
          this.metrics.lastHeartbeatResult = this.buildYdpcSummaryText();
        }
      }

      // 保活失效检测：把"机器由运行变关机"这一**唯一可信判据**（独立查询到的电源状态）
      // 变成显式告警，而不是让用户自己去界面上发现。
      try { this.detectKeepAliveFailure(vms, accName); } catch (e) { /* 告警失败不得影响刷新 */ }

      this.saveConfig();
      return vms;
    } catch (err) {
      this.appendLog('SOHO', `[${accName}] 刷新云电脑列表异常: ${err.message}`, 'error', accName, 'ydpc');
      return this.account.vms || [];
    }
  }

  async ensureMqttConnection() {
    const accName = this.account.name || this.account.user;
    if (this.account.features?.mqttKeepAlive === false) {
      if (this.mqttClient) {
        this.mqttClient.disconnect();
        this.mqttClient = null;
      }
      return;
    }

    // 智能全关机感知：仅当名下所有云电脑均已关机、或保活开关全关时，才不发起 MQTT 连接。
    // 【2026-09-23 用户要求】时长耗尽（20 小时到期）**不再**阻断 MQTT ——
    // 时长耗尽只阻止"开机/拉起"，不阻止"对一台已在运行机器的保活"。
    // 场景：到期后用户用其他方式把机器启动（系统已判定运行中），此时仍应正常保活。
    const vms = this.account.vms || [];
    const allOffOrDisabled = vms.length > 0 && vms.every(vm => {
      // 【2026-09-26 修复】必须走权威 isYdpcVmOff()：就地写法漏了「未开机」与 vmStatusCode===0，
      // 于是一台 SCG（深信服）"未开机"的机器在这里被判成运行中，MQTT 白连一场。
      const isVmOff = isYdpcVmOff(vm);
      return isVmOff || vm.keepaliveEnabled === false;
    });

    if (allOffOrDisabled) {
      if (this.mqttClient) {
        this.mqttClient.disconnect();
        this.mqttClient = null;
      }
      return;
    }

    if (this.mqttClient && this.mqttClient.isConnected) {
      return;
    }

    // 防频繁重试退避：若上次连接失败，至少冷却 5 分钟（300s）后再重试，绝不刷屏
    if (this._lastMqttFailedAt && Date.now() - this._lastMqttFailedAt < 300000) {
      return;
    }

    try {
      if (!this.sohoClient.sohoToken) {
        await this.login();
      }
      const res = await this.sohoClient.getMqttConnectInfo();
      if (res && res.code === 2000 && res.data) {
        const info = res.data;
        // 核心解析：官方 /system/mqttConnect/v1 返回结构解析：
        // 1. url: "ssl://alive.soho.komect.com" (提取主机与端口)
        // 2. 官方标准 MQTTS 端口为 8883 (若未指定或配置为 443 会被防火墙直接丢包超时)
        // 3. 官方 MQTT 凭证字段为 jwt (非 password)
        // 4. 心跳保活参数为 mqttKeepAlive (非 keepAlive，通常为 30s)
        let host = 'alive.soho.komect.com';
        let port = 8883;
        if (info.url) {
          const match = info.url.match(/^(?:ssl|mqtts|tcp):\/\/([^:/]+)(?::(\d+))?/i);
          if (match) {
            host = match[1];
            if (match[2]) port = Number(match[2]);
          }
        } else if (info.host) {
          host = info.host;
          if (info.port && Number(info.port) !== 443) port = Number(info.port);
        }

        const clientId = info.clientId || `cl_${this.account.user.slice(-4)}_${Date.now().toString(36)}`;
        const username = info.userName || info.username || '';
        const password = info.jwt || info.password || '';
        const keepAliveSeconds = Number(info.mqttKeepAlive || info.keepAlive) || 30;

        if (this.mqttClient) {
          this.mqttClient.disconnect();
        }

        this.mqttClient = new MqttKeepAliveClient({
          host,
          port,
          clientId,
          username,
          password,
          keepAliveSeconds,
          onLog: (src, msg, lvl) => this.appendLog(src, `[${accName}] ${msg}`, lvl, accName, 'ydpc')
        });

        await this.mqttClient.connect(10000);
        this._lastMqttFailedAt = 0;
        this.appendLog('MQTT', `[${accName}] 🟢 官方 MQTT 3.1.1 over TLS 链路已连接保持 (Broker: ${host}:${port})`, 'success', accName, 'ydpc');
      }
    } catch (err) {
      this._lastMqttFailedAt = Date.now();
      this.appendLog('MQTT', `[${accName}] MQTT 链路连接异常: ${err.message} (已转入5分钟静默退避)`, 'warning', accName, 'ydpc');
    }
  }

  async sendHeartbeat(userServiceId) {
    const accName = this.account.name || this.account.user;
    const usid = userServiceId || this.account.vms?.[0]?.userServiceId;
    if (!usid) throw new Error('未找到有效的 userServiceId');

    const currentVm = (this.account.vms || []).find(v => String(v.userServiceId) === String(usid));
    if (currentVm && isYdpcVmOff(currentVm)) {
      this.metrics.status = 'offline';
      if (this.account.stats) this.account.stats.keepAliveStatus = 'offline';
      this.metrics.lastHeartbeatResult = `云电脑 [${currentVm.vmName}] 处于已关机状态 (待命中)`;
      this._recordVmAction(usid, '已关机 · 心跳待命', 'off');
      this.appendLog('SOHO', `[${accName}][${currentVm.vmName}] 云电脑当前处于已关机状态，心跳守护待命中。`, 'info', accName, 'ydpc');
      // 【2026-09-26 修复·假成功】"没做事"必须报 success:false —— 与 pingCag 统一契约。
      // 旧写法返回 success:true，调用方于是把"待命"记成了"完成"。
      return { success: false, message: '云电脑处于关机状态' };
    }

    try {
      if (!this.sohoClient.sohoToken) {
        await this.login();
      }
      const res = await this.sohoClient.heartbeat(usid);
      
      // 触发官方活跃度埋点上报 (对齐 point.soho.komect.com)
      this.sohoClient.pointEvent('heartbeat', { userServiceId: Number(usid) }).catch(() => {});

      const nowStr = getBeijingTimeOnly();
      this.metrics.status = 'online';
      if (this.account.stats) this.account.stats.keepAliveStatus = 'online';
      this.metrics.lastHeartbeatTime = nowStr;
      this.metrics.lastHeartbeatResult = `SOHO 心跳保持活跃 (${nowStr})`;
      this._recordVmAction(usid, '✅ SOHO 心跳保持成功', 'ok');
      this.appendLog('SOHO', `[${accName}] 💓 SOHO 心跳保持成功 (userServiceId: ${usid})`, 'info', accName, 'ydpc');
      return res;
    } catch (err) {
      this.metrics.status = 'offline';
      if (this.account.stats) this.account.stats.keepAliveStatus = 'offline';
      this.metrics.lastHeartbeatResult = `心跳异常: ${err.message}`;
      this._recordVmAction(usid, `SOHO 心跳异常: ${err.message}`, 'error');
      throw err;
    }
  }

  async pingCag(userServiceId, holdSeconds = 3) {
    const accName = this.account.name || this.account.user;
    const usid = userServiceId || this.account.vms?.[0]?.userServiceId;
    if (!usid) throw new Error('未找到有效的 userServiceId');

    const currentVm = (this.account.vms || []).find(v => String(v.userServiceId) === String(usid));
    if (currentVm && isYdpcVmOff(currentVm)) {
      this.metrics.status = 'offline';
      if (this.account.stats) this.account.stats.keepAliveStatus = 'offline';
      this.metrics.lastHeartbeatResult = `云电脑 [${currentVm.vmName}] 处于已关机状态 (待命中)`;
      this._recordVmAction(usid, '已关机 · CAG 握手待命', 'off');
      return { success: false, message: '云电脑处于关机状态' };
    }

    // 【2026-09-26 修复·SCG 机没有 CAG 通道】SCG 底座的 firm-auth 里 cagIp/cagPort/vmcIp
    // **全空**（现场样本见 product_route.js），它的官方开机触发位于 CEM 通道内 —— 本项目不引入。
    // 对这类机器发起 CAG 握手只会得到 `getaddrinfo ENOTFOUND undefined`（主机名是字面量
    // "undefined"），再被 classifyZteError 按 /ENOTFOUND|getaddrinfo/ 判成 hard ⇒ error 级告警。
    // 与"机器没开机"同属"本次没做事"：按 skipped 返回，既不记成功，也不渲染成失败。
    if (currentVm && (currentVm.vendor === 'SCG' ||
        (currentVm._route && currentVm._route.kind === 'SCG'))) {
      this.metrics.lastHeartbeatResult = `云电脑 [${currentVm.vmName}] 为 SCG 底座（无 CAG 通道），本次未发起握手`;
      this._recordVmAction(usid, 'SCG 底座 · 无 CAG 握手通道', 'off');
      return { success: false, message: 'SCG 底座无 CAG 通道，本次未发起握手' };
    }

    try {
      if (!this.sohoClient.sohoToken) {
        await this.login();
      }
      const firmAuth = await this.sohoClient.getFirmAuth(usid);
      // 【2026-09-26 修复】材料缺失 ⇒ **连拨都不拨**。此前会把 undefined 拼成主机名，
      // 真的去解析一个叫 "undefined" 的主机（现场日志 getaddrinfo ENOTFOUND undefined）。
      // 这是"这台机器没有这条通道/材料没下来"，不是网络抖动，必须如实按跳过处理。
      if (!firmAuth || !(firmAuth.cagIp || firmAuth.cagHost)) {
        this.metrics.lastHeartbeatResult = '该机器未下发 CAG 连接材料（cagIp 缺失），本次未发起握手';
        this._recordVmAction(usid, '无 CAG 材料 · 本次未发起握手', 'off');
        return { success: false, message: '该机器未下发 CAG 连接材料（cagIp 缺失），本次未发起握手' };
      }
      this.appendLog('CAG', `[${accName}] 正在向中兴 CAG 网关 (${firmAuth.cagIp}:${firmAuth.cagPort}) 发起 ZTEC TCP 三阶段握手...`, 'info', accName, 'ydpc');

      const cagRes = await performCagAuthHold(firmAuth, holdSeconds);
      const nowStr = getBeijingTimeOnly();
      
      this.metrics.status = 'online';
      this.metrics.lastHeartbeatTime = nowStr;
      this.metrics.lastHeartbeatResult = `ZTEC CAG 握手 200 OK (${nowStr})`;
      this._recordVmAction(usid, '✅ ZTEC CAG 握手 200 OK', 'ok');
      this.metrics.successCount++;

      this.account.stats = this.account.stats || {};
      this.account.stats.keepAliveStatus = 'online';
      this.account.stats.lastKeepAliveTime = getBeijingTimeString();
      this.saveConfig();

      this.appendLog('CAG', `[${accName}] 🟢 ZTEC CAG TCP 三阶段握手成功，网关返回 200 OK！`, 'success', accName, 'ydpc');
      return cagRes;
    } catch (err) {
      this.metrics.status = 'offline';
      if (this.account.stats) this.account.stats.keepAliveStatus = 'offline';
      const errMsg = err.message || '';
      if (errMsg.includes('用完') || errMsg.includes('已用尽') || errMsg.includes('计费周期') || errMsg.includes('到期') || errMsg.includes('欠费')) {
        this.metrics.lastHeartbeatResult = `时长已耗尽 (${errMsg})`;
        this._recordVmAction(usid, `当前计费周期时长已用完`, 'warn');
        if (currentVm) {
          currentVm.durationMode = 'limited';
          currentVm.remainText = '⏱️ 0小时';
          currentVm.remainHours = 0;
          currentVm._durationExhausted = true;
        }
        this.metrics.remainText = '⏱️ 0小时';
        this.metrics.remainHours = 0;
      } else {
        this.metrics.lastHeartbeatResult = `CAG 握手受阻: ${errMsg}`;
        this._recordVmAction(usid, `CAG 握手受阻: ${errMsg}`, 'error');
      }
      this.saveConfig();
      throw err;
    }
  }

  async controlPower(userServiceId, action = 'poweron') {
    const accName = this.account.name || this.account.user;
    const usid = userServiceId || this.account.vms?.[0]?.userServiceId;
    if (!usid) throw new Error('未找到有效的 userServiceId');

    if (!this.sohoClient.sohoToken) {
      await this.login();
    }

    const actionLower = (action || '').toLowerCase();
    if (actionLower === 'reboot') {
      this.appendLog('SOHO', `[${accName}] 正在向移动爱家下发【重启】指令 (userServiceId: ${usid})...`, 'info', accName, 'ydpc');
      const res = await this.sohoClient.rebootVm(usid);
      this.appendLog('SOHO', `[${accName}] ✅ 云电脑重启指令已生效！`, 'success', accName, 'ydpc');
      setTimeout(() => this.refreshVms().catch(() => {}), 3000);
      return res;
    } else if (actionLower === 'shutdown' || actionLower === 'poweroff') {
      this.appendLog('SOHO', `[${accName}] 正在向移动爱家下发【关机/断开】指令 (userServiceId: ${usid})...`, 'info', accName, 'ydpc');
      const res = await this.sohoClient.shutdownVm(usid);
      this.appendLog('SOHO', `[${accName}] ✅ 云电脑关机/断开指令已生效！`, 'success', accName, 'ydpc');
      setTimeout(() => this.refreshVms().catch(() => {}), 2000);
      return res;
    }

    // 【2026-09-23 修订】开机能力已恢复，但改为走 CAG HTTPS 干净通道（见 app/ydpc/cag_boot.js）。
    // 口径（用户 2026-09-23 明确选择）：
    //   ✅ 使用账号自身 firm-auth 凭据   ✅ RSA 公钥动态获取   ✅ 保留 TLS 证书校验
    //   ❌ 不伪造第三方 SC 客户端身份    ❌ 不硬编码任何第三方凭据
    // 伪造身份 / 硬编码凭据 / 关证书 仍属禁止项，由回归组 7 机械拦截。
    if (actionLower === 'poweron' || actionLower === 'boot' || actionLower === 'awake' || actionLower === 'start') {
      return await this.bootVmViaCag(usid, accName);
    }

    throw new Error(`未知的电源操作: ${action}`);
  }

  /**
   * 通过 CAG 通道拉起一台已关机的机器（干净实现）。
   * 开机凭据来自账号自身 firm-auth；RSA 公钥由 CAG 动态下发；保留证书校验。
   */
  async bootVmViaCag(userServiceId, accName = null) {
    const name = accName || this.account.name || this.account.user;
    if (!this.sohoClient.sohoToken) {
      await this.login();
    }

    this.appendLog('CAG', `[${name}] 正在通过 CAG 干净通道拉起云电脑 (userServiceId: ${userServiceId})...`, 'info', name, 'ydpc');

    let firmAuth;
    try {
      firmAuth = await this.sohoClient.getFirmAuth(userServiceId);
    } catch (err) {
      const msg = `获取开机凭据失败：${err.message}`;
      this.appendLog('CAG', `[${name}] ❌ ${msg}`, 'error', name, 'ydpc');
      throw new Error(msg);
    }

    // 【2026-09-23 G1 底座闸门】拨号之前先确认底座，**用刚取到的 firmAuth 现算**，
    // 不复用 refreshVms 的缓存 —— 开机误拨的代价比保活高（会真的向网关发出 CSAP 建连请求）。
    // 判不出底座（UNKNOWN）同样拒绝：宁可明确报"底座未知"，也不假装它是 ZTE 去盲拨。
    const vmRef = (this.account.vms || []).find(v => String(v.userServiceId) === String(userServiceId)) || { userServiceId };
    const gate = routeGate(resolveVmRoute(vmRef, firmAuth));
    if (!gate.allow) {
      const msg = `已拒绝开机拨号 · ${gate.reason}`;
      this.appendLog('CAG', `[${name}] ⛔ ${msg}`, 'warning', name, 'ydpc');
      this._recordVmAction(userServiceId, `⛔ ${msg}`, 'warn');
      throw new Error(msg);
    }

    // SCG 底座开机走 **CEM 官方通道**（2026-09-26 真机验证通过：OAuth → getConnectInfo
    // 本身就是开机触发 → 轮询 readyStatus 至 1；与保活的 CEM 控制面同一套已获批端点与材料）。
    if (resolveVmRoute(vmRef, firmAuth).kind === 'SCG') {
      return await this.bootVmViaCem(userServiceId, accName, firmAuth);
    }

    const { cagBootVm } = require('./cag_boot');
    const result = await cagBootVm(firmAuth, {
      onLog: (label, message, level) => this.appendLog(label, `[${name}] ${message}`, level, name, 'ydpc')
    });

    if (result.success) {
      this.appendLog('CAG', `[${name}] ✅ 云电脑已拉起：${result.message}`, 'success', name, 'ydpc');
      setTimeout(() => this.refreshVms().catch(() => {}), 3000);
      return result;
    }

    this.appendLog('CAG', `[${name}] ❌ 开机失败：${result.message}`, 'error', name, 'ydpc');
    throw new Error(result.message);
  }

  /**
   * SCG（深信服）底座开机：CEM 官方通道（真机 2026-09-26 验证通过）。
   * 机制：OAuth(scAuthCode→access_token) → getConnectInfo（**本身就是开机触发**，
   * 对未开机机器服务端会握住连接等拉起后才响应，故内部超时放大到 120s）
   * → 轮询 getVmReadyStatus 至 readyStatus=1（默认最长 180s）。
   * 无新增凭据：client_id / sdk2 公钥与保活的 CEM 路径同源（用户已批准）。
   * @returns {Promise<{success:boolean, message:string}>}
   */
  async bootVmViaCem(userServiceId, accName = null, firmAuth = null) {
    const name = accName || this.account.name || this.account.user;
    this.appendLog('SCG', `[${name}] 正在通过 CEM 官方通道拉起云电脑 (userServiceId: ${userServiceId})...`, 'info', name, 'ydpc');

    let auth = firmAuth;
    if (!auth) {
      try {
        auth = await this.sohoClient.getFirmAuth(userServiceId);
      } catch (err) {
        const msg = `获取开机凭据失败：${err.message}`;
        this.appendLog('SCG', `[${name}] ❌ ${msg}`, 'error', name, 'ydpc');
        throw new Error(msg);
      }
    }

    let r;
    try {
      r = await cemBootVm(auth, {
        maxWaitSeconds: 180,
        onLog: (label, message, level) => this.appendLog(label, `[${name}] ${message}`, level, name, 'ydpc')
      });
    } catch (e) {
      // 【2026-09-27】任何 CEM 异常都必须落到日志（此前直接冒泡到 toast，日志里什么都没有）。
      this.appendLog('SCG', `[${name}] ❌ CEM 开机流程异常：${e.message}`, 'error', name, 'ydpc');
      // 失败前先做独立状态核验：CEM 报了错 ≠ 机器没被拉起（真机实测 504/超时后机器照样启动）
      const verified = await this._verifyVmRunning(userServiceId);
      if (verified) {
        const okMsg = '开机已在途并核实生效：独立状态接口显示机器已运行（CEM 网关超时不影响开机结果）';
        this.appendLog('SCG', `[${name}] ✅ ${okMsg}`, 'success', name, 'ydpc');
        this._recordVmAction(userServiceId, '✅ 开机生效（独立核验：运行中）', 'ok');
        setTimeout(() => this.refreshVms().catch(() => {}), 3000);
        return { success: true, message: okMsg };
      }
      this._recordVmAction(userServiceId, `❌ CEM 开机异常: ${e.message}`, 'error');
      throw e;
    }

    if (r.ok) {
      this.appendLog('SCG', `[${name}] ✅ 云电脑已拉起并就绪（readyStatus=1），CEM 开机完成`, 'success', name, 'ydpc');
      this._recordVmAction(userServiceId, '✅ CEM 开机完成（已就绪）', 'ok');
      setTimeout(() => this.refreshVms().catch(() => {}), 3000);
      return { success: true, message: 'CEM 开机完成，机器已就绪' };
    }

    // pending（504/超时/未就绪）：先独立核验，再如实下结论 —— 绝不把"正在开机"报成失败
    const verified = await this._verifyVmRunning(userServiceId);
    if (verified) {
      const okMsg = '开机已生效：独立状态接口显示机器已在运行（CEM 等待窗口内未及确认，不影响结果）';
      this.appendLog('SCG', `[${name}] ✅ ${okMsg}`, 'success', name, 'ydpc');
      this._recordVmAction(userServiceId, '✅ 开机生效（独立核验：运行中）', 'ok');
      setTimeout(() => this.refreshVms().catch(() => {}), 3000);
      return { success: true, message: okMsg };
    }
    const msg = `CEM 开机指令已下发，机器仍在启动中（${r.reason || '等待窗口内未就绪'}），稍后自动刷新状态`;
    this.appendLog('SCG', `[${name}] 🟠 ${msg}`, 'warning', name, 'ydpc');
    this._recordVmAction(userServiceId, '🟠 CEM 开机已触发，启动中', 'warn');
    setTimeout(() => this.refreshVms().catch(() => {}), 10000);
    return { success: true, message: msg };
  }

  /**
   * 独立状态核验：走 SOHO 云电脑列表接口确认某台机器当前是否运行中。
   * 用途（对齐 analysis/移动云CAG脚本开机-实测结论.md 的核验纪律）：
   * 开机链路自身的报错/超时**不构成"没开成"的证据**——必须用独立接口核实后再下结论。
   * @returns {Promise<boolean>} true=列表接口明确显示运行中（读不到列表时返回 false，不猜）
   */
  async _verifyVmRunning(userServiceId) {
    try {
      const vms = await this.sohoClient.listCloudPcs();
      const t = (vms || []).find((v) => String(v.userServiceId) === String(userServiceId));
      return !!(t && !isYdpcVmOff(t));
    } catch (e) {
      return false;
    }
  }

  /**
   * ==========================================================================
   * 数据面保活（P3 接入 · 2026-09-23）
   * ==========================================================================
   * 在控制面（SOHO 心跳 / CAG 握手 / MQTT）之上，新增官方客户端同款的
   * raw ZTEC 数据面保活（app/ydpc/zte_cag_raw.js）。
   *
   * 背景：HTTP 心跳 / CAG 刷新都只能证明"管道通"，不能阻止平台按"无活动"关机；
   * 唯一真保活是官方客户端的"原生传输"（IPv6 环境下为 raw ZTEC 帧）。
   * 本机实测（tools/probe_cag_raw_keepalive.js）已打通拨号 + HB 心跳回包。
   *
   * ⚠️ session-owning 代价（用户已确认接受）：数据面保活建立的是独占桌面会话，
   * 开启期间官方 App / PC 客户端可能无法同时接入这台机器。
   *
   * 开关：账号级 `features.dataPlaneKeepalive !== false`（"自动化保活开关"区，默认开启）
   *       + 单机现有「⚡保活」开关（keepaliveEnabled）。单机不再单独设数据面开关。
   * 循环：拿 connectStr → 拨号 → ADD_LINK/DATA 预热 → HB 心跳 hold 15 分钟 →
   *       重拨（刷新 connectStr 防 TTL 过期 / 防 ~30min 空闲关机）。
   */

  /**
   * 按账号级开关决定启动/停止数据面保活后台任务。
   * 由主巡检循环每 tick 调用一次，幂等。
   *
   * 开关口径（2026-09-23 用户定稿）：
   *   账号级 features.dataPlaneKeepalive !== false（"自动化保活开关"区，默认开启）
   *   且 单机 vm.keepaliveEnabled !== false（单机只有「⚡保活」一个开关）
   *   且 机器运行中
   *   且 时长未耗尽（耗尽则网关拒绝 connectStr，无法数据面；改走控制面保活）
   * 同时满足 → 该机器走数据面保活，并抑制其 SOHO 心跳/CAG 握手（冗余）。
   */
  ensureDataPlaneKeepalive(vm, accName) {
    const usid = String(vm.userServiceId);
    const wantOn = this.account.features?.dataPlaneKeepalive !== false
      && vm.keepaliveEnabled !== false
      && !this.isVmLimitedExpired(vm);
    const existing = this.dataPlaneTasks.get(usid);

    if (!wantOn || isYdpcVmOff(vm)) {
      // 账号开关关闭 / 单机保活关闭 / 时长耗尽 / 机器关机（拨号必失败）→ 停止
      if (existing) this.stopDataPlaneTask(usid, accName);
      return;
    }
    if (existing && existing.running) return; // 已在跑
    this.startDataPlaneTask(vm, usid, accName);
  }

  /**
   * 该机器当前是否**真的有**一条活跃的数据面隧道。
   *
   * 【2026-09-26 修复·假活跃】判据不能只看 `task.running`：失败重试的循环同样是 running，
   * 于是一个从未建立过隧道的任务会一直把控制面（SOHO 心跳 + CAG 握手）压住，
   * 机器反而**一条保活动作都没有**而被平台关机（用户现场："已经开机了，为什么无法保活？
   * 一直自动关机"，同一时段告警却写着"数据面保活=活跃"）。
   * ⇒ 只有"运行中 **且** 未连续失败到阈值"才算在场；到阈值即交还控制面。
   */
  isDataPlaneActive(usid) {
    const task = this.dataPlaneTasks.get(String(usid));
    if (!task || !task.running) return false;
    return (task.failStreak || 0) < DATA_PLANE_FAIL_LIMIT;
  }

  /**
   * 数据面**有进展**（隧道建成 / 切片正常走完）⇒ 清零失败计数并撤销降级。
   * 必须有这个反向动作：否则一次瞬时抖动会把"已降级"永久焊住，
   * 数据面就算恢复正常也再也拿不回抑制权（与"一次故障永久挂卡片上"同源）。
   */
  _noteDataPlaneProgress(task, usid, name) {
    if (!task) return;
    const wasDemoted = task.demoted === true;
    task.failStreak = 0;
    task.lastProgressAt = Date.now();
    if (wasDemoted) {
      task.demoted = false;
      this.appendLog('CAGRAW', `[${name}] 数据面已恢复（隧道重新建立），控制面心跳转入抑制`, 'info', name, 'ydpc');
      this._recordVmAction(usid, '📡 数据面已恢复', 'ok');
    }
  }

  /**
   * 数据面**失败一次** ⇒ 累加；到阈值即判定"隧道并不存在"，留证并把控制面交还。
   * 留证是刻意的：用户此前只看到"数据面=活跃"的结论，看不到"其实每 30s 都在失败"。
   */
  _noteDataPlaneFailure(task, usid, name, errMsg) {
    if (!task) return;
    task.failStreak = (task.failStreak || 0) + 1;
    if (task.failStreak >= DATA_PLANE_FAIL_LIMIT && task.demoted !== true) {
      task.demoted = true;
      this.appendLog(
        'CAGRAW',
        `[${name}] 数据面连续 ${task.failStreak} 次未能建立隧道（最近一次：${errMsg}），` +
        // 措辞按底座分叉：SCG 底座**没有** CAG 握手通道，笼统写"CAG 握手"是失真
        `已交还控制面保活${task.routeKind === 'SCG'
          ? '（SCG 底座无 CAG 握手通道，仅剩 SOHO 心跳）'
          : '（SOHO 心跳 + CAG 握手）'}继续重试数据面`,
        'warning', name, 'ydpc'
      );
      this._recordVmAction(usid, '⚠ 数据面未建立 · 已交还控制面保活', 'warn');
    }
  }

  /**
   * ==========================================================================
   * 按主机维度的保活状态视图（移动云多机）
   * ==========================================================================
   * 为什么需要：一个移动云账号下可以挂多台云电脑，各机状态（运行/关机/时长耗尽/
   * 单机保活开关/独立周期/数据面是否在场）可以完全不同。原来界面"当前动作"只有一行
   * 账号级文案，既无法表达多机差异，又因为 refreshVms() 只在"全部关机"时才写它，
   * 导致机器运行中时它永远停在初始值「保活巡检待命中」。
   *
   * 本方法在**序列化给前端时**按需调用（保证倒计时实时），严格只读、无副作用。
   * 任何"由状态推导"的文案都必须可从已有字段复现，不臆造无法验证的成功。
   */
  /**
   * 自动开机守护的**唯一武装判定**（runCycle 守护与状态视图共用，杜绝两套判定漂移）。
   *
   * 【2026-09-28 用户拍板】默认口径按底座分叉，而不是一刀切：
   *   · 账号含 SCG 机器（如爱家样本账号）⇒ 默认**开启**（平台强制关机拦不住，就自动恢复；
   *     SCG 开机走已验证的 CEM 通道，无额外代价）；
   *   · 纯 ZTE 账号 ⇒ 保持默认**关闭**（ZTE 开机走 CAG，会真实消耗限时套餐时长，
   *     需用户显式开启，沿用 2026-09-23 的保守口径）。
   * 双开关任一显式 `=== false` 即未武装；显式 `true` 即武装。
   */
  _autoBootArmed(vm) {
    const isScg = (v) => String((v && v.vendor) || '').toUpperCase() === 'SCG'
      || !!(v && v._route && v._route.kind === 'SCG');
    const accFlag = this.account.features?.autoBoot;
    const accOn = accFlag === undefined
      ? (this.account.vms || []).some(isScg)
      : accFlag !== false;
    const vmFlag = vm && vm.autoBootEnabled;
    const vmOn = vmFlag === undefined ? isScg(vm) : vmFlag !== false;
    return accOn && vmOn;
  }

  describeVmKeepAlive(vm) {
    const f = (this.account && this.account.features) || {};
    const usid = String((vm && vm.userServiceId) || '');
    const vmName = (vm && vm.vmName) || '移动云电脑';
    const defaultIntervalSec = Math.max(60, parseInt(this.account && this.account.keepaliveInterval) || 600);
    const intervalSec = Math.max(60, parseInt(vm && vm.keepaliveInterval) || defaultIntervalSec);

    const running = !isYdpcVmOff(vm);
    const keepaliveOn = !vm || vm.keepaliveEnabled !== false;
    const limitedExpired = this.isVmLimitedExpired(vm);
    const allChannelsOff = f.controlPlaneKeepalive === false &&
                           f.mqttKeepAlive === false &&
                           f.dataPlaneKeepalive === false;
    const globalKeepAliveOff = f.keepAlive === false || allChannelsOff;
    // 【2026-09-28 用户拍板】守护武装判定统一走 _autoBootArmed（默认口径见该方法注释）
    const autoBootArmed = this._autoBootArmed(vm);
    const dataPlaneActive = this.isDataPlaneActive(usid);

    // 【G3 双标志分离】"通道在场"与"保活有效"分成两个字段，互不冒充
    // 以下三项都是**纯读取** vm 上由别处写入的事实，本方法内不做任何推导或副作用。
    // 该机最近一轮的实际失败等级（由 runCycle 按 G2 分级写入）
    const failureKind = (vm && vm._lastFailureKind) || 'none';
    const failureText = (vm && vm._lastFailureText) || '';
    // 该机底座路由判定（由 refreshVms 按 G1 写入）
    const routeKind = (vm && vm._route && vm._route.kind) || '';
    const routeRefused = !!(vm && vm._route && vm._route.supported === false);
    const routeReason = (vm && vm._route && vm._route.reason) || '';

    const lastKeepAliveAt = Number(vm && vm.lastKeepAliveAt) || 0;
    const nextDueAt = lastKeepAliveAt > 0 ? lastKeepAliveAt + intervalSec * 1000 : 0;

    // 【G5】数据面通道名必须**如实**反映当前实际走的那条（地址族由 connectStr 内层主机决定，
    // 是"每台每次取材料"的属性，不是账号属性）。任务尚未建起 path 时留空，不臆造。
    const dpTask = (this.dataPlaneTasks && this.dataPlaneTasks.get)
      ? (this.dataPlaneTasks.get(usid) || null)
      : null;
    const dpPath = (dpTask && dpTask.path) || '';
    const dpChannel = dpPath === 'tls' ? 'IPv4 · TLS+SPICE'
      : (dpPath === 'raw' ? 'IPv6 · raw ZTEC'
        : (dpPath === 'scg' ? 'SCG · trunk+SPICE' : ''));

    let tone = 'off';
    let actionText = '待命中';
    let hintText = '';

    if (!keepaliveOn) {
      tone = 'off';
      actionText = '单机保活已关闭';
      hintText = '该主机不参与保活巡检';
    } else if (!running) {
      if (limitedExpired) {
        tone = 'warn';
        actionText = '时长耗尽 · 已关机';
        hintText = '套餐时长已用完，自动开机守护已熔断';
      } else if (autoBootArmed && routeKind === 'SCG') {
        // 【2026-09-26 恢复】SCG 开机已真机打通（CEM 通道），守护对 SCG 机器真实生效：
        tone = 'idle';
        actionText = '已关机 · SCG 自动开机守护中（CEM）';
        hintText = '守护已就绪：下个巡检周期将通过 CEM 通道自动拉起（同机 10 分钟冷却）';
      } else if (autoBootArmed) {
        tone = 'idle';
        actionText = '已关机 · 自动开机守护中';
        hintText = 'CAG/CEM 通道按底座分流，检测到关机将自动拉起（同机 10 分钟冷却）';
      } else {
        tone = 'off';
        actionText = '已关机 · 守护未开启';
        hintText = '请在移动爱家官方 App 连接一次，或开启「自动开机守护」';
      }
    } else if (globalKeepAliveOff) {
      tone = 'off';
      actionText = '全局保活已关闭';
      hintText = '账号级保活总开关关闭，本机不参与巡检';
    } else if (routeRefused) {
      // G1 底座闸门拒绝：本机底座不是 ZTE（或判不出来），系统**主动不拨号**。
      // 必须显式说出来，否则会呈现成"在保活但没效果"——那是最失真的一种展示。
      tone = 'warn';
      actionText = `底座不支持 (${routeKind || '未知'}) · 已跳过`;
      hintText = routeReason;
    } else if (dataPlaneActive) {
      tone = 'ok';
      actionText = dpChannel ? `数据面保活中 (${dpChannel})` : '数据面保活中';
      hintText = '独占桌面会话，控制面心跳已抑制';
    } else if (failureKind === 'hard' || failureKind === 'tokenRetry') {
      // 本轮拨号真失败（含重登后仍失效）→ 用既有 error 基调（🔴 #dc2626）浮出来，
      // 不让它只藏在"最近动作"里等人自己去翻。
      tone = 'error';
      actionText = failureKind === 'tokenRetry' ? '会话失效 · 待重登重试' : '拨号失败 · 待下轮重试';
      hintText = failureText;
    } else if (failureKind === 'soft') {
      // 已知非致命（维护 / 升级 / 时长耗尽 / 限流）：如实标 warn，但**不标"失败"**——
      // 区分"通道这条没走通"和"保活坏了"，这是 G2 存在的全部意义。
      tone = 'warn';
      actionText = '通道暂不可用 · 已跳过本轮';
      hintText = failureText;
    } else if (lastKeepAliveAt === 0) {
      tone = 'idle';
      actionText = '即将首次巡检';
      hintText = '尚未产生过保活记录';
    } else if (Date.now() >= nextDueAt) {
      tone = 'idle';
      actionText = '巡检时间已到 · 即将执行';
      hintText = '';
    } else {
      tone = 'ok';
      actionText = '保活运行中';
      hintText = '';
    }

    const rec = (this.metrics && this.metrics.vmActions && this.metrics.vmActions[usid]) || null;

    return {
      usid,
      vmName,
      running,
      keepaliveOn,
      intervalSec,
      lastKeepAliveAt,
      nextDueAt,
      tone,
      actionText,
      hintText,
      // ── G2 / G3 诚实性字段（前端暂不消费，先让"事实"可被日志与测试取用） ──
      failureKind,
      failureText,
      routeKind,
      // G5 数据面通道（'' 表示尚未判明/未建起；'raw'=IPv6，'tls'=IPv4）
      dataPlanePath: dpPath,
      dataPlaneChannel: dpChannel,
      // candidateAccepted 语义：服务端**接受过**我们的动作（账号级成功计数 > 0）。
      // 它只能证明"管道通"，**不能证明保活有效**。
      serverAccepted: !!(this.metrics && Number(this.metrics.successCount) > 0),
      // keepaliveProven：**恒为 false 的硬编码常量**。本通道从未被证明有效——
      // 观测窗口仍是短窗口（数小时级），不足以证明长周期有效。
      // ⚠️ 严禁改成运行时推导：独立电源状态核验（verifyKeepAliveEffect /
      // detectKeepAliveFailure）只负责"发现失效"，不构成"证明有效"。
      // 回归组 23 机械拦截任何把它变成非常量的改动（变异 M56）。
      keepaliveProven: false,
      // 最近一次发生的实际动作（含时间戳，由前端原样展示——不做"是否算当前"的
      // 时间启发式判断，避免把过期动作伪装成正在进行的事）
      lastActionText: rec ? rec.text : '',
      lastActionLevel: rec ? (rec.level || 'info') : '',
      lastActionAt: rec ? rec.at : 0,
      lastKeepAliveText: lastKeepAliveAt > 0
        ? new Date(lastKeepAliveAt).toLocaleTimeString('sv-SE', { timeZone: 'Asia/Shanghai' })
        : '',
      // 【2026-09-28】守护武装态（界面胶囊与 5 秒同步的唯一真源，避免前端复刻默认口径）
      autoBootArmed
    };
  }

  /**
   * 记录"某台主机最近一次动作"，供前端按主机维度展示。
   * 只写内存 metrics.vmActions，不碰持久化配置（避免把临时文案写进 config.json）。
   */
  _recordVmAction(usid, text, level = 'info') {
    const key = String(usid || '');
    if (!key || !text) return;
    if (!this.metrics.vmActions || typeof this.metrics.vmActions !== 'object') {
      this.metrics.vmActions = {};
    }
    this.metrics.vmActions[key] = { text: String(text), level, at: Date.now() };
  }

  /**
   * 账号级摘要文案：明确写出"几台运行中 / 几台已关机 / 几台关闭保活"，
   * 取代原先"运行中时永不刷新"的账号级 lastHeartbeatResult。
   */
  buildYdpcSummaryText() {
    const vms = (this.account && this.account.vms) || [];
    if (vms.length === 0) return '名下暂未发现云电脑';
    let running = 0;
    let off = 0;
    let paused = 0;
    for (const vm of vms) {
      if (vm.keepaliveEnabled === false) { paused++; continue; }
      if (isYdpcVmOff(vm)) off++; else running++;
    }
    const seg = [];
    if (running) seg.push(`${running} 台运行中·巡检中`);
    if (off) seg.push(`${off} 台已关机`);
    if (paused) seg.push(`${paused} 台单机保活关闭`);
    return `多机独立巡检 (${seg.join(' / ')})`;
  }

  /**
   * ==========================================================================
   * 保活失效检测（运行中 → 已关机 的转移告警）
   * ==========================================================================
   * 为什么需要：数据面 / 控制面的"成功"都是**自证**的 —— `hb_recv > 0` 只说明管道通、
   * 网关在回包，**不能说明机器不会被关机**（zte_cag_raw.js 的 onData 连内容都不校验）。
   * 唯一可信的判据是**独立查询到的电源状态**（listCloudPcs）。
   *
   * 此前系统只在界面上把状态悄悄改成「已关机」，没有任何告警，用户得自己去发现 ——
   * 2026-09-23 ZTE样本主号事件即如此（且因日志当时不落盘，事后无从复盘）。
   * 本方法把这一转移变成高亮日志 + 推送通知，并附上关机当刻的保活上下文供排查。
   */
  detectKeepAliveFailure(vms, accName) {
    if (!this._vmPrevOffState) this._vmPrevOffState = new Map();
    const prev = this._vmPrevOffState;
    const name = accName || this.account.name || this.account.user;
    for (const vm of (Array.isArray(vms) ? vms : [])) {
      const key = String(vm.userServiceId);
      const wasOff = prev.get(key); // boolean | undefined（首次观测不告警，避免启动误报）
      const isOff = isYdpcVmOff(vm);
      // 只有"确实应该正在被保活"的机器才值得告警：保活关闭 / 时长耗尽的本就该是关机状态
      const expectedRunning = vm.keepaliveEnabled !== false && !this.isVmLimitedExpired(vm);

      if (wasOff === false && isOff && expectedRunning) {
        const dpActive = this.isDataPlaneActive(vm.userServiceId);
        const lastKaMs = vm.lastKeepAliveAt || 0;
        const minsAgo = lastKaMs > 0 ? Math.max(0, Math.round((Date.now() - lastKaMs) / 60000)) : null;
        const ctx = [
          `数据面保活=${dpActive ? '活跃' : '未激活'}`,
          `控制面=${this.account.features?.controlPlaneKeepalive !== false ? '开' : '关'}`,
          `MQTT=${this.account.features?.mqttKeepAlive !== false ? '开' : '关'}`,
          minsAgo === null ? '无保活记录' : `上次保活 ${minsAgo} 分钟前`
        ].join('，');
        this.appendLog(
          'KeepAlive',
          `[${name}][${vm.vmName || vm.userServiceId}] 🚨 保活失效告警：机器由「运行中」变为「已关机」（${ctx}）。` +
          `注意：数据面 hb_recv>0 只代表管道通，不代表机器不会被关机；请查看心跳保活日志中关机前约 15 分钟的切片/重拨记录。`,
          'error', name, 'ydpc'
        );
        if (this.account.stats) this.account.stats.lastKeepAliveFailureAt = getBeijingTimeString();
        this._recordVmAction(vm.userServiceId, '🚨 检测到保活失效（运行中→已关机）', 'error');
        try {
          this.sendNotification(
            this.account,
            `🚨 保活失效：${name} / ${vm.vmName || vm.userServiceId}`,
            `移动爱家已从「运行中」变为「已关机」。\n${ctx}\n\n` +
            `提示：数据面保活的 hb_recv>0 只能证明隧道通，不能证明保活有效。` +
            `请到控制台「📡 心跳保活」日志查看关机前约 15 分钟的记录（切片结束 / 重拨是否中断）。`,
            { event: 'ydpc_keepalive_failed', accountName: name, vmName: vm.vmName || '' }
          );
        } catch (e) { /* 通知失败不得影响保活主流程 */ }
      }
      prev.set(key, isOff);
    }
  }

  /**
   * 判断该机器是否「时长耗尽」（20 小时/月包限时套餐用尽）。
   * 时长耗尽时，网关拒绝下发 connectStr（cs_startDesktop 返回"当前计费周期时长已用完"），
   * 因此数据面保活**无法建立**——这类机器应改走控制面保活（SOHO 心跳 + CAG 握手）。
   * 供数据面调度与主循环复用，避免两处各写一份判定。
   */
  isVmLimitedExpired(vm) {
    if (!vm) return false;
    const isPermanent = vm.durationMode === 'permanent' || String(vm.remainText || '').includes('永久');
    if (isPermanent) return false;
    const remain0 = vm.remainHours <= 0 ||
      (typeof vm.remainDurationTime === 'number' && vm.remainDurationTime <= 0) ||
      String(vm.remainText || '').includes('0小时') ||
      String(vm.remainText || '').includes('已耗尽') ||
      String(vm.remainText || '').includes('用完');
    if (vm._durationExhausted || (vm.durationMode === 'limited' && remain0)) return true;
    // 名称兜底：skuName/vmName 含"20小时"且剩余为 0
    const name20h = (String(vm.skuName || '').includes('20小时') || String(vm.vmName || '').includes('20小时'));
    if (name20h && remain0) return true;
    return false;
  }

  stopDataPlaneTask(usid, accName) {
    const name = accName || this.account.name || this.account.user;
    const task = this.dataPlaneTasks.get(usid);
    if (!task) return;
    task.stopFlag = true;
    task.running = false;
    try { if (task.socket) task.socket.destroy(); } catch (e) { /* 已关闭 */ }
    this.dataPlaneTasks.delete(usid);
    this.appendLog('CAGRAW', `[${name}] 数据面保活已停止 (userServiceId: ${usid})`, 'info', name, 'ydpc');
    this._recordVmAction(usid, '数据面保活已停止', 'off');
  }

  startDataPlaneTask(vm, usid, accName) {
    const name = accName || this.account.name || this.account.user;
    const task = {
      running: true, stopFlag: false, socket: null,
      // 假活跃防线：failStreak 到阈值 ⇒ isDataPlaneActive 判否 ⇒ 控制面立刻接管
      failStreak: 0, lastProgressAt: 0, demoted: false,
      // 底座标签：降级留证的措辞要按底座分叉（SCG 无 CAG 握手，笼统写"CAG 握手"是失真）
      routeKind: (vm && vm._route && vm._route.kind) || ''
    };
    this.dataPlaneTasks.set(usid, task);

    const { dialCagTcpRaw, keepaliveRawZtecLoop } = require('./zte_cag_raw');
    const { cagBootVm, zteDecodeConnectStr, parseConnectCommand } = require('./cag_boot');

    // 15 分钟切片：每轮 hold 后重拨。官方客户端 ~30min 无真实隧道活动会关机，
    // 纯 HB 也会 BrokenPipe；connectStr 有 TTL，重拨前须刷新。
    // （可经 vm._dataPlaneHoldSeconds 覆盖，仅用于测试/排障）
    const HOLD_SLICE_S = Number(vm._dataPlaneHoldSeconds) || 900;

    const loop = async () => {
      while (task.running && !task.stopFlag) {
        try {
          if (!this.sohoClient.sohoToken) await this.login();
          const firmAuth = await this.sohoClient.getFirmAuth(usid);

          // ══════════════════════════════════════════════════════════════════
          // 【SCG 分支】深信服底座走**另一套**数据面（app/ydpc/scg_keepalive.js）：
          //   材料 = firm-auth 的 scAuthCode（OAuth ext-grant 令牌）+ vmId + bizCode
          //   流程 = CEM 控制面（OAuth 换 token → getConnectInfo 建会话 → 就绪轮询）
          //          → 裸 TCP → auth 包 → 同 socket 升 TLS → trunk 帧 + SPICE 通道认证
          // 【2026-09-26 根因修复】firm-auth 的 scgIp/scgTcpPort 只是入口记录，数据面
          //   拨号必须用 CEM getConnectInfo 返回的会话绑定材料 —— 否则边缘对任何输入
          //   静默丢包（历史症状「SCG auth 无应答」的机制性根因）。
          // 必须**在** cagBootVm 之前分流 —— 否则会拿 SCG 材料去撞 CAG 开机路径，
          // 历史症状就是每 30s 报一次「该机器未暴露 CAG 连接材料（cagIp 缺失），无法开机」。
          // ══════════════════════════════════════════════════════════════════
          if (vm._route && vm._route.kind === 'SCG') {
            task.path = 'scg';
            // 【2026-09-27 修订】必填判据收敛为 scAuthCode + vmId：firm-auth 的
            //   scgIp/scgTcpPort 是间歇性的（会话失效时网关不下发），而 CEM 流程
            //   自带拨号地址 —— 旧判据把它们当必填，导致数据面循环每 60s 误报一次。
            const presence = describeScgMaterialPresence(firmAuth);
            if (!presence.scAuthCode || !presence.vmId) {
              throw new Error(
                `SCG 材料未下发（scAuthCode=${presence.scAuthCode} vmId=${presence.vmId}）` +
                ' —— 通常表示该机未就绪或材料尚未下发'
              );
            }
            const session = await runScgSession({
              firmAuth,
              holdSeconds: HOLD_SLICE_S,
              timeoutMs: 10000,
              onLog: (label, message, level) => this.appendLog(label, `[${name}] ${message}`, level, name, 'ydpc'),
              // 慢平面（~25s）：官方客户端在 SCG 上也打 SOHO 心跳，沿用控制面同一函数
              onSlowPlane: () => this.sendHeartbeat(usid),
              shouldStop: () => task.stopFlag || !task.running
            });
            // 措辞红线：**只有**观察到真实显示数据才用 success/ok；否则一律 warning/warn，
            // 并且任何情况下都不说"保活成功"（keepaliveProven 恒 false）。
            this.appendLog(
              'SCG',
              `[${name}] SCG 切片结束：会话 ${session.sessionId}，通道 [${session.channels.join(',') || '无'}]，` +
              `display=${session.displayProven ? '已观察到显示数据' : '未观察到显示数据'}，` +
              `帧 ${session.stats.frames} / 应答 ${session.stats.responses}，重拨中`,
              session.displayProven ? 'success' : 'warning', name, 'ydpc'
            );
            this._recordVmAction(
              usid,
              session.displayProven
                ? '📡 SCG 切片完成（已观察到显示数据），重拨中'
                : '📡 SCG 切片完成（仅通道就绪，未见显示数据），重拨中',
              session.displayProven ? 'ok' : 'warn'
            );
            // 走到这里说明 SCG 会话**真的建起来过**（材料齐、TLS 通、通道认证完成）
            // ⇒ 这是进展，清零失败计数（否则一次早期抖动会让"降级"永久焊住）。
            // 注：displayProven 只影响措辞，不影响"隧道是否存在"这件事本身。
            this._noteDataPlaneProgress(task, usid, name);
            task.socket = null;
            continue;
          }

          // 1. 拿 connectStr（机器已运行，cs_startDesktop 立即返回）
          const boot = await cagBootVm(firmAuth, {
            onLog: (label, message, level) => this.appendLog(label, `[${name}] ${message}`, level, name, 'ydpc'),
            bootWait: 90,
            wireLog: false
          });
          if (!boot.success || !boot.connectStr) {
            throw new Error(boot.message || '未取得 connectStr');
          }

          // 2. 解密 → 地址族判定 → 拨号
          const decoded = zteDecodeConnectStr(String(boot.connectStr).trim());
          const p = parseConnectCommand(decoded);
          const innerHost = p.spiceHost;
          const innerPort = Number(p.kcpDestPort || p.spicePort);
          const vmId = p.vmId || firmAuth.vmId;

          // 【G5 地址族路由】必须在拨号**之前**判明这台机器走哪条数据面通道：
          //   内层主机含 ':'   ⇒ raw ZTEC（不升 TLS）
          //   内层主机点分四段 ⇒ TLS + CAGMux + raw SPICE
          // 旧代码一律走 raw：IPv4 内层主机于是被 ipv6ToBytes 在 `sock.on('data')`
          // 回调里抛错 —— 既成为未捕获异常，又让 Promise 挂到 15s 超时，
          // **绕过了 G2 失败分级**（既非 tokenRetry 也非 soft/hard，而是无人接管）。
          // 现在这条路会被明确拒绝，理由可读、可分级、可留证。
          const innerRoute = resolveInnerRoute(innerHost);
          if (innerRoute.path === 'reject') {
            throw new Error(`内层主机无法路由：${innerRoute.reason}`);
          }
          task.path = innerRoute.path;
          this.appendLog(
            'CAGRAW',
            `[${name}] 地址族判定：${innerRoute.path === 'tls' ? 'IPv4 / TLS+CAGMux+SPICE' : 'IPv6 / raw ZTEC'}（${innerRoute.reason}）`,
            'info', name, 'ydpc'
          );

          if (innerRoute.path === 'tls') {
            // ── IPv4 分支：官方"经典"数据面 —— 也是唯一会建立 Display Surface 的通道 ──
            const session = await runTlsSpiceSession({
              outerHost: String(firmAuth.cagIp),
              outerPort: Number(firmAuth.cagPort),
              innerHost,
              innerPort,
              proxySport: Number(p.spicePort),
              vmId,
              key: p.sessionKey,
              traceId: p.traceId,
              timeoutMs: 15000,
              holdSeconds: HOLD_SLICE_S,
              onLog: (label, message, level) => this.appendLog(label, `[${name}] ${message}`, level, name, 'ydpc'),
              onEstablished: (info) => {
                this.appendLog(
                  'CAGTLS',
                  `[${name}] ✅ 数据面会话已建立 (conv=${info.conv} spice=${info.spiceSessionId} ` +
                  `子通道 ${info.authedSubLinks}/${info.subLinks}，display ${info.displaySubLinks} 条` +
                  `${info.tlsDowngraded ? '，TLS 已按受控降级建立' : ''})，` +
                  `hold ${Math.round(HOLD_SLICE_S / 60)} 分钟`,
                  'success', name, 'ydpc'
                );
                // 隧道**当场**建成 ⇒ 立刻清零失败计数。不能等 15 分钟切片结束再清：
                // 否则一次早期瞬时抖动会把"已交还控制面"的降级状态焊住整整一个切片。
                this._noteDataPlaneProgress(task, usid, name);
              },
              shouldStop: () => task.stopFlag || !task.running
            });
            // 措辞与 raw 分支同一口径：只说"切片完成 / 重拨"，**绝不说"保活成功"** ——
            // 会话建立不等于保活被证明（见 keepaliveProven 恒 false 的诚实性口径）。
            this._recordVmAction(
              usid,
              `📡 数据面切片完成 (TLS+SPICE)，重拨中 (消息 ${session.messages} / 心跳 ${session.heartbeats})`,
              session.errors > 0 ? 'warn' : 'ok'
            );
            task.socket = null;
            continue;
          }

          // ── IPv6 分支：raw ZTEC（既有实现，不升 TLS）──
          const dial = await dialCagTcpRaw({
            host: String(firmAuth.cagIp),
            port: Number(firmAuth.cagPort),
            innerHost,
            innerPort,
            proxySport: Number(p.spicePort),
            vmId,
            timeoutMs: 15000,
            onLog: (label, message, level) => this.appendLog(label, `[${name}] ${message}`, level, name, 'ydpc')
          });
          task.socket = dial.socket;

          this.appendLog('CAGRAW', `[${name}] ✅ 数据面保活隧道已建立 (conv=${dial.conv})，hold ${Math.round(HOLD_SLICE_S / 60)} 分钟`, 'success', name, 'ydpc');
          // 拨号成功即"隧道真的存在" ⇒ 立刻清零失败计数（同上：不能等切片结束才清）
          this._noteDataPlaneProgress(task, usid, name);

          // 3. 预热 + HB 心跳 hold（阻塞直到切片结束或连接断开）
          const counters = await keepaliveRawZtecLoop(dial.socket, {
            interval: 1.0,
            stopAfter: HOLD_SLICE_S,
            primeLinks: true,
            dataResend: 60,
            onLog: (label, message, level) => this.appendLog(label, `[${name}] ${message}`, level, name, 'ydpc')
          });

          if (counters.error) {
            this.appendLog('CAGRAW', `[${name}] 数据面切片结束（hb_sent=${counters.hbSent} hb_recv=${counters.hbRecv}）：${counters.error}`, 'info', name, 'ydpc');
          }
          // 按主机登记：hb_recv 只是"收到字节÷4"，不校验内容 → 措辞只说"切片完成/重拨"，
          // 不写成"保活成功"，避免把无法自证的管道通当成保活有效。
          this._recordVmAction(
            usid,
            `📡 数据面切片完成，重拨中 (hb 收/发 ${counters.hbRecv}/${counters.hbSent})`,
            counters.error ? 'warn' : 'ok'
          );

          // 4. 收尾，进入下一轮重拨
          try { dial.socket.destroy(); } catch (e) { /* 已关闭 */ }
          task.socket = null;
        } catch (err) {
          if (!task.running || task.stopFlag) break;
          const errMsg = String(err.message || '');
          // 【2026-09-23 关键修复】时长耗尽/到期是永久性错误：网关拒绝下发 connectStr，
          // 数据面保活**永远建立不起来**，30s 无限重试只会刷屏且毫无意义。
          // 正确做法：标记耗尽 + 停止本任务，等机器状态变化（下周期/重新有余额）
          // 或机器重启后，由 ensureDataPlaneKeepalive 重新调度。
          const exhausted = errMsg.includes('用完') || errMsg.includes('已用尽') ||
            errMsg.includes('计费周期') || errMsg.includes('到期') || errMsg.includes('欠费');
          if (exhausted) {
            vm._durationExhausted = true;
            vm.durationMode = 'limited';
            vm.remainText = '⏱️ 0小时';
            vm.remainHours = 0;
            this.metrics.remainText = '⏱️ 0小时';
            this.appendLog('CAGRAW', `[${name}] 当前计费周期时长已耗尽，数据面保活无法建立（网关拒绝下发连接材料），已停止；改由控制面保活接管（若机器仍在运行）`, 'warning', name, 'ydpc');
            this._recordVmAction(usid, '时长已耗尽 · 数据面无法建立，改走控制面', 'warn');
            break;
          }
          // SCG 材料未下发属于"机器未就绪"这一类**软失败**，不是链路故障：
          // 退避久一点、措辞写清"材料没下来"，不要伪装成网络抖动。
          if (errMsg.includes('SCG 材料未下发') || err.code === 'SCG_MATERIAL_MISSING') {
            this._noteDataPlaneFailure(task, usid, name, errMsg);
            this.appendLog('SCG', `[${name}] ${errMsg} —— 60s 后重试`, 'warning', name, 'ydpc');
            this._recordVmAction(usid, '⏸ SCG 材料未下发（机器可能未运行）· 等待重试', 'warn');
            try { if (task.socket) task.socket.destroy(); } catch (e) { /* 已关闭 */ }
            task.socket = null;
            await new Promise((r) => setTimeout(r, 60000));
            continue;
          }
          // 非耗尽类错误（网络抖动 / 拨号失败等）→ 短暂退避后重试
          this._noteDataPlaneFailure(task, usid, name, errMsg);
          this.appendLog('CAGRAW', `[${name}] 数据面保活异常，30s 后重试：${errMsg}`, 'warning', name, 'ydpc');
          try { if (task.socket) task.socket.destroy(); } catch (e) { /* 已关闭 */ }
          task.socket = null;
          await new Promise((r) => setTimeout(r, 30000));
        }
      }
      if (this.dataPlaneTasks.get(usid) === task) this.dataPlaneTasks.delete(usid);
    };

    this.appendLog('CAGRAW', `[${name}] 🚀 数据面保活已启动 (userServiceId: ${usid})`, 'info', name, 'ydpc');
    this._recordVmAction(usid, '📡 数据面隧道建立中', 'idle');
    loop().catch(() => {});
  }

  /**
   * ==========================================================================
   * 独立状态验证器（旁路核验：独立轮询电源状态，不复用保活动作的自述结论）
   * ==========================================================================
   * 目的：用**独立轮询**判断"保活是否真的有效"，而不是相信保活动作自己报的成功。
   *
   * 判定口径（三项同时满足才算通过）：
   *   1. 保活动作本身没有抛错；
   *   2. 监控持续满请求时长；
   *   3. 每一次电源状态快照都显示机器在运行（不曾出现关机）。
   *
   * 这是"用独立证据判定结果"的落地，与项目已有的
   * diagnoseHangInterruption() 非对称决策原则一脉相承：
   * 不采信自我宣称，只采信外部可观测事实。
   *
   * @param {number} durationSec  监控总时长（秒）
   * @param {number} intervalSec  快照间隔（秒）
   * @returns {Promise<object>} 验证报告
   */
  async verifyKeepAliveEffect(durationSec = 60, intervalSec = 15) {
    const accName = this.account.name || this.account.user;
    const started = Date.now();
    const report = {
      ok: false,
      userServiceIds: [],
      requestedDurationSeconds: durationSec,
      intervalSeconds: intervalSec,
      durationSeconds: 0,
      snapshots: [],
      errors: [],
      poweredThroughout: false,
      firstOffAt: null,
      firstOffSeconds: null,
      stoppedEarly: false,
      stopReason: ''
    };

    this.appendLog('CAG', `[${accName}] 启动独立状态验证：持续 ${durationSec}s，每 ${intervalSec}s 采样一次电源状态`, 'info', accName, 'ydpc');

    let count = 0;
    while (Date.now() - started < durationSec * 1000) {
      count++;
      const elapsed = Math.round((Date.now() - started) / 1000);
      try {
        const vms = await this.sohoClient.listCloudPcs();
        // 【2026-09-23】只对"预期应在运行"的机器判定：保活关闭 / 时长耗尽的机器本就该是关机，
        // 把它们算作失败会造成**永久误报**（ZTE样本主号 VM2 正是这种情况，会导致核验永远红灯）。
        const expectedIds = new Set(
          (this.account.vms || [])
            .filter(v => v.keepaliveEnabled !== false && !this.isVmLimitedExpired(v))
            .map(v => String(v.userServiceId))
        );
        const scope = expectedIds.size > 0
          ? vms.filter(v => expectedIds.has(String(v.userServiceId)))
          : [];
        const running = scope.filter(v => !isYdpcVmOff(v));
        const off = scope.filter(v => isYdpcVmOff(v));

        report.userServiceIds = scope.map(v => String(v.userServiceId));
        const snap = {
          index: count,
          elapsedSeconds: elapsed,
          total: scope.length,
          running: running.length,
          off: off.length,
          statusText: scope.map(v => `${v.vmName || v.userServiceId}=${v.vmStatus || '未知'}`).join(', ')
        };
        report.snapshots.push(snap);
        this.appendLog('CAG', `[${accName}] [${count}] 独立验证：运行 ${running.length}/${scope.length}，关机 ${off.length}，已持续 ${elapsed}s`, 'info', accName, 'ydpc');

        if (off.length > 0) {
          report.stoppedEarly = true;
          report.stopReason = 'power_state_not_running';
          report.firstOffAt = new Date().toISOString();
          report.firstOffSeconds = elapsed;
          if (report.firstOffSeconds !== null) {
            this.appendLog('CAG', `[${accName}] ⚠️ 独立验证发现机器不在运行（第 ${elapsed}s），保活未生效`, 'warning', accName, 'ydpc');
          }
          break;
        }
      } catch (err) {
        report.errors.push({ index: count, elapsedSeconds: elapsed, error: err.message });
        this.appendLog('CAG', `[${accName}] 独立验证采样失败：${err.message}`, 'warning', accName, 'ydpc');
      }

      if (Date.now() - started >= durationSec * 1000) break;
      const nextAt = count * intervalSec * 1000;
      const sleepMs = Math.max(1000, nextAt - (Date.now() - started));
      await new Promise(r => setTimeout(r, sleepMs));
    }

    report.durationSeconds = Math.round((Date.now() - started) / 1000);
    const lastSnap = report.snapshots[report.snapshots.length - 1];
    report.poweredThroughout = !!(
      report.snapshots.length > 0 &&
      !report.stoppedEarly &&
      lastSnap && lastSnap.total > 0 && lastSnap.off === 0 &&
      report.durationSeconds >= durationSec - 1
    );
    report.ok = report.poweredThroughout && report.errors.length === 0;

    this.appendLog(
      'CAG',
      `[${accName}] ${originCn}结束：${report.ok ? '✅ 通过' : '❌ 未通过'}（持续 ${report.durationSeconds}s，采样 ${report.snapshots.length} 次，错误 ${report.errors.length} 次${report.firstOffSeconds !== null ? `，首次离线于 ${report.firstOffSeconds}s` : ''}）`,
      report.ok ? 'success' : 'warning',
      accName,
      'ydpc'
    );

    return report;
  }

  /**
   * ==========================================================================
   * 保活效果自动核验看门狗
   * ==========================================================================
   * 每隔 intervalMs 用 verifyKeepAliveEffect 做一次**独立**核验（不采信保活动作的自证）。
   * 只在"确实有机器应当运行中、且它们当前都在运行"时才跑 —— 已经关机的机器再核验毫无意义
   * （那属于已告警的失效态，由 detectKeepAliveFailure 负责）。
   *
   * 与主循环解耦：独立定时器 + 全 async，不阻塞 20s 巡检节拍，也不会并发叠加。
   */
  startEffectWatchdog(intervalMs = EFFECT_VERIFY_INTERVAL_MS, firstDelayMs = EFFECT_VERIFY_FIRST_DELAY_MS, sampleSec = EFFECT_VERIFY_SAMPLE_SEC) {
    if (this._effectWatchTimer) return;
    const accName = this.account.name || this.account.user;
    const interval = Math.max(60 * 1000, parseInt(intervalMs, 10) || EFFECT_VERIFY_INTERVAL_MS);
    const run = async () => {
      if (!this.workerRunning) return;
      try {
        const allChannelsOff = this.account.features?.controlPlaneKeepalive === false &&
                               this.account.features?.mqttKeepAlive === false &&
                               this.account.features?.dataPlaneKeepalive === false;
        const accountOn = this.account.features?.keepAlive !== false && !allChannelsOff;
        if (accountOn && !this._effectVerifyRunning) {
          const expected = (this.account.vms || [])
            .filter(v => v.keepaliveEnabled !== false && !this.isVmLimitedExpired(v));
          const allRunning = expected.length > 0 && expected.every(v => !isYdpcVmOff(v));
          if (allRunning) {
            this._effectVerifyRunning = true;
            let report = null;
            try {
              report = await this.verifyKeepAliveEffect(sampleSec, Math.max(10, Math.round(sampleSec / 3)), { origin: 'auto' });
            } finally {
              this._effectVerifyRunning = false;
            }
            if (report && !report.ok) {
              this.appendLog('KeepAlive', `[${accName}] ❌ 保活效果自动核验未通过（${report.stopReason || '采样异常'}）—— 保活可能未真正生效，已推送告警。`, 'error', accName, 'ydpc');
              try {
                this.sendNotification(
                  this.account,
                  `❌ 保活效果核验未通过：${accName}`,
                  `独立核验发现机器在采样期间出现关机（${report.stopReason || '采样异常'}）。` +
                  `${report.firstOffSeconds !== null ? `首次离线于 ${report.firstOffSeconds}s。` : ''}\n保活可能未真正生效，请检查数据面切片 / 重拨记录。`,
                  { event: 'ydpc_keepalive_verify_failed', accountName: accName }
                );
              } catch (e) { /* 通知失败不阻断 */ }
            }
          }
        }
      } catch (e) {
        this._effectVerifyRunning = false;
      }
      if (this.workerRunning) this._effectWatchTimer = setTimeout(run, interval);
    };
    this._effectWatchTimer = setTimeout(run, Math.max(1000, parseInt(firstDelayMs, 10) || EFFECT_VERIFY_FIRST_DELAY_MS));
  }

  startKeepAliveWorker() {
    if (this.workerRunning) return;
    const accName = this.account.name || this.account.user;

    // 【2026-09-23 事故修复】整个启动流程必须"要么完整成功、要么完整回滚"。
    // 原先 `workerRunning = true` 之后任何一步抛错（例如附加看门狗抛 ReferenceError），
    // 都会留下一个"标记为已启动、但循环从未被排程"的僵尸状态，且被守卫永久锁死。
    try {
      this.workerRunning = true;

      const defaultIntervalSec = Math.max(60, parseInt(this.account.keepaliveInterval) || 600);
      this.appendLog('CAG', `[${accName}] 移动爱家多机独立时间戳看门狗已启动 (基准周期: ${Math.round(defaultIntervalSec / 60)} 分钟)...`, 'info', accName, 'ydpc');

      // 【2026-09-23】保活"有效性"自动核验：每 30 分钟用独立轮询电源状态判定一次，
      // 不采信保活动作自己报的成功（hb_recv>0 只证明管道通）。发现失效即告警。
      // ⚠️ 这是**附加能力**：它坏掉绝不允许拖垮主保活循环——2026-09-23 的静默停摆就由此而来。
      try {
        this.startEffectWatchdog();
      } catch (e) {
        this.appendLog('CAG', `[${accName}] ⚠️ 保活效果核验看门狗启动失败（不影响保活主流程，已跳过）: ${e.message}`, 'warning', accName, 'ydpc');
      }

      // 守护看门狗以 20 秒为基准时间片高精度巡检各单机
      const TICK_INTERVAL_MS = 20000;

    const runCycle = async () => {
      if (!this.workerRunning) return;
      try {
        // 【2026-09-23 数据面】数据面保活是独立的第四条通道：
        // 即使三条控制面通道全关，只要数据面开关开着，就不算"全部关闭"。
        // （SOHO 心跳与 CAG 握手已合并为一个"控制面保活"开关 controlPlaneKeepalive）
        const isAllChannelsOff = this.account.features?.controlPlaneKeepalive === false &&
                                 this.account.features?.mqttKeepAlive === false &&
                                 this.account.features?.dataPlaneKeepalive === false;
        if (this.account.features?.keepAlive === false || isAllChannelsOff) {
          // 账号级保活总开关关闭（或通道全关）→ 停掉所有数据面任务
          for (const usid of Array.from(this.dataPlaneTasks.keys())) {
            this.stopDataPlaneTask(usid, accName);
          }
          this.metrics.status = 'offline';
          this.metrics.lastHeartbeatResult = '自动化保活通道已全部关闭 (待命中)';
          // 逐台登记，让"当前动作"在界面上按主机展示关闭原因（而不是停留在旧动作）
          for (const vm of (this.account.vms || [])) {
            this._recordVmAction(vm.userServiceId, '全局保活已关闭 · 本机未参与巡检', 'off');
          }
          if (this.workerRunning) {
            this.loopTimer = setTimeout(runCycle, TICK_INTERVAL_MS);
          }
          return;
        }

        // 定期静默刷新 VM 状态 (每 60 秒一次)
        if (!this._lastVmsRefreshAt || Date.now() - this._lastVmsRefreshAt > 60000) {
          await this.refreshVms().catch(() => {});
          this._lastVmsRefreshAt = Date.now();
        }

        const vms = this.account.vms || [];
        const anyRunning = vms.some(v => String(v.vmStatus || '').includes('运行') || v.vmStatusCode === 1);
        if (!anyRunning) {
          this.metrics.status = 'offline';
          if (this.account.stats) this.account.stats.keepAliveStatus = 'offline';
          this.metrics.lastHeartbeatResult = '云电脑处于已关机状态，自动守护待命中';
        }

        const now = Date.now();
        for (const vm of vms) {
          // ── 底座闸门（G1，最先判定：数据面任务本身就是一次拨号） ────────────
          // 【2026-09-23】此前 `vm.vendor` 只用于界面展示，**没有任何执行路径守它** ——
          // 一台底座为 SCG 的机器照样每轮被 ZTE 握手盲拨。这里把它变成真闸门：
          // 判定不受支持（UNKNOWN / 未登记底座）→ 本轮不拨任何通道，只留证后跳过该机。
          // 【2026-09-26】SCG 通道（app/ydpc/scg_keepalive.js）已落地，product_route 里
          // SCG 的 supported 随之翻为 true ⇒ 闸门对 SCG 放行，随后由 startDataPlaneTask 内的
          // SCG 分支走**另一套**数据面（trunk+SPICE），不再借用 CAG/connectStr。
          // 现有 ZTE 机器（spuCode=zte-cloud-pc）路径零影响。
          const gate = routeGate(vm._route || null);
          if (!gate.allow) {
            // 顺带停掉可能残留的数据面任务（它也是拨号，同样必须被闸门管住）
            this.stopDataPlaneTask(vm.userServiceId, accName);
            // 闸门拒绝**不是**"通道失败"，而是"按设计不拨号" ⇒ 清掉遗留失败等级，
            // 由 describeVmKeepAlive 的底座分支统一呈现（两套原因不许打架）。
            vm._lastFailureKind = 'none';
            vm._lastFailureText = '';
            const note = `⛔ 底座闸门拒绝保活 · ${gate.reason}`;
            if (vm._lastGateNote !== note) {
              // 去重：底座不变时只留一条证据，不每轮刷屏（同 _hasNotifiedOff 的既有约定）
              vm._lastGateNote = note;
              this.appendLog('CAG', `[${accName}][${vm.vmName}] ${note}`, 'warning', accName, 'ydpc');
            }
            this._recordVmAction(vm.userServiceId, note, 'warn');
            continue;
          }
          if (vm._lastGateNote) vm._lastGateNote = '';

          // 0. 数据面保活调度（幂等，必须在 continue 之前：即使单机保活关闭
          //    或时间戳未到，也要及时停止/保持数据面任务）。
          //    开关口径：账号级 features.dataPlaneKeepalive + 单机「⚡保活」+ 运行中。
          this.ensureDataPlaneKeepalive(vm, accName);
          const dataPlaneActive = this.isDataPlaneActive(vm.userServiceId);

          if (vm.keepaliveEnabled === false) {
            // 按主机维度登记"该机不参与巡检"，否则界面上这台机器会一直显示上一轮的旧动作
            this._recordVmAction(vm.userServiceId, '单机保活已关闭 · 不参与巡检', 'off');
            continue;
          }

          // 核心：单机独立时间戳差量调度 (Per-Device Interval Wheel)
          const vmIntervalSec = Math.max(60, parseInt(vm.keepaliveInterval) || defaultIntervalSec);
          const lastActive = vm.lastKeepAliveAt || 0;
          const elapsedSec = Math.floor((now - lastActive) / 1000);

          // 时间未到达该主机的专属周期，继续休眠跳过
          if (lastActive > 0 && elapsedSec < vmIntervalSec) {
            continue;
          }

          // 【2026-09-26 修复·判定不一致】此前这里就地重写了一份"是否关机"的判据，且漏掉了
          // 「未开机」文案与 vmStatusCode === 0 —— 而权威的 isYdpcVmOff()（本文件顶部）两者都算关机。
          // 后果（用户 2026-09-26 现场日志实证）：SCG 机「家庭云电脑畅享版」状态为「未开机」，
          // 权威判定=已关机（卡片也这么显示），这里却判成"运行中" ⇒ 继续对它打心跳与 CAG 握手。
          // 判据只允许存在一份：一律走 isYdpcVmOff(vm)。
          const isVmOff = isYdpcVmOff(vm);

          // 时长耗尽判定统一走 isVmLimitedExpired（与数据面调度共用同一份逻辑，避免漂移）
          const isLimitedExpired = this.isVmLimitedExpired(vm);

          // 1. 自动开机守护逻辑（2026-09-23 恢复，走 CAG/CEM 干净通道）
          // 【2026-09-28 用户拍板】武装判定统一走 _autoBootArmed（含 SCG 的账号默认开；
          // 纯 ZTE 账号保持默认关 —— ZTE 开机会真实消耗限时套餐时长，需显式开启）。
          // 时长耗尽的机器由 isLimitedExpired 熔断（网关本就拒绝，避免空转耗接口）。
          if (isVmOff && this._autoBootArmed(vm) && !isLimitedExpired) {
            const lastBootAt = vm._lastAutoBootAt || 0;
            // 冷却期：同一台机器 10 分钟内不重复尝试拉起，避免刷接口
            if (Date.now() - lastBootAt > 10 * 60 * 1000) {
              vm._lastAutoBootAt = Date.now();
              if (!vm._hasNotifiedBooting) {
                this.appendLog('CAG', `[${accName}][${vm.vmName}] 检测到关机，正在通过 CAG 通道自动拉起...`, 'info', accName, 'ydpc');
                vm._hasNotifiedBooting = true;
              }
              try {
                await this.bootVmViaCag(vm.userServiceId, accName);
                vm._hasNotifiedOff = false;
                vm._hasNotifiedBooting = false;
                this._recordVmAction(vm.userServiceId, '✅ CAG 自动开机指令已下发', 'ok');
              } catch (e) {
                this.appendLog('CAG', `[${accName}][${vm.vmName}] 自动开机失败: ${e.message}`, 'warning', accName, 'ydpc');
                this._recordVmAction(vm.userServiceId, `自动开机失败: ${e.message}`, 'error');
              }
            }
          } else if (isVmOff && !vm._hasNotifiedOff) {
            vm._hasNotifiedOff = true;
            // 【2026-09-28 修复】此处曾写 `!accAutoBootOn || !vmAutoBootOn` —— 两个局部量已随武装判定
            // 抽取为 _autoBootArmed 而删除，关机且未武装的机器一旦走到本分支就抛 ReferenceError，
            // 整账号本轮巡检被中断。原因必须从同一入口派生，不得再复制第二份开关判据。
            const why = this._autoBootArmed(vm) ? '当前套餐时长受限' : '未开启自动开机守护';
            this.appendLog('SOHO', `[${accName}][${vm.vmName}] 检测到机器已关机（${why}），本次不自动拉起。如需开机请在移动爱家官方 App 连接一次，或开启"自动开机守护"。`, 'info', accName, 'ydpc');
            this._recordVmAction(vm.userServiceId, `已关机 · ${why}，本次不自动拉起`, 'off');
          }

          const cpOn = this.account.features?.controlPlaneKeepalive !== false;
          // 本轮实际完成的动作（用于按主机维度展示"当前动作"，账号级文案无法区分多机）
          const doneParts = [];
          let cycleTone = 'ok';
          let cycleNote = '';

          // 单调升级：error > warn > ok。多步（心跳 / 握手）各报各的，最终取最严重的一档，
          // 但**文案只保留第一条**（后到的软失败不得把前面的硬失败说明覆盖掉）。
          const bump = (t, note) => {
            const rank = { ok: 0, warn: 1, error: 2 };
            if ((rank[t] || 0) > (rank[cycleTone] || 0)) cycleTone = t;
            if (note && !cycleNote) cycleNote = note;
          };

          // ── G2 失败分级（软失败 / 硬失败 / 未执行 三分类） ──────────
          // tokenRetry : 会话 / token 失效 —— **可自愈**，重登一次再试；成功即视同本轮成功。
          // soft       : 已知非致命（维护 / 升级 / 时长耗尽 / 已关机 / 限流）—— 只告警，不熔断。
          // hard       : 兜底（含 TLS / DNS / 网络层与一切未知错误）—— 记异常，等下轮。
          // 返回 null 表示成功；否则返回 { kind, err, retried }。
          const runWithGrade = async (label, fn) => {
            // 【2026-09-26 修复·假成功】fn 有两种"失败"：① 抛异常；② **不抛异常但明确没做事**
            // （sendHeartbeat / pingCag 在机器已关机时返回 { success:false }）。
            // 旧逻辑只看"有没有抛" ⇒ 把 ② 记成成功 —— 用户 2026-09-26 现场日志里，一台
            // **已关机**的 SCG 机每 10 分钟被打出一条「ZTEC CAG TCP 握手保活成功」。
            // 现在：返回体 success === false 一律判 skipped（不记完成、也不当失败告警 ——
            // "这台机器本来就没开机"不是故障；内层已自行记「待命」）。
            const judge = (r) =>
              r && r.success === false
                ? { kind: 'soft', skipped: true, retried: false, err: new Error(r.message || `${label}未执行`) }
                : null;
            let res;
            try {
              res = await fn();
            } catch (e1) {
              const kind = classifyZteError(e1.message);
              if (kind !== 'tokenRetry') return { kind, err: e1, retried: false };
              let reloginOk = false;
              try {
                const relogin = await this.login();
                reloginOk = !(relogin && relogin.success === false);
              } catch (e) {
                reloginOk = false;
              }
              if (!reloginOk) return { kind, err: e1, retried: false };
              try {
                res = await fn();
              } catch (e2) {
                return { kind: classifyZteError(e2.message), err: e2, retried: true };
              }
              const skip2 = judge(res);
              if (skip2) return skip2;
              this.appendLog('SOHO', `[${accName}][${vm.vmName}] ${label} 命中会话失效，重登后重试成功`, 'info', accName, 'ydpc');
              return null;
            }
            return judge(res);
          };

          // 每轮开始先清空"上一轮的失败等级"。失败状态必须是**本轮的事实**，不是"曾经发生过"——
          // 否则一次瞬时故障会永久挂在卡片上，把"如实"变成恒常误报（与"假成功"同样是失真）。
          vm._lastFailureKind = 'none';
          vm._lastFailureText = '';

          // 2. 发送 SOHO 心跳与埋点
          // 【2026-09-23 用户要求】保活只看"机器是否运行中"，不看时长是否耗尽。
          // 时长耗尽只阻止"开机/拉起"，不阻止"对一台已在运行机器的保活"。
          // 【2026-09-23 数据面】数据面保活活跃时抑制 SOHO 心跳——实测确认 HTTP
          // 心跳不能真正保活，数据面在场时它只是冗余流量。
          // 【2026-09-23 合并】SOHO 心跳与 CAG 握手共用一个"控制面保活"开关。
          if (cpOn && !isVmOff && !dataPlaneActive) {
            const hbFail = await runWithGrade('SOHO 心跳', () => this.sendHeartbeat(vm.userServiceId));
            if (!hbFail) {
              doneParts.push('SOHO 心跳');
            } else if (!hbFail.skipped) {
              // skipped（机器不在运行状态 ⇒ 内层返回 success:false 而未抛）= 既不算完成也不算失败，
              // 内层已自行记「已关机 · 心跳待命」；只有真失败才走下面的分级告警。
              vm._lastFailureKind = hbFail.kind;
              vm._lastFailureText = hbFail.err.message || '';
              if (hbFail.kind === 'soft') {
                bump('warn', `SOHO 心跳暂不可用(软失败,不熔断): ${hbFail.err.message}`);
              } else {
                bump('error', `SOHO 心跳${hbFail.retried ? '重登后仍失效' : '异常'}: ${hbFail.err.message}`);
              }
            }
          }

          // 3. 执行 CAG TCP 握手保活
          // 【2026-09-23 数据面】同理：数据面在场时抑制 CAG 握手（避免干扰独占会话）。
          if (cpOn && !isVmOff && !dataPlaneActive) {
            const cagFail = await runWithGrade('CAG 握手', () => this.pingCag(vm.userServiceId, 3));
            if (!cagFail) {
              doneParts.push('CAG 握手');
              this.appendLog('CAG', `[${accName}][${vm.vmName}] ZTEC CAG TCP 握手保活成功 (周期: ${Math.round(vmIntervalSec / 60)} 分钟)`, 'success', accName, 'ydpc');
            } else if (!cagFail.skipped) {
              // skipped = "这台机器没在运行状态，握手压根没执行" ⇒ 绝不打成功日志
              // （这正是用户 2026-09-26 看到「关机的 SCG 机每 10 分钟握手保活成功」的来源）。
              const errMsg = cagFail.err.message || '';
              if (errMsg.includes('用完') || errMsg.includes('已用尽') || errMsg.includes('计费周期') || errMsg.includes('到期')) {
                vm._durationExhausted = true;
                vm.durationMode = 'limited';
                vm.remainText = '⏱️ 0小时';
                vm.remainHours = 0;
                this.metrics.remainText = '⏱️ 0小时';
                vm._lastFailureKind = 'soft';
                vm._lastFailureText = '当前计费周期时长已用完';
                bump('warn', '当前计费周期时长已用完 (仅自动开机受限)');
                if (!vm._hasWarnedExhausted) {
                  // 【2026-09-23 用户要求】时长耗尽只熔断"自动开机"，不熔断"对运行中机器的保活"。
                  // 此处 CAG 握手报"用完"通常是机器已关机时的信号；若机器仍在运行，
                  // 保活循环会照常继续（见上方 !isVmOff 闸门），不再整体静默。
                  this.appendLog('CAG', `[${accName}][${vm.vmName}] 当前计费周期时长已用完，自动开机守护已熔断（若机器已在运行，保活照常继续）`, 'info', accName, 'ydpc');
                  vm._hasWarnedExhausted = true;
                }
              } else if (cagFail.kind === 'soft') {
                // 维护窗口 / 升级 / 限流一类的**已知非致命**：只告警，绝不当成链路熔断。
                // （实测结论：把这类当硬失败会造成"一维护就整轮熔断"的假故障。）
                vm._lastFailureKind = 'soft';
                vm._lastFailureText = errMsg;
                this.appendLog('CAG', `[${accName}][${vm.vmName}] CAG 握手软失败(不熔断): ${errMsg}`, 'warning', accName, 'ydpc');
                bump('warn', `CAG 握手暂不可用(软失败,不熔断): ${errMsg}`);
              } else {
                vm._lastFailureKind = cagFail.kind;
                vm._lastFailureText = errMsg;
                this.appendLog('CAG', `[${accName}][${vm.vmName}] CAG 握手${cagFail.retried ? '重登后仍失效' : '异常'}: ${errMsg}`, 'warning', accName, 'ydpc');
                bump('error', `CAG 握手异常: ${errMsg}`);
              }
            }
          }

          // 数据面保活的启停已在循环开头（步骤 0）处理，此处不重复。

          // 记录单机专属活跃时间戳并同步状态
          // 【2026-09-23 修订】只有"运行中"的机器才推进该时间戳：原先关机机也会被
          // 每轮刷新成"刚刚保活过"，既掩盖了真实的最后一次保活时刻，又会让机器重新
          // 开机后的首次保活被额外推迟一整个周期。
          if (!isVmOff) {
            vm.lastKeepAliveAt = now;
            // 【2026-09-24】机器处于运行中 → 复位"已关机提示"去重标记。
            // 语义从"一辈子只提示一次"改成"每次关机状态变化提示一次"：
            // 本次开机后再关机，仍会如实提示；同一次关机期间则不再重复刷屏。
            vm._hasNotifiedOff = false;
            this.metrics.lastHeartbeatTime = getBeijingTimeString().slice(11);
            if (this.account.stats) this.account.stats.lastKeepAliveTime = getBeijingTimeString();
          }

          // 按主机维度登记本轮结果（供界面"当前动作"逐台展示）
          if (cycleNote) {
            this._recordVmAction(vm.userServiceId, cycleNote, cycleTone);
          } else if (doneParts.length > 0) {
            this._recordVmAction(vm.userServiceId, `✅ 保活巡检完成 · ${doneParts.join(' + ')}`, 'ok');
          } else if (dataPlaneActive) {
            this._recordVmAction(vm.userServiceId, '数据面保活进行中 (raw ZTEC 隧道保持)', 'ok');
          } else if (isVmOff) {
            this._recordVmAction(vm.userServiceId, '已关机 · 未参与本轮巡检', 'off');
          } else if (!cpOn) {
            this._recordVmAction(vm.userServiceId, '控制面保活已关闭 · 本轮未发心跳/握手', 'off');
          }
        }

        // 账号级摘要：明确写出多机各自的归属（取代原先"运行中时永不刷新"的初始文案）
        this.metrics.lastHeartbeatResult = this.buildYdpcSummaryText();

        // 保持官方 MQTT 3.1.1 over TLS 链路
        if (this.account.features?.mqttKeepAlive !== false) {
          await this.ensureMqttConnection().catch(() => {});
        }

      } catch (err) {
        this.metrics.status = 'offline';
        this.metrics.lastHeartbeatResult = `异常: ${err.message}`;
        this.appendLog('CAG', `[${accName}] 移动爱家保活巡检异常: ${err.message}`, 'error', accName, 'ydpc');
      }

      if (this.workerRunning) {
        this.loopTimer = setTimeout(runCycle, TICK_INTERVAL_MS);
      }
    };

      // 延迟 2 秒立即执行首次（存入 loopTimer 以便 stopKeepAliveWorker 能取消，
      // 也与后续每轮排程共用同一个可清理句柄）
      this.loopTimer = setTimeout(runCycle, 2000);
    } catch (err) {
      // 启动失败必须复位 workerRunning，否则 `if (this.workerRunning) return;` 守卫会让这个
      // 账号永远无法再次启动保活（2026-09-23 实测：静默停摆、且每 5 秒的 /api/accounts 轮询
      // 也无法自愈，因为守卫直接 return）。复位后下一轮轮询即可自动重试。
      this.workerRunning = false;
      if (this.loopTimer) { clearTimeout(this.loopTimer); this.loopTimer = null; }
      this.appendLog(
        'CAG',
        `[${accName}] ❌ 移动爱家保活看门狗启动失败，已复位为"未启动"以便下轮自动重试: ${err.message}`,
        'error', accName, 'ydpc'
      );
    }
  }

  stopKeepAliveWorker() {
    this.workerRunning = false;
    if (this.loopTimer) {
      clearTimeout(this.loopTimer);
      this.loopTimer = null;
    }
    // 停掉保活效果自动核验看门狗（避免停保活后仍在打接口）
    if (this._effectWatchTimer) {
      clearTimeout(this._effectWatchTimer);
      this._effectWatchTimer = null;
    }
    // 停掉所有数据面保活后台任务
    for (const usid of Array.from(this.dataPlaneTasks.keys())) {
      this.stopDataPlaneTask(usid);
    }
    if (this.mqttClient) {
      this.mqttClient.disconnect();
      this.mqttClient = null;
    }
    this.metrics.status = 'offline';
    if (this.account.stats) this.account.stats.keepAliveStatus = 'offline';
  }
}

module.exports = { YdpcClient };
