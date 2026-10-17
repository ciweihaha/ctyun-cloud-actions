'use strict';

/**
 * ============================================================================
 * 日志落盘器（按日期滚动 + 启动回灌）
 * ============================================================================
 *
 * 【为什么需要它】
 * 本项目的运行日志原本**只存在内存数组**里（server.js 的 `const logs = []`），服务一重启
 * 历史即丢。后果在 2026-09-23 的"ZTE样本主号永久版云电脑自行关机"事件中完全暴露：
 * 事后要复盘"关机发生在几点、当时保活在不在跑"，**数据已经不存在**，只能靠推断。
 *
 * 【设计要点】
 *   1. 按北京日期分文件：`<dir>/dashboard-YYYY-MM-DD.jsonl`（JSONL，一行一条 JSON）。
 *   2. **落盘先于折叠**：写盘的是**原始条目**（含每一条 progress 心跳流水），
 *      内存里的"折叠成一条 + xN"只是 UI 展示优化，不应损失取证信息。
 *   3. **同步追加**（appendFileSync）而非异步流：本项目日志量很低（每秒不到 1 条，
 *      仅数据面 progress 与心跳日志），同步写代价可忽略；换来的是
 *      ① 顺序确定 ② **进程崩溃/被 kill 时最后几行不丢** —— 而"最后几行"恰恰是
 *      故障取证最需要的（异步流缓冲区一旦没 flush，丢的就是它们）。
 *   4. 保留策略：默认保留 7 天，超期文件在初始化与跨天滚动时清理。
 *      可用环境变量 CTYUN_LOG_RETENTION_DAYS 覆盖（解析在 server.js 侧完成）。
 *   5. 启动回灌：从各文件**尾部**按需读取最近 N 行（不会把整文件载入内存），
 *      交回内存日志流，使重启后控制台不至于空白。
 *   6. 健壮性：任何磁盘异常（只读挂载、配额、权限）都**不得影响主流程** ——
 *      全部 try/catch 包裹，失败即降级为"仅内存日志"，只通过 onError 告警。
 *
 * 零依赖（只用 node 内建 fs/path），可直接被回归测试真实调用。
 */

const fs = require('fs');
const path = require('path');

const FILE_PREFIX = 'dashboard-';
const FILE_SUFFIX = '.jsonl';
const DEFAULT_RETENTION_DAYS = 7;
const DEFAULT_BOOT_LINES = 400;
/** 回灌时单个文件最多从尾部读取的字节数，防止超大文件拖慢启动 */
const TAIL_READ_MAX_BYTES = 2 * 1024 * 1024;

/** 北京时区的 YYYY-MM-DD（sv-SE 的日期格式恰好就是 ISO 形式） */
function beijingDateString(d = new Date()) {
  return d.toLocaleDateString('sv-SE', { timeZone: 'Asia/Shanghai' });
}

class LogPersister {
  constructor(opts = {}) {
    this.dir = opts.dir || path.join(process.cwd(), 'logs');
    this.retentionDays = Math.max(1, parseInt(opts.retentionDays, 10) || DEFAULT_RETENTION_DAYS);
    this.onError = typeof opts.onError === 'function' ? opts.onError : () => {};
    this.enabled = false;
    this.currentDate = null;
    this.written = 0;
  }

  /** 初始化：建目录、确定当日文件、清理超期文件。失败则降级为仅内存。 */
  init() {
    try {
      if (!fs.existsSync(this.dir)) fs.mkdirSync(this.dir, { recursive: true });
      this.enabled = true;
      this.currentDate = beijingDateString();
      this.prune();
    } catch (e) {
      this.enabled = false;
      this.onError(`日志落盘初始化失败（已降级为仅内存日志）: ${e.message}`);
    }
    return this.enabled;
  }

  /** 当日日志文件绝对路径 */
  currentFile(dateStr = beijingDateString()) {
    return path.join(this.dir, `${FILE_PREFIX}${dateStr}${FILE_SUFFIX}`);
  }

  /** 追加一条原始日志条目。跨天自动滚动文件并触发清理。 */
  append(entry) {
    if (!this.enabled || !entry) return false;
    try {
      const dateStr = beijingDateString();
      if (dateStr !== this.currentDate) {
        this.currentDate = dateStr;
        this.prune();
      }
      fs.appendFileSync(this.currentFile(dateStr), JSON.stringify(entry) + '\n', 'utf8');
      this.written++;
      return true;
    } catch (e) {
      this.enabled = false;
      this.onError(`日志落盘失败（已降级为仅内存日志）: ${e.message}`);
      return false;
    }
  }

  /** 清理超过保留天数的历史文件（按文件名中的日期判断） */
  prune() {
    if (!this.enabled) return 0;
    let removed = 0;
    try {
      const cutoff = Date.now() - this.retentionDays * 86400000;
      for (const name of fs.readdirSync(this.dir)) {
        if (!name.startsWith(FILE_PREFIX) || !name.endsWith(FILE_SUFFIX)) continue;
        const dateStr = name.slice(FILE_PREFIX.length, name.length - FILE_SUFFIX.length);
        const t = Date.parse(`${dateStr}T00:00:00+08:00`);
        if (!Number.isFinite(t)) continue;
        if (t < cutoff) {
          try { fs.unlinkSync(path.join(this.dir, name)); removed++; } catch (e) { /* 占用/权限，忽略 */ }
        }
      }
    } catch (e) {
      this.onError(`日志清理失败: ${e.message}`);
    }
    return removed;
  }

  /** 文件名按日期降序（新文件在前）。日期为 ISO 形式，字典序即时间序。 */
  _listFilesNewestFirst() {
    try {
      return fs.readdirSync(this.dir)
        .filter((n) => n.startsWith(FILE_PREFIX) && n.endsWith(FILE_SUFFIX))
        .sort()
        .reverse()
        .map((n) => path.join(this.dir, n));
    } catch (e) {
      return [];
    }
  }

  /** 从文件尾部读取最多 n 行（只读尾部若干字节，不整文件载入） */
  _tailLines(file, n) {
    if (n <= 0) return [];
    let fd = null;
    try {
      fd = fs.openSync(file, 'r');
      const size = fs.fstatSync(fd).size;
      if (size <= 0) return [];
      const limit = Math.min(size, TAIL_READ_MAX_BYTES);
      const start = Math.max(0, size - limit);
      const buf = Buffer.alloc(limit);
      fs.readSync(fd, buf, 0, limit, start);
      let text = buf.toString('utf8');
      if (start > 0) {
        // 从中间截断，首行可能是半行 —— 丢弃
        const nl = text.indexOf('\n');
        text = nl >= 0 ? text.slice(nl + 1) : '';
      }
      const all = text.split('\n').filter((l) => l.trim());
      return all.slice(-n);
    } catch (e) {
      this.onError(`日志回灌读取失败(${path.basename(file)}): ${e.message}`);
      return [];
    } finally {
      if (fd !== null) { try { fs.closeSync(fd); } catch (e) { /* 已关闭 */ } }
    }
  }

  /**
   * 从最近的文件向前收集，返回按时间升序的最近 maxLines 条**已解析**条目。
   * 损坏行直接跳过，不影响整体。
   */
  loadRecent(maxLines = DEFAULT_BOOT_LINES) {
    const need = Math.max(1, parseInt(maxLines, 10) || DEFAULT_BOOT_LINES);
    const chunks = [];
    let got = 0;
    for (const file of this._listFilesNewestFirst()) {
      if (got >= need) break;
      const lines = this._tailLines(file, need - got);
      if (lines.length > 0) {
        chunks.unshift(lines); // 新文件在前 → unshift 后恢复为时间升序
        got += lines.length;
      }
    }
    const flat = [];
    for (const c of chunks) flat.push(...c);
    const out = [];
    for (const line of flat.slice(-need)) {
      try {
        const o = JSON.parse(line);
        if (o && typeof o.message === 'string') out.push(o);
      } catch (e) { /* 跳过损坏行 */ }
    }
    return out;
  }

  /** 关闭（同步实现下仅置位，保留 API 以便调用方与未来切换实现兼容） */
  close() {
    this.enabled = false;
  }
}

module.exports = { LogPersister, beijingDateString };
