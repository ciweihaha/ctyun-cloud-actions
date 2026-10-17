const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// 【安全整改 2026-10-15】密码哈希从 SHA256+硬编码 salt 升级为 scrypt + 每用户随机 salt。
// 存储格式：scrypt$<saltHex>$<hashHex>（N=16384,r=8,p=1，Node 内置 crypto，零新依赖）。
// verifyPassword 同时兼容旧格式（64 位 hex 的 SHA256+固定 salt），仅用于验证、不再产生。
const SCRYPT_OPTS = { N: 16384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 };
const LEGACY_SALT = 'ctyun_salt_2026';

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 32, SCRYPT_OPTS).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
  if (typeof stored !== 'string' || !stored) return false;
  try {
    if (stored.startsWith('scrypt$')) {
      const parts = stored.split('$');
      if (parts.length !== 3 || !parts[1] || !parts[2]) return false;
      const hash = crypto.scryptSync(String(password), parts[1], 32, SCRYPT_OPTS);
      const expected = Buffer.from(parts[2], 'hex');
      return hash.length === expected.length && crypto.timingSafeEqual(hash, expected);
    }
    // 旧格式：SHA256(password + 硬编码 salt)，仅验证兼容
    if (/^[0-9a-f]{64}$/.test(stored)) {
      const legacy = crypto.createHash('sha256').update(String(password) + LEGACY_SALT).digest();
      return crypto.timingSafeEqual(legacy, Buffer.from(stored, 'hex'));
    }
    return false;
  } catch (e) {
    return false;
  }
}

/** 生成随机初始管理员口令（未设置环境变量时的兜底），24 字符 base64url。 */
function generateInitialAdminPassword() {
  return crypto.randomBytes(18).toString('base64url');
}

class AuthManager {
  constructor(configManager) {
    this.configManager = configManager;
    // 【2026-09-28】免登录会话持久化：会话表原先是纯内存 Map，容器一重启全部丢失 ——
    // 用户勾了"30 天内免登录"也必须重新登录，这是本次报障的根因。
    // sessionStore = { load(): object|null, save(obj): void }，由 server.js 注入（data/auth_sessions.json）。
    this.sessionStore = configManager.sessionStore || null;
    this.sessions = new Map(); // token -> { userId, username, role, expiresAt, remember }
    this.initAdminUser();
    this.restoreSessions();
  }

  /**
   * 从磁盘恢复"免登录"会话（仅 remember=true 的会持久化；过期即丢弃）。
   * 恢复的会话角色/quota 由 verifySession 每次从用户表动态同步，这里只存最小字段。
   */
  restoreSessions() {
    if (!this.sessionStore) return;
    const data = this.sessionStore.load();
    if (!data || typeof data !== 'object') return;
    let restored = 0;
    for (const [token, s] of Object.entries(data)) {
      if (!s || !s.userId || !s.expiresAt) continue;
      if (Date.now() > s.expiresAt) continue; // 过期不恢复（30 天窗口到期）
      this.sessions.set(token, {
        userId: s.userId,
        username: s.username || '',
        role: '',
        maxQuota: 2,
        remember: true,
        createdAt: s.createdAt || 0,
        expiresAt: s.expiresAt,
      });
      restored++;
    }
    if (restored > 0) console.log(`[Auth] 已从磁盘恢复 ${restored} 个免登录会话（30 天窗口内）`);
  }

  /** 把 remember=true 的会话写盘（非免登录会话绝不落盘，避免公共电脑被持久化）。 */
  _persistSessions() {
    if (!this.sessionStore) return;
    const out = {};
    for (const [token, s] of this.sessions.entries()) {
      if (!s.remember) continue;
      out[token] = {
        userId: s.userId,
        username: s.username,
        createdAt: s.createdAt || 0,
        expiresAt: s.expiresAt,
      };
    }
    this.sessionStore.save(out);
  }

  /** 登出 / 管理员清理：显式销毁会话（含落盘记录）。 */
  destroySession(token) {
    if (token && this.sessions.delete(token)) this._persistSessions();
  }

  createSession(user, remember = false) {
    const token = crypto.randomUUID().replace(/-/g, '');
    const now = Date.now();
    const session = {
      userId: user.id,
      username: user.username,
      role: user.role,
      maxQuota: user.maxQuota || 2,
      remember: !!remember, // 勾选"30 天内免登录"才落盘
      createdAt: now,
      expiresAt: now + 30 * 24 * 3600 * 1000 // 30天
    };
    this.sessions.set(token, session);
    if (session.remember) this._persistSessions();
    return token;
  }

  verifySession(token) {
    if (!token) return null;
    const session = this.sessions.get(token);
    if (!session) return null;
    if (Date.now() > session.expiresAt) {
      this.sessions.delete(token);
      this._persistSessions(); // 过期即清盘（否则磁盘会堆积死会话）
      return null;
    }
    // 动态同步最新用户的 maxQuota、role 和 avatar；
    // 用户已被删除 ⇒ 会话必须失效（否则残留会话还能以旧身份访问）。
    const user = this.getUserById(session.userId);
    if (user) {
      session.role = user.role;
      session.maxQuota = user.maxQuota;
      session.avatar = user.avatar || '';
    } else {
      this.sessions.delete(token);
      this._persistSessions();
      return null;
    }
    return session;
  }

  login(username, password, remember = false) {
    const cfg = this.configManager.config;
    const user = (cfg.users || []).find(u => u.username === username);
    if (!user) return { success: false, error: '用户不存在' };

    // 【安全整改 2026-10-15】改走 verifyPassword（scrypt+随机 salt；兼容旧 SHA256 格式仅用于验证）
    if (!verifyPassword(password, user.passwordHash)) {
      return { success: false, error: '密码错误' };
    }

    const token = this.createSession(user, remember);
    return {
      success: true,
      token,
      remember: !!remember,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        maxQuota: user.maxQuota,
        avatar: user.avatar || ''
      }
    };
  }

  initAdminUser() {
    const cfg = this.configManager.config;
    if (!cfg.users) cfg.users = [];

    // 按角色判定而非用户名字面量：只要系统中已存在任意管理员（含被改名的），
    // 一律不再注入默认账号，避免管理员改名/删除后被凭空重建。
    // 仅在系统完全没有管理员时（全新部署或误删全部管理员的兜底防锁死）才创建默认 admin。
    const hasAnyAdmin = cfg.users.some(u => u.role === 'admin');
    if (hasAnyAdmin) return;

    // 【安全整改 2026-10-15】消除硬编码默认口令。
    // 初始口令来源：环境变量 CTYUN_DASHBOARD_ADMIN_PASSWORD；未设置则生成随机强口令，
    // 只写入本地 data/.admin-init-password.log（0600），控制台仅提示文件位置、绝不打印口令本身。
    const envPassword = process.env.CTYUN_DASHBOARD_ADMIN_PASSWORD;
    const initialPassword = (typeof envPassword === 'string' && envPassword.length > 0)
      ? envPassword
      : generateInitialAdminPassword();
    const admin = {
      id: 'u_admin',
      username: 'admin',
      passwordHash: hashPassword(initialPassword),
      role: 'admin',
      maxQuota: 999,
      createdAt: new Date().toISOString()
    };
    cfg.users.push(admin);
    this.configManager.saveConfig();
    if (!envPassword) {
      try {
        const dataDir = this.configManager.dataDir || path.join(process.cwd(), 'data');
        if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
        const logFile = path.join(dataDir, '.admin-init-password.log');
        const line = `${new Date().toISOString()} 初始管理员账号 admin 的随机口令（仅此一次，请立即登录后修改）：${initialPassword}\n`;
        fs.writeFileSync(logFile, line, { mode: 0o600 });
        console.log(`[Auth] 已为 admin 生成随机初始口令，写入 ${logFile}（0600），请查看后登录修改`);
      } catch (e) {
        console.log('[Auth] 随机初始口令文件写入失败，请设置环境变量 CTYUN_DASHBOARD_ADMIN_PASSWORD 后重启');
      }
    }
  }

  register(username, password) {
    const cfg = this.configManager.config;
    // 默认不开放注册，必须由管理员在后台系统设置中开启
    if (cfg.settings?.allowRegistration !== true) {
      return { success: false, error: '管理员未开放新用户自行注册功能，请联系管理员！' };
    }

    if (!cfg.users) cfg.users = [];

    const cleanUser = username.trim();
    if (!cleanUser || !password) {
      return { success: false, error: '用户名和密码不能为空' };
    }

    if (cfg.users.some(u => u.username === cleanUser)) {
      return { success: false, error: '该用户名已被注册，请直接登录' };
    }

    const defaultQuota = cfg.settings?.defaultQuota || 2;
    const newUser = {
      id: 'u_' + crypto.randomUUID().substring(0, 8),
      username: cleanUser,
      passwordHash: hashPassword(password),
      role: 'user',
      maxQuota: defaultQuota,
      avatar: '',
      createdAt: new Date().toISOString()
    };

    cfg.users.push(newUser);
    this.configManager.saveConfig();

    const token = this.createSession(newUser);
    return {
      success: true,
      token,
      user: {
        id: newUser.id,
        username: newUser.username,
        role: newUser.role,
        maxQuota: newUser.maxQuota,
        avatar: newUser.avatar || ''
      }
    };
  }

  getUserById(userId) {
    const cfg = this.configManager.config;
    return (cfg.users || []).find(u => u.id === userId);
  }

  getUserNotify(userId) {
    const user = this.getUserById(userId);
    return user?.notify || null;
  }

  updateUserNotify(userId, notifyConfig) {
    const cfg = this.configManager.config;
    const user = (cfg.users || []).find(u => u.id === userId);
    if (!user) return false;
    user.notify = {
      enabled: !!notifyConfig?.enabled,
      channel: notifyConfig?.channel || 'webhook',
      webhookUrl: String(notifyConfig?.webhookUrl || '').trim(),
      secret: String(notifyConfig?.secret || '').trim(),
      customTitleTemplate: String(notifyConfig?.customTitleTemplate || '').trim(),
      customContentTemplate: String(notifyConfig?.customContentTemplate || '').trim()
    };
    this.configManager.saveConfig();
    return true;
  }

  getUsers() {
    const cfg = this.configManager.config;
    return (cfg.users || []).map(u => {
      const accountsCount = (cfg.accounts || []).filter(a => a.ownerId === u.id).length;
      return {
        id: u.id,
        username: u.username,
        role: u.role,
        maxQuota: u.maxQuota || 2,
        accountsCount,
        createdAt: u.createdAt
      };
    });
  }

  updateUserQuota(userId, maxQuota) {
    const cfg = this.configManager.config;
    const user = (cfg.users || []).find(u => u.id === userId);
    if (!user) return false;
    user.maxQuota = parseInt(maxQuota) || 2;
    this.configManager.saveConfig();
    return true;
  }

  updateUserPassword(userId, newPassword) {
    const cfg = this.configManager.config;
    const user = (cfg.users || []).find(u => u.id === userId);
    if (!user) return false;
    user.passwordHash = hashPassword(newPassword);
    this.configManager.saveConfig();
    return true;
  }

  updateUserAvatar(userId, avatar) {
    const cfg = this.configManager.config;
    const user = (cfg.users || []).find(u => u.id === userId);
    if (!user) return false;
    user.avatar = String(avatar || '').trim();
    // 同步活跃会话
    for (const [token, s] of this.sessions.entries()) {
      if (s.userId === userId) s.avatar = user.avatar;
    }
    this.configManager.saveConfig();
    return true;
  }

  updateAdminUsername(oldUsername, newUsername) {
    const cfg = this.configManager.config;
    const cleanNew = (newUsername || '').trim();
    if (!cleanNew) return { success: false, error: '新管理员用户名不能为空' };
    if (cfg.users.some(u => u.username === cleanNew && u.username !== oldUsername)) {
      return { success: false, error: '该用户名已被其他账号占用' };
    }

    const admin = (cfg.users || []).find(u => u.username === oldUsername && u.role === 'admin');
    if (!admin) return { success: false, error: '管理员账号不存在' };

    admin.username = cleanNew;
    // 同步更新当前会话里的 username
    for (const [token, s] of this.sessions.entries()) {
      if (s.userId === admin.id) s.username = cleanNew;
    }
    this.configManager.saveConfig();
    return { success: true, newUsername: cleanNew };
  }

  deleteUser(userId) {
    const cfg = this.configManager.config;
    const user = (cfg.users || []).find(u => u.id === userId);
    if (!user || user.role === 'admin') return false;
    cfg.users = cfg.users.filter(u => u.id !== userId);
    // 同时清理该用户的会话（含落盘的免登录会话 —— 否则重启后残魂复活）
    for (const [token, s] of this.sessions.entries()) {
      if (s.userId === userId) this.sessions.delete(token);
    }
    this._persistSessions();
    this.configManager.saveConfig();
    return true;
  }
}

module.exports = { AuthManager, hashPassword, verifyPassword };
