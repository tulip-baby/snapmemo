const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'snapmemo-secret-key-change-in-production';
const TOKEN_EXPIRY = '30d';

// ── Middleware ──
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname)));

// ── Database ──
const db = new Database(path.join(__dirname, 'snapmemo.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    nickname TEXT DEFAULT '',
    avatar TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    date TEXT NOT NULL,
    time TEXT DEFAULT '',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS daily_sop_categories (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    sort_order INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS daily_sop_items (
    id TEXT PRIMARY KEY,
    category_id TEXT NOT NULL,
    text TEXT NOT NULL,
    checked INTEGER DEFAULT 0,
    sort_order INTEGER DEFAULT 0,
    FOREIGN KEY (category_id) REFERENCES daily_sop_categories(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS event_sops (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS event_sop_steps (
    id TEXT PRIMARY KEY,
    event_sop_id TEXT NOT NULL,
    text TEXT NOT NULL,
    sort_order INTEGER DEFAULT 0,
    FOREIGN KEY (event_sop_id) REFERENCES event_sops(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS inspirations (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    date TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// ── Auth Middleware ──
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: '未登录，请先登录' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    req.username = payload.username;
    next();
  } catch (err) {
    return res.status(401).json({ error: '登录已过期，请重新登录' });
  }
}

// ── Auth Routes ──

// Register
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: '用户名和密码不能为空' });
  }
  if (username.length < 2 || username.length > 30) {
    return res.status(400).json({ error: '用户名需要 2-30 个字符' });
  }
  if (password.length < 4 || password.length > 100) {
    return res.status(400).json({ error: '密码需要 4-100 个字符' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    return res.status(409).json({ error: '该用户名已被注册' });
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  const result = db.prepare(
    'INSERT INTO users (username, password_hash, nickname) VALUES (?, ?, ?)'
  ).run(username, passwordHash, username);

  // Create default data for new user
  const userId = result.lastInsertRowid;
  createDefaultData(userId);

  const token = jwt.sign({ userId, username }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });

  res.json({
    token,
    user: { id: userId, username, nickname: username, avatar: '' }
  });
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: '请输入用户名和密码' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) {
    return res.status(401).json({ error: '用户名或密码错误' });
  }

  if (!bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: '用户名或密码错误' });
  }

  const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });

  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      nickname: user.nickname || user.username,
      avatar: user.avatar || ''
    }
  });
});

// ── Profile Routes ──

app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, username, nickname, avatar, created_at FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(404).json({ error: '用户不存在' });
  res.json({ user });
});

app.put('/api/me', authMiddleware, (req, res) => {
  const { nickname, avatar } = req.body;
  const updates = [];
  const params = [];

  if (nickname !== undefined) {
    updates.push('nickname = ?');
    params.push(nickname);
  }
  if (avatar !== undefined) {
    updates.push('avatar = ?');
    params.push(avatar);
  }

  if (updates.length > 0) {
    params.push(req.userId);
    db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  }

  const user = db.prepare('SELECT id, username, nickname, avatar FROM users WHERE id = ?').get(req.userId);
  res.json({ user });
});

// ── Data Routes ──

// Get all user data
app.get('/api/data', authMiddleware, (req, res) => {
  const userId = req.userId;

  // Profile
  const user = db.prepare('SELECT nickname, avatar FROM users WHERE id = ?').get(userId);

  // Schedules
  const schedules = db.prepare(
    'SELECT id, title, date, time FROM schedules WHERE user_id = ? ORDER BY date DESC, time DESC'
  ).all(userId);

  // Daily SOPs with items
  const categories = db.prepare(
    'SELECT id, name, sort_order FROM daily_sop_categories WHERE user_id = ? ORDER BY sort_order, id'
  ).all(userId);
  const dailySOPs = categories.map(cat => {
    const items = db.prepare(
      'SELECT id, text, checked, sort_order FROM daily_sop_items WHERE category_id = ? ORDER BY sort_order, id'
    ).all(cat.id);
    return {
      id: cat.id,
      name: cat.name,
      items: items.map(i => ({ id: i.id, text: i.text, checked: !!i.checked }))
    };
  });

  // Event SOPs with steps
  const eventSOPsRaw = db.prepare(
    'SELECT id, title FROM event_sops WHERE user_id = ? ORDER BY id'
  ).all(userId);
  const eventSOPs = eventSOPsRaw.map(esop => {
    const steps = db.prepare(
      'SELECT id, text, sort_order FROM event_sop_steps WHERE event_sop_id = ? ORDER BY sort_order, id'
    ).all(esop.id);
    return {
      id: esop.id,
      title: esop.title,
      steps: steps.map(s => ({ id: s.id, text: s.text }))
    };
  });

  // Inspirations
  const inspirations = db.prepare(
    'SELECT id, text, date FROM inspirations WHERE user_id = ? ORDER BY date DESC'
  ).all(userId);

  res.json({
    profile: { nickname: user.nickname, avatar: user.avatar || '' },
    schedules,
    dailySOPs,
    eventSOPs,
    inspirations
  });
});

// Sync all user data (replace)
app.put('/api/data', authMiddleware, (req, res) => {
  const userId = req.userId;
  const { profile, schedules, dailySOPs, eventSOPs, inspirations } = req.body;

  const syncAll = db.transaction(() => {
    // Update profile
    if (profile) {
      db.prepare('UPDATE users SET nickname = ?, avatar = ? WHERE id = ?')
        .run(profile.nickname || '', profile.avatar || '', userId);
    }

    // Replace schedules
    db.prepare('DELETE FROM schedules WHERE user_id = ?').run(userId);
    if (Array.isArray(schedules)) {
      const insertSched = db.prepare(
        'INSERT INTO schedules (id, user_id, title, date, time) VALUES (?, ?, ?, ?, ?)'
      );
      schedules.forEach(s => insertSched.run(s.id, userId, s.title, s.date, s.time || ''));
    }

    // Replace daily SOPs
    const oldCats = db.prepare('SELECT id FROM daily_sop_categories WHERE user_id = ?').all(userId);
    oldCats.forEach(c => db.prepare('DELETE FROM daily_sop_items WHERE category_id = ?').run(c.id));
    db.prepare('DELETE FROM daily_sop_categories WHERE user_id = ?').run(userId);
    if (Array.isArray(dailySOPs)) {
      const insertCat = db.prepare(
        'INSERT INTO daily_sop_categories (id, user_id, name, sort_order) VALUES (?, ?, ?, ?)'
      );
      const insertItem = db.prepare(
        'INSERT INTO daily_sop_items (id, category_id, text, checked, sort_order) VALUES (?, ?, ?, ?, ?)'
      );
      dailySOPs.forEach((cat, ci) => {
        insertCat.run(cat.id, userId, cat.name, ci);
        if (Array.isArray(cat.items)) {
          cat.items.forEach((item, ii) => {
            insertItem.run(item.id, cat.id, item.text, item.checked ? 1 : 0, ii);
          });
        }
      });
    }

    // Replace event SOPs
    const oldEvents = db.prepare('SELECT id FROM event_sops WHERE user_id = ?').all(userId);
    oldEvents.forEach(e => db.prepare('DELETE FROM event_sop_steps WHERE event_sop_id = ?').run(e.id));
    db.prepare('DELETE FROM event_sops WHERE user_id = ?').run(userId);
    if (Array.isArray(eventSOPs)) {
      const insertEvent = db.prepare(
        'INSERT INTO event_sops (id, user_id, title) VALUES (?, ?, ?)'
      );
      const insertStep = db.prepare(
        'INSERT INTO event_sop_steps (id, event_sop_id, text, sort_order) VALUES (?, ?, ?, ?)'
      );
      eventSOPs.forEach(esop => {
        insertEvent.run(esop.id, userId, esop.title);
        if (Array.isArray(esop.steps)) {
          esop.steps.forEach((step, si) => {
            insertStep.run(step.id, esop.id, step.text, si);
          });
        }
      });
    }

    // Replace inspirations
    db.prepare('DELETE FROM inspirations WHERE user_id = ?').run(userId);
    if (Array.isArray(inspirations)) {
      const insertInsp = db.prepare(
        'INSERT INTO inspirations (id, user_id, text, date) VALUES (?, ?, ?, ?)'
      );
      inspirations.forEach(insp => insertInsp.run(insp.id, userId, insp.text, insp.date));
    }
  });

  try {
    syncAll();
    res.json({ success: true });
  } catch (err) {
    console.error('Sync error:', err);
    res.status(500).json({ error: '数据同步失败' });
  }
});

// ── Default Data for New Users ──
function createDefaultData(userId) {
  const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);

  const cats = [
    { id: uid(), name: '出门必备', items: [
      { id: uid(), text: '手机' }, { id: uid(), text: '钥匙' },
      { id: uid(), text: '钱包/卡包' }, { id: uid(), text: '充电宝' }
    ]},
    { id: uid(), name: '考试必备', items: [
      { id: uid(), text: '准考证' }, { id: uid(), text: '身份证' },
      { id: uid(), text: '2B铅笔' }, { id: uid(), text: '黑色签字笔' }
    ]},
    { id: uid(), name: '回家必备', items: [
      { id: uid(), text: '给家人带礼物' }, { id: uid(), text: '车票/机票' },
      { id: uid(), text: '充电线' }
    ]}
  ];

  const eventSOP = {
    id: uid(), title: '发布新版本上线流程', steps: [
      { id: uid(), text: '代码审查通过' }, { id: uid(), text: '合并到主分支' },
      { id: uid(), text: '运行自动化测试' }, { id: uid(), text: '构建生产版本' },
      { id: uid(), text: '灰度发布 5% 流量' }, { id: uid(), text: '监控指标正常后全量发布' }
    ]
  };

  const insertCat = db.prepare('INSERT INTO daily_sop_categories (id, user_id, name, sort_order) VALUES (?, ?, ?, ?)');
  const insertItem = db.prepare('INSERT INTO daily_sop_items (id, category_id, text, checked, sort_order) VALUES (?, ?, ?, 0, ?)');
  const insertEvent = db.prepare('INSERT INTO event_sops (id, user_id, title) VALUES (?, ?, ?)');
  const insertStep = db.prepare('INSERT INTO event_sop_steps (id, event_sop_id, text, sort_order) VALUES (?, ?, ?, ?)');

  cats.forEach((cat, ci) => {
    insertCat.run(cat.id, userId, cat.name, ci);
    cat.items.forEach((item, ii) => insertItem.run(item.id, cat.id, item.text, ii));
  });

  insertEvent.run(eventSOP.id, userId, eventSOP.title);
  eventSOP.steps.forEach((step, si) => insertStep.run(step.id, eventSOP.id, step.text, si));
}

// ── Serve Frontend ──
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'instant-memory.html'));
});

// ── Start Server ──
app.listen(PORT, () => {
  console.log(`SnapMemo 服务器已启动: http://localhost:${PORT}`);
  console.log(`在浏览器打开 http://localhost:${PORT} 即可使用`);
});
