const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
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
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://localhost/snapmemo',
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Helper: wrap async route handlers to catch errors
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// Helper: build positional params $1, $2, ...
function params(count) {
  return Array.from({ length: count }, (_, i) => '$' + (i + 1)).join(', ');
}

// Initialize tables
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      phone TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      nickname TEXT DEFAULT '',
      avatar TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS schedules (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      date TEXT NOT NULL,
      time TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS daily_sop_categories (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      sort_order INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS daily_sop_items (
      id TEXT PRIMARY KEY,
      category_id TEXT NOT NULL REFERENCES daily_sop_categories(id) ON DELETE CASCADE,
      text TEXT NOT NULL,
      checked INTEGER DEFAULT 0,
      sort_order INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS event_sops (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS event_sop_steps (
      id TEXT PRIMARY KEY,
      event_sop_id TEXT NOT NULL REFERENCES event_sops(id) ON DELETE CASCADE,
      text TEXT NOT NULL,
      sort_order INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS inspirations (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      text TEXT NOT NULL,
      date TEXT DEFAULT ''
    );
  `);
  console.log('PostgreSQL 数据库表已初始化');
}

initDB().catch(err => {
  console.error('数据库初始化失败:', err.message);
});

// ── Auth Middleware ──
const authMiddleware = asyncHandler(async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: '未登录，请先登录' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT id FROM users WHERE id = $1', [payload.userId]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: '用户不存在，请重新注册' });
    }
    req.userId = payload.userId;
    req.phone = payload.phone || payload.username;
    next();
  } catch (err) {
    return res.status(401).json({ error: '登录已过期，请重新登录' });
  }
});

// ── Auth Routes ──

// Register
app.post('/api/register', asyncHandler(async (req, res) => {
  const { phone, password } = req.body;

  if (!phone || !password) {
    return res.status(400).json({ error: '手机号和密码不能为空' });
  }
  if (!/^1\d{10}$/.test(phone)) {
    return res.status(400).json({ error: '请输入正确的11位手机号' });
  }
  if (password.length < 4 || password.length > 100) {
    return res.status(400).json({ error: '密码需要 4-100 个字符' });
  }

  const existing = await pool.query('SELECT id FROM users WHERE phone = $1', [phone]);
  if (existing.rows.length > 0) {
    return res.status(409).json({ error: '该手机号已被注册' });
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  const result = await pool.query(
    'INSERT INTO users (phone, password_hash, nickname) VALUES ($1, $2, $3) RETURNING id',
    [phone, passwordHash, phone]
  );

  const userId = result.rows[0].id;
  await createDefaultData(userId);

  const token = jwt.sign({ userId, phone }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });

  res.json({
    token,
    user: { id: userId, phone, nickname: phone, avatar: '' }
  });
}));

// Login
app.post('/api/login', asyncHandler(async (req, res) => {
  const { phone, password } = req.body;

  if (!phone || !password) {
    return res.status(400).json({ error: '请输入手机号和密码' });
  }

  const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
  if (result.rows.length === 0) {
    return res.status(401).json({ error: '手机号或密码错误' });
  }

  const user = result.rows[0];
  if (!bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: '手机号或密码错误' });
  }

  const token = jwt.sign({ userId: user.id, phone: user.phone }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });

  res.json({
    token,
    user: {
      id: user.id,
      phone: user.phone,
      nickname: user.nickname || user.phone,
      avatar: user.avatar || ''
    }
  });
}));

// ── Profile Routes ──

app.get('/api/me', authMiddleware, asyncHandler(async (req, res) => {
  const result = await pool.query(
    'SELECT id, phone, nickname, avatar, created_at FROM users WHERE id = $1',
    [req.userId]
  );
  if (result.rows.length === 0) return res.status(404).json({ error: '用户不存在' });
  res.json({ user: result.rows[0] });
}));

app.put('/api/me', authMiddleware, asyncHandler(async (req, res) => {
  const { nickname, avatar } = req.body;
  const updates = [];
  const params = [];
  let idx = 1;

  if (nickname !== undefined) {
    updates.push(`nickname = $${idx++}`);
    params.push(nickname);
  }
  if (avatar !== undefined) {
    updates.push(`avatar = $${idx++}`);
    params.push(avatar);
  }

  if (updates.length > 0) {
    params.push(req.userId);
    await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${idx}`, params);
  }

  const result = await pool.query(
    'SELECT id, phone, nickname, avatar FROM users WHERE id = $1',
    [req.userId]
  );
  res.json({ user: result.rows[0] });
}));

// ── Data Routes ──

// Get all user data
app.get('/api/data', authMiddleware, asyncHandler(async (req, res) => {
  const userId = req.userId;

  const userResult = await pool.query(
    'SELECT nickname, avatar FROM users WHERE id = $1', [userId]
  );
  const user = userResult.rows[0] || { nickname: '', avatar: '' };

  const schedResult = await pool.query(
    'SELECT id, title, date, time FROM schedules WHERE user_id = $1 ORDER BY date DESC, time DESC',
    [userId]
  );

  const catResult = await pool.query(
    'SELECT id, name, sort_order FROM daily_sop_categories WHERE user_id = $1 ORDER BY sort_order, id',
    [userId]
  );
  const dailySOPs = [];
  for (const cat of catResult.rows) {
    const itemResult = await pool.query(
      'SELECT id, text, checked, sort_order FROM daily_sop_items WHERE category_id = $1 ORDER BY sort_order, id',
      [cat.id]
    );
    dailySOPs.push({
      id: cat.id,
      name: cat.name,
      items: itemResult.rows.map(i => ({ id: i.id, text: i.text, checked: !!i.checked }))
    });
  }

  const eventResult = await pool.query(
    'SELECT id, title FROM event_sops WHERE user_id = $1 ORDER BY id',
    [userId]
  );
  const eventSOPs = [];
  for (const esop of eventResult.rows) {
    const stepResult = await pool.query(
      'SELECT id, text, sort_order FROM event_sop_steps WHERE event_sop_id = $1 ORDER BY sort_order, id',
      [esop.id]
    );
    eventSOPs.push({
      id: esop.id,
      title: esop.title,
      steps: stepResult.rows.map(s => ({ id: s.id, text: s.text }))
    });
  }

  const inspResult = await pool.query(
    'SELECT id, text, date FROM inspirations WHERE user_id = $1 ORDER BY date DESC',
    [userId]
  );

  res.json({
    profile: { nickname: user.nickname, avatar: user.avatar || '' },
    schedules: schedResult.rows,
    dailySOPs,
    eventSOPs,
    inspirations: inspResult.rows
  });
}));

// Sync all user data (replace)
app.put('/api/data', authMiddleware, asyncHandler(async (req, res) => {
  const userId = req.userId;
  const { profile, schedules, dailySOPs, eventSOPs, inspirations } = req.body;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Update profile
    if (profile) {
      await client.query(
        'UPDATE users SET nickname = $1, avatar = $2 WHERE id = $3',
        [profile.nickname || '', profile.avatar || '', userId]
      );
    }

    // Replace schedules
    await client.query('DELETE FROM schedules WHERE user_id = $1', [userId]);
    if (Array.isArray(schedules)) {
      for (let i = 0; i < schedules.length; i++) {
        const s = schedules[i];
        const sid = s.id || (Date.now().toString(36) + Math.random().toString(36).slice(2, 7) + i);
        await client.query(
          'INSERT INTO schedules (id, user_id, title, date, time) VALUES ($1, $2, $3, $4, $5)',
          [sid, userId, s.title || '', s.date || '', s.time || '']
        );
      }
    }

    // Replace daily SOPs
    const oldCats = await client.query('SELECT id FROM daily_sop_categories WHERE user_id = $1', [userId]);
    for (const c of oldCats.rows) {
      await client.query('DELETE FROM daily_sop_items WHERE category_id = $1', [c.id]);
    }
    await client.query('DELETE FROM daily_sop_categories WHERE user_id = $1', [userId]);
    if (Array.isArray(dailySOPs)) {
      for (let ci = 0; ci < dailySOPs.length; ci++) {
        const cat = dailySOPs[ci];
        const cid = cat.id || (Date.now().toString(36) + Math.random().toString(36).slice(2, 7) + 'c' + ci);
        await client.query(
          'INSERT INTO daily_sop_categories (id, user_id, name, sort_order) VALUES ($1, $2, $3, $4)',
          [cid, userId, cat.name || '', ci]
        );
        if (Array.isArray(cat.items)) {
          for (let ii = 0; ii < cat.items.length; ii++) {
            const item = cat.items[ii];
            const iid = item.id || (Date.now().toString(36) + Math.random().toString(36).slice(2, 7) + 'i' + ii);
            await client.query(
              'INSERT INTO daily_sop_items (id, category_id, text, checked, sort_order) VALUES ($1, $2, $3, $4, $5)',
              [iid, cid, item.text || '', item.checked ? 1 : 0, ii]
            );
          }
        }
      }
    }

    // Replace event SOPs
    const oldEvents = await client.query('SELECT id FROM event_sops WHERE user_id = $1', [userId]);
    for (const e of oldEvents.rows) {
      await client.query('DELETE FROM event_sop_steps WHERE event_sop_id = $1', [e.id]);
    }
    await client.query('DELETE FROM event_sops WHERE user_id = $1', [userId]);
    if (Array.isArray(eventSOPs)) {
      for (let ei = 0; ei < eventSOPs.length; ei++) {
        const esop = eventSOPs[ei];
        const eid = esop.id || (Date.now().toString(36) + Math.random().toString(36).slice(2, 7) + 'e' + ei);
        await client.query(
          'INSERT INTO event_sops (id, user_id, title) VALUES ($1, $2, $3)',
          [eid, userId, esop.title || '']
        );
        if (Array.isArray(esop.steps)) {
          for (let si = 0; si < esop.steps.length; si++) {
            const step = esop.steps[si];
            const sid = step.id || (Date.now().toString(36) + Math.random().toString(36).slice(2, 7) + 's' + si);
            await client.query(
              'INSERT INTO event_sop_steps (id, event_sop_id, text, sort_order) VALUES ($1, $2, $3, $4)',
              [sid, eid, step.text || '', si]
            );
          }
        }
      }
    }

    // Replace inspirations
    await client.query('DELETE FROM inspirations WHERE user_id = $1', [userId]);
    if (Array.isArray(inspirations)) {
      for (let i = 0; i < inspirations.length; i++) {
        const insp = inspirations[i];
        const iid = insp.id || (Date.now().toString(36) + Math.random().toString(36).slice(2, 7) + 'n' + i);
        await client.query(
          'INSERT INTO inspirations (id, user_id, text, date) VALUES ($1, $2, $3, $4)',
          [iid, userId, insp.text || '', insp.date || '']
        );
      }
    }

    await client.query('COMMIT');
    res.json({ success: true });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Sync error:', err);
    res.status(500).json({ error: '数据同步失败' });
  } finally {
    client.release();
  }
}));

// ── Default Data for New Users ──
async function createDefaultData(userId) {
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

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    for (let ci = 0; ci < cats.length; ci++) {
      const cat = cats[ci];
      await client.query(
        'INSERT INTO daily_sop_categories (id, user_id, name, sort_order) VALUES ($1, $2, $3, $4)',
        [cat.id, userId, cat.name, ci]
      );
      for (let ii = 0; ii < cat.items.length; ii++) {
        const item = cat.items[ii];
        await client.query(
          'INSERT INTO daily_sop_items (id, category_id, text, checked, sort_order) VALUES ($1, $2, $3, $4, $5)',
          [item.id, cat.id, item.text, 0, ii]
        );
      }
    }

    await client.query(
      'INSERT INTO event_sops (id, user_id, title) VALUES ($1, $2, $3)',
      [eventSOP.id, userId, eventSOP.title]
    );
    for (let si = 0; si < eventSOP.steps.length; si++) {
      const step = eventSOP.steps[si];
      await client.query(
        'INSERT INTO event_sop_steps (id, event_sop_id, text, sort_order) VALUES ($1, $2, $3, $4)',
        [step.id, eventSOP.id, step.text, si]
      );
    }

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('createDefaultData error:', err);
  } finally {
    client.release();
  }
}

// ── Error Handler ──
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: '服务器内部错误' });
});

// ── Serve Frontend ──
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'instant-memory.html'));
});

// ── Start Server ──
app.listen(PORT, () => {
  console.log(`SnapMemo 服务器已启动: http://localhost:${PORT}`);
  console.log(`在浏览器打开 http://localhost:${PORT} 即可使用`);
});
