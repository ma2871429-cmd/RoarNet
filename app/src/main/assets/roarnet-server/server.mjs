import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const root = path.dirname(fileURLToPath(import.meta.url));

for (const line of (fs.existsSync(path.join(root, '.env')) ? fs.readFileSync(path.join(root, '.env'), 'utf8').split(/\r?\n/) : [])) {
  const m = line.match(/^\s*([A-Z_]+)=(.*)$/);
  if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
}

const ADMIN = process.env.ADMIN_TOKEN || '';
const HOST = process.env.HOST || '0.0.0.0';
const PORT = Number(process.env.PORT || 3180);
const RELAY_TOKEN = process.env.RELAY_TOKEN || '';
const MONTHLY_CAP_BYTES = 150_000_000_000;
const MAX_RELAY_EVENT_BYTES = 100 * 1024 * 1024;

if (ADMIN.length < 32 || !Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  console.error('Invalid configuration. Keep ADMIN_TOKEN secret and at least 32 characters.');
  process.exit(1);
}

const DB_PATH = process.env.DB_PATH || (
  process.env.NODE_ENV === 'production'
    ? path.join(root, 'roarnet.sqlite')
    : path.join(root, 'data', 'roarnet.sqlite')
);
try {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
} catch (err) {
  console.error('Cannot prepare SQLite database directory:', err.message);
  process.exit(1);
}

let db;
try {
  db = new DatabaseSync(DB_PATH);
} catch (err) {
  console.error('Cannot open SQLite database:', DB_PATH, err.message);
  process.exit(1);
}

 // ROARNET_IP_ANALYTICS_V1
 db.exec(`
   CREATE TABLE IF NOT EXISTS participant_ip_fingerprints (
     node_id TEXT NOT NULL REFERENCES nodes(id),
     ip_fingerprint TEXT NOT NULL,
     first_seen_at TEXT NOT NULL,
     last_seen_at TEXT NOT NULL,
     PRIMARY KEY(node_id, ip_fingerprint)
   );
 `);

db.exec(`
  PRAGMA journal_mode=WAL;
  PRAGMA foreign_keys=ON;

  CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sharing_consents (
    node_id TEXT PRIMARY KEY REFERENCES nodes(id),
    accepted_at TEXT NOT NULL,
    revoked_at TEXT,
    disclosure_version TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS usage_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL REFERENCES nodes(id),
    reference TEXT NOT NULL UNIQUE,
    bytes INTEGER NOT NULL CHECK(bytes > 0),
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS net_revenue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reference TEXT NOT NULL UNIQUE,
    net_cents INTEGER NOT NULL CHECK(net_cents > 0),
    created_at TEXT NOT NULL
  );
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS customers (
      id TEXT PRIMARY KEY,
      label TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS traffic_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      reference TEXT NOT NULL UNIQUE,
      node_id TEXT NOT NULL REFERENCES nodes(id),
      customer_id TEXT NOT NULL REFERENCES customers(id),
      bytes INTEGER NOT NULL CHECK(bytes > 0),
      month_key TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_traffic_node_month
      ON traffic_events(node_id, month_key);
    CREATE INDEX IF NOT EXISTS idx_traffic_customer_month
      ON traffic_events(customer_id, month_key);
    CREATE INDEX IF NOT EXISTS idx_traffic_customer_bytes
      ON traffic_events(customer_id, bytes);
    CREATE INDEX IF NOT EXISTS idx_traffic_node_month_bytes
      ON traffic_events(node_id, month_key, bytes);
    CREATE INDEX IF NOT EXISTS idx_traffic_customer_month_bytes
      ON traffic_events(customer_id, month_key, bytes);
  `);


// ROARNET_SALES_V1
// Store catalog and prepaid customer balances. Prices are USD cents.
db.exec(`
  CREATE TABLE IF NOT EXISTS packages (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    bytes INTEGER NOT NULL CHECK(bytes > 0),
    price_cents INTEGER NOT NULL CHECK(price_cents > 0),
    active INTEGER NOT NULL DEFAULT 0 CHECK(active IN (0,1)),
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES customers(id),
    package_id TEXT NOT NULL REFERENCES packages(id),
    package_name TEXT NOT NULL,
    package_bytes INTEGER NOT NULL CHECK(package_bytes > 0),
    price_cents INTEGER NOT NULL CHECK(price_cents > 0),
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','paid','cancelled')),
    payment_provider TEXT,
    payment_reference TEXT UNIQUE,
    net_cents INTEGER,
    created_at TEXT NOT NULL,
    paid_at TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_orders_customer_status ON orders(customer_id,status);
`);

// Existing customers get a token column; older rows remain admin-managed until a token is issued.
const customerColumns = db.prepare('PRAGMA table_info(customers)').all().map(c => c.name);
if (!customerColumns.includes('token_hash')) {
  db.exec('ALTER TABLE customers ADD COLUMN token_hash TEXT');
}
db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_token_hash ON customers(token_hash) WHERE token_hash IS NOT NULL');

// Draft prices only: packages remain disabled until the owner activates and verifies them.
const seedPackage = db.prepare('INSERT OR IGNORE INTO packages(id,name,bytes,price_cents,active,created_at) VALUES(?,?,?,?,0,?)');
seedPackage.run('starter-1gb', 'Starter 1 GB (draft price)', 1_000_000_000, 100, new Date().toISOString(),);
seedPackage.run('standard-10gb', 'Standard 10 GB (draft price)', 10_000_000_000, 500, new Date().toISOString(),);
seedPackage.run('large-50gb', 'Large 50 GB (draft price)', 50_000_000_000, 2000, new Date().toISOString(),);

db.exec(`
  CREATE TABLE IF NOT EXISTS page_visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    visit_day TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_page_visits_day ON page_visits(visit_day);
`);

const addPageVisit = db.prepare(
  'INSERT INTO page_visits (visit_day, created_at) VALUES (?, ?)'
);
const getBaghdadDay = () => new Intl.DateTimeFormat('en-CA', {
  timeZone: 'Asia/Baghdad', year: 'numeric', month: '2-digit', day: '2-digit'
}).format(new Date());

const hash = x => crypto.createHash('sha256').update(x).digest('hex');
const now = () => new Date().toISOString();

function json(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  res.end(JSON.stringify(data));
}

function bearer(req) {
  const m = (req.headers.authorization || '').match(/^Bearer ([A-Za-z0-9_-]+)$/);
  return m ? m[1] : '';
}

function isAdmin(req) {
  const supplied = bearer(req);
  const a = Buffer.from(hash(supplied));
  const b = Buffer.from(hash(ADMIN));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function nodeFor(req) {
  const supplied = bearer(req);
  if (!supplied) return null;
  return db.prepare(
    "SELECT id FROM nodes WHERE token_hash=? AND status='active'"
  ).get(hash(supplied)) || null;
}


function customerFor(req) {
  const supplied = bearer(req);
  if (!supplied) return null;
  return db.prepare("SELECT id,label FROM customers WHERE token_hash=? AND status='active'")
    .get(hash(supplied)) || null;
}

function customerBalance(customerId) {
  const purchased = Number(db.prepare("SELECT COALESCE(SUM(package_bytes),0) AS n FROM orders WHERE customer_id=? AND status='paid'").get(customerId).n);
  const used = Number(db.prepare('SELECT COALESCE(SUM(bytes),0) AS n FROM traffic_events WHERE customer_id=?').get(customerId).n);
  return { purchasedBytes: purchased, usedBytes: used, remainingBytes: Math.max(0, purchased - used) };
}

async function body(req) {
  let data = '';
  for await (const chunk of req) {
    data += chunk;
    if (data.length > 16384) throw new Error('BODY_TOO_LARGE');
  }
  return JSON.parse(data || '{}');
}


// ROARNET_USDT_INVOICES_V1
db.exec(`
  CREATE TABLE IF NOT EXISTS payment_invoices (
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL UNIQUE REFERENCES orders(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    amount_usdt TEXT NOT NULL,
    network TEXT NOT NULL DEFAULT 'TRC20',
    destination TEXT,
    status TEXT NOT NULL CHECK(status IN ('setup_required','pending','paid','expired')),
    txid TEXT UNIQUE,
    created_at TEXT NOT NULL,
    paid_at TEXT
  );
`);

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (req.method === "GET" && url.pathname === "/sitemap.xml") {
      const xml = '<?xml version="1.0" encoding="UTF-8"?>' +
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' +
        '<url><loc>https://roarnet.hostless.app/</loc></url>' +
        '</urlset>';
      res.writeHead(200, {
        "Content-Type": "application/xml; charset=utf-8",
        "Cache-Control": "public, max-age=3600",
        "X-Content-Type-Options": "nosniff"
      });
      return res.end(xml);
    }

    if (req.method === "GET" && url.pathname === "/robots.txt") {
      res.writeHead(200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "public, max-age=3600",
        "X-Content-Type-Options": "nosniff"
      });
      return res.end("User-agent: *\nAllow: /\nSitemap: https://roarnet.hostless.app/sitemap.xml\n");
    }

    if (req.method === "GET" && url.pathname === "/google851250a9e589b228.html") {
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff"
      });
      return res.end("google-site-verification: google851250a9e589b228.html");
    }

    if (req.method === 'GET' && url.pathname === '/api/public/stats') {
      const registered = db.prepare('SELECT COUNT(*) AS n FROM nodes').get();
      const consented = db.prepare(
        'SELECT COUNT(*) AS n FROM sharing_consents WHERE accepted_at IS NOT NULL AND revoked_at IS NULL'
      ).get();
      const visits = db.prepare('SELECT COUNT(*) AS n FROM page_visits').get();
      const relayTraffic = db.prepare(`
        SELECT COALESCE(SUM(bytes), 0) AS bytes, COUNT(*) AS events
        FROM traffic_events
      `).get();
      const totalRelayTrafficBytes = Number(relayTraffic.bytes);
      const totalRelayTrafficGb = totalRelayTrafficBytes / 1000000000;
      const ipConfig = (process.env.ROARNET_IP_HMAC_SECRET || '').length >= 32 &&
        process.env.ROARNET_PROXY_IP_HEADER_TRUSTED === 'yes';
      let distinctIps = null;
      let activeIps24h = null;
      if (ipConfig) {
        distinctIps = Number(db.prepare(
          'SELECT COUNT(DISTINCT ip_fingerprint) AS n FROM participant_ip_fingerprints'
        ).get().n);
        const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        activeIps24h = Number(db.prepare(
          'SELECT COUNT(DISTINCT ip_fingerprint) AS n FROM participant_ip_fingerprints WHERE last_seen_at >= ?'
        ).get(cutoff).n);
      }
      return json(res, 200, {
        registeredParticipants: Number(registered.n),
        consentedParticipants: Number(consented.n),
        totalVisits: Number(visits.n),
        totalRelayTrafficBytes,
        totalRelayTrafficGb,
        relayTrafficEvents: Number(relayTraffic.events),
        distinctIps,
        activeIps24h,
        note: 'الأرقام تخص السجلات المسجلة فقط. إحصاءات IP تعتمد على إعدادات الخادم وبيانات المشاركين المبلّغين.'
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/visits/stats') {
      const today = getBaghdadDay();
      const visitsToday = db.prepare(
        'SELECT COUNT(*) AS count FROM page_visits WHERE visit_day = ?'
      ).get(today).count;
      const totalVisits = db.prepare(
        'SELECT COUNT(*) AS count FROM page_visits'
      ).get().count;
      return json(res, 200, { today, visitsToday, totalVisits });
    }

    // ROARNET_UNIFIED_UI_V1
    if (req.method === 'GET' && url.pathname === '/') {
      addPageVisit.run(getBaghdadDay(), now());
      const page = fs.readFileSync(path.join(root, 'public', 'index.html'), 'utf8');
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://bauval.org https://esm.sh; frame-src 'self' https:; style-src 'self' 'unsafe-inline'; connect-src 'self' https://bauval.org https://bsmumxfajnzhziezxfth.supabase.co; img-src 'self' data: https://bauval.org; base-uri 'none'; frame-ancestors 'none'"
      });
      return res.end(page);
    }

    if (req.method === 'GET' && url.pathname === '/health') {
      return json(res, 200, { app: 'RoarNet Independent Core', status: 'running' });
    }

    if (req.method === 'POST' && url.pathname === '/api/admin/nodes') {
      if (!isAdmin(req)) return json(res, 401, { error: 'Unauthorized' });

      const b = await body(req);
      const label = String(b.label || '').trim();
      if (!label || label.length > 80) {
        return json(res, 400, { error: 'Provide a label up to 80 characters' });
      }

      const id = crypto.randomUUID();
      const token = crypto.randomBytes(32).toString('hex');

      db.prepare(
        'INSERT INTO nodes(id,label,token_hash,created_at) VALUES(?,?,?,?)'
      ).run(id, label, hash(token), now());

      return json(res, 201, {
        id, label, token,
        warning: 'Save this token securely. It is shown only once. No proxy traffic is served by this core.'
      });
    }


    // ROARNET_MY_CONTRIBUTIONS_V1
    if (req.method === 'GET' && url.pathname === '/api/node/my-contributions') {
      const node = nodeFor(req);
      if (!node) return json(res, 401, { error: 'Invalid node token' });

      const monthKey = now().slice(0, 7);
      const total = db.prepare(`
        SELECT COALESCE(SUM(bytes), 0) AS bytes, COUNT(*) AS events
        FROM usage_events WHERE node_id=?
      `).get(node.id);
      const monthly = db.prepare(`
        SELECT COALESCE(SUM(bytes), 0) AS bytes, COUNT(*) AS events
        FROM usage_events WHERE node_id=? AND substr(created_at, 1, 7)=?
      `).get(node.id, monthKey);
      const recent = db.prepare(`
        SELECT reference, bytes, created_at
        FROM usage_events WHERE node_id=?
        ORDER BY id DESC LIMIT 10
      `).all(node.id);

      return json(res, 200, {
        nodeId: node.id,
        month: monthKey,
        total: { bytes: Number(total.bytes), events: Number(total.events) },
        monthly: { bytes: Number(monthly.bytes), events: Number(monthly.events) },
        recent: recent.map(e => ({
          reference: e.reference,
          bytes: Number(e.bytes),
          createdAt: e.created_at
        })),
        note: 'These are reported usage events, not independently verified billable traffic or confirmed earnings.'
      });
    }

    // ROARNET_PARTICIPANT_CONSENT_V1
    if (url.pathname === '/api/node/consent' &&
        req.method === 'GET') {
      const node = nodeFor(req);
      if (!node) return json(res, 401, { error: 'Invalid node token' });

      const consent = db.prepare(
        'SELECT accepted_at, revoked_at, disclosure_version FROM sharing_consents WHERE node_id=?'
      ).get(node.id);

      return json(res, 200, {
        accepted: Boolean(consent && !consent.revoked_at),
        acceptedAt: consent?.accepted_at || null,
        revokedAt: consent?.revoked_at || null,
        disclosureVersion: consent?.disclosure_version || null
      });
    }

    if (url.pathname === '/api/node/consent' &&
        req.method === 'POST') {
      const node = nodeFor(req);
      if (!node) return json(res, 401, { error: 'Invalid node token' });

      const data = await body(req);
      if (data.accepted !== true ||
          data.disclosureVersion !== 'roarnet-sharing-v1') {
        return json(res, 400, {
          error: 'Explicit consent and the current disclosure version are required',
          requiredDisclosureVersion: 'roarnet-sharing-v1'
        });
      }

      const acceptedAt = now();
      db.prepare(`
        INSERT INTO sharing_consents(node_id, accepted_at, revoked_at, disclosure_version)
        VALUES(?,?,NULL,?)
        ON CONFLICT(node_id) DO UPDATE SET
          accepted_at=excluded.accepted_at,
          revoked_at=NULL,
          disclosure_version=excluded.disclosure_version
      `).run(node.id, acceptedAt, 'roarnet-sharing-v1');

      return json(res, 200, {
        ok: true,
        accepted: true,
        acceptedAt,
        disclosureVersion: 'roarnet-sharing-v1'
      });
    }

    if (url.pathname === '/api/node/consent/revoke' &&
        req.method === 'POST') {
      const node = nodeFor(req);
      if (!node) return json(res, 401, { error: 'Invalid node token' });

      const revokedAt = now();
      db.prepare(
        'UPDATE sharing_consents SET revoked_at=? WHERE node_id=? AND revoked_at IS NULL'
      ).run(revokedAt, node.id);

      return json(res, 200, {
        ok: true,
        accepted: false,
        revokedAt
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/meter') {
      const node = nodeFor(req);
      if (!node) return json(res, 401, { error: 'Invalid node token' });
      const consent = db.prepare(
        'SELECT node_id FROM sharing_consents WHERE node_id=? AND revoked_at IS NULL'
      ).get(node.id);
      if (!consent) {
        return json(res, 403, {
          error: 'Participant consent required',
          consentEndpoint: '/api/node/consent'
        });
      }

      const b = await body(req);
      const reference = String(b.reference || '');
      const bytes = Number(b.bytes);

      if (!/^[A-Za-z0-9_-]{8,100}$/.test(reference) ||
          !Number.isSafeInteger(bytes) || bytes < 1 || bytes > 100 * 1024 * 1024) {
        return json(res, 400, { error: 'Invalid reference or byte count (max 100 MiB per event)' });
      }

      try {
        db.prepare(
          'INSERT INTO usage_events(node_id,reference,bytes,created_at) VALUES(?,?,?,?)'
        ).run(node.id, reference, bytes, now());
      } catch (e) {
        if (String(e.message).includes('UNIQUE')) {
          return json(res, 409, { error: 'Duplicate usage reference' });
        }
        throw e;
      }

      // ROARNET_IP_CAPTURE_V1
      // Fail closed: لا نثق بالترويسة إلا بعد تأكيد إعداد البروكسي.
      const ipSecret = process.env.ROARNET_IP_HMAC_SECRET || '';
      const ipHeader = (process.env.ROARNET_CLIENT_IP_HEADER || '').toLowerCase();
      if (ipSecret.length >= 32 &&
          process.env.ROARNET_PROXY_IP_HEADER_TRUSTED === 'yes' &&
          /^[a-z0-9-]+$/.test(ipHeader)) {
        const raw = String(req.headers[ipHeader] || '').trim();
        // نقبل عنوانًا واحدًا فقط؛ لا نختار عنوانًا من قائمة Forwarded غير موثوقة.
        if (raw && !raw.includes(',') && raw.length <= 100 &&
            !/[\s;]/.test(raw)) {
          const fingerprint = crypto.createHmac('sha256', ipSecret)
            .update(raw).digest('hex');
          const stamp = now();
          db.prepare(`
            INSERT INTO participant_ip_fingerprints
              (node_id, ip_fingerprint, first_seen_at, last_seen_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(node_id, ip_fingerprint)
            DO UPDATE SET last_seen_at=excluded.last_seen_at
          `).run(node.id, fingerprint, stamp, stamp);
        }
      }

      return json(res, 201, { ok: true, recordedBytes: bytes });
    }


    // ROARNET_CAPS_METER_V1
    if (req.method === 'POST' && url.pathname === '/api/relay/usage') {
      if (RELAY_TOKEN.length < 32) {
        return json(res, 503, { error: 'Relay metering is not configured' });
      }

      const supplied = bearer(req);
      const a = Buffer.from(hash(supplied));
      const b = Buffer.from(hash(RELAY_TOKEN));
      if (!supplied || !crypto.timingSafeEqual(a, b)) {
        return json(res, 401, { error: 'Invalid relay credentials' });
      }

      const data = await body(req);
      const reference = String(data.reference || '');
      const nodeId = String(data.nodeId || '');
      const customerId = String(data.customerId || '');
      const bytes = Number(data.bytes);

      if (!/^[A-Za-z0-9_-]{8,100}$/.test(reference) ||
          !/^[0-9a-f-]{36}$/i.test(nodeId) ||
          !/^[0-9a-f-]{36}$/i.test(customerId) ||
          !Number.isSafeInteger(bytes) ||
          bytes < 1 || bytes > MAX_RELAY_EVENT_BYTES) {
        return json(res, 400, { error: 'Invalid usage event' });
      }

      const node = db.prepare(
        "SELECT id FROM nodes WHERE id=? AND status='active'"
      ).get(nodeId);
      const customer = db.prepare(
        "SELECT id FROM customers WHERE id=? AND status='active'"
      ).get(customerId);

      if (!node || !customer) {
        return json(res, 403, { error: 'Active node and customer required' });
      }

      const balance = customerBalance(customerId);
      if (bytes > balance.remainingBytes) {
        return json(res, 402, {
          error: 'Insufficient prepaid traffic balance',
          purchasedBytes: balance.purchasedBytes,
          usedBytes: balance.usedBytes,
          remainingBytes: balance.remainingBytes
        });
      }

      const consent = db.prepare(
        'SELECT node_id FROM sharing_consents WHERE node_id=? AND revoked_at IS NULL'
      ).get(nodeId);
      if (!consent) {
        return json(res, 403, {
          error: 'Participant consent required',
          consentEndpoint: '/api/node/consent'
        });
      }

      const monthKey = now().slice(0, 7);
      const nodeUsed = Number(db.prepare(
        'SELECT COALESCE(SUM(bytes),0) AS n FROM traffic_events WHERE node_id=? AND month_key=?'
      ).get(nodeId, monthKey).n);
      const customerUsed = Number(db.prepare(
        'SELECT COALESCE(SUM(bytes),0) AS n FROM traffic_events WHERE customer_id=? AND month_key=?'
      ).get(customerId, monthKey).n);

      if (bytes > MONTHLY_CAP_BYTES - nodeUsed) {
        return json(res, 429, {
          error: 'Participant monthly cap reached',
          capBytes: MONTHLY_CAP_BYTES,
          usedBytes: nodeUsed
        });
      }

      if (bytes > MONTHLY_CAP_BYTES - customerUsed) {
        return json(res, 429, {
          error: 'Customer monthly cap reached',
          capBytes: MONTHLY_CAP_BYTES,
          usedBytes: customerUsed
        });
      }

      try {
        db.prepare(
          'INSERT INTO traffic_events(reference,node_id,customer_id,bytes,month_key,created_at) VALUES(?,?,?,?,?,?)'
        ).run(reference, nodeId, customerId, bytes, monthKey, now());
      } catch (e) {
        if (String(e.message).includes('UNIQUE')) {
          return json(res, 409, { error: 'Duplicate usage reference' });
        }
        throw e;
      }

      return json(res, 201, {
        ok: true,
        measuredBytes: bytes,
        participantRemainingBytes: MONTHLY_CAP_BYTES - nodeUsed - bytes,
        customerRemainingBytes: MONTHLY_CAP_BYTES - customerUsed - bytes,
        month: monthKey,
        note: 'Counts events submitted by the trusted relay; it does not verify customer payment.'
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/admin/customers') {
      if (!isAdmin(req)) return json(res, 401, { error: 'Unauthorized' });
      const data = await body(req);
      const label = String(data.label || '').trim();
      if (!label || label.length > 80) {
        return json(res, 400, { error: 'Provide a customer label up to 80 characters' });
      }

      const id = crypto.randomUUID();
      const customerToken = crypto.randomBytes(32).toString('hex');
      db.prepare(
        'INSERT INTO customers(id,label,token_hash,created_at) VALUES(?,?,?,?)'
      ).run(id, label, hash(customerToken), now());

      return json(res, 201, {
        id, label, status: 'active', customerToken,
        warning: 'Save customerToken securely; it is shown only once.'
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/admin/analytics') {
      if (!isAdmin(req)) return json(res, 401, { error: 'Unauthorized' });

      const visits = db.prepare(
        'SELECT COUNT(*) AS total, SUM(CASE WHEN visit_day=? THEN 1 ELSE 0 END) AS today FROM page_visits'
      ).get(now().slice(0, 10));

      const registered = db.prepare(
        'SELECT COUNT(*) AS total FROM nodes'
      ).get();

      const consented = db.prepare(
        'SELECT COUNT(DISTINCT node_id) AS total FROM sharing_consents WHERE accepted_at IS NOT NULL AND revoked_at IS NULL'
      ).get();

      const reporting = db.prepare(
        'SELECT COUNT(DISTINCT node_id) AS total FROM traffic_events WHERE month_key=?'
      ).get(now().slice(0, 7));

      return json(res, 200, {
        visitsToday: Number(visits.today || 0),
        visitsTotal: Number(visits.total || 0),
        registeredParticipants: Number(registered.total || 0),
        consentedParticipants: Number(consented.total || 0),
        participantsWithTrafficThisMonth: Number(reporting.total || 0),
        distinctVerifiedIps: (() => {
          const secret = process.env.ROARNET_IP_HMAC_SECRET || '';
          if (secret.length < 32 ||
              process.env.ROARNET_PROXY_IP_HEADER_TRUSTED !== 'yes') return null;
          return Number(db.prepare(
            'SELECT COUNT(DISTINCT ip_fingerprint) AS n FROM participant_ip_fingerprints'
          ).get().n);
        })(),
        activeDistinctIps24h: (() => {
          const secret = process.env.ROARNET_IP_HMAC_SECRET || '';
          if (secret.length < 32 ||
              process.env.ROARNET_PROXY_IP_HEADER_TRUSTED !== 'yes') return null;
          const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
          return Number(db.prepare(
            'SELECT COUNT(DISTINCT ip_fingerprint) AS n FROM participant_ip_fingerprints WHERE last_seen_at >= ?'
          ).get(cutoff).n);
        })(),
        note: 'هذه أعداد سجلات وزيارات وأحداث مسجلة؛ لا تمثل عناوين IP فريدة مؤكدة أو حركة مستقلة مدققة.'
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/admin/traffic-summary') {
      if (!isAdmin(req)) return json(res, 401, { error: 'Unauthorized' });
      const monthKey = now().slice(0, 7);

      const participants = db.prepare(
        'SELECT node_id AS id, SUM(bytes) AS bytes FROM traffic_events WHERE month_key=? GROUP BY node_id'
      ).all(monthKey).map(x => ({ id: x.id, bytes: Number(x.bytes) }));

      const customers = db.prepare(
        'SELECT customer_id AS id, SUM(bytes) AS bytes FROM traffic_events WHERE month_key=? GROUP BY customer_id'
      ).all(monthKey).map(x => ({ id: x.id, bytes: Number(x.bytes) }));

      return json(res, 200, {
        month: monthKey,
        monthlyCapBytes: MONTHLY_CAP_BYTES,
        participants,
        customers,
        note: 'Usage totals are not proof of payment or independently audited traffic.'
      });
    }

    // ROARNET_SALES_V1 public catalog, authenticated checkout, and balance.
    if (req.method === 'GET' && url.pathname === '/api/store/packages') {
      const packages = db.prepare('SELECT id,name,bytes,price_cents FROM packages WHERE active=1 ORDER BY price_cents ASC').all();
      return json(res, 200, { currency: 'USD', packages: packages.map(p => ({ id: p.id, name: p.name, bytes: Number(p.bytes), priceUsd: Number((p.price_cents / 100).toFixed(2)) })) });
    }

    if (req.method === 'POST' && url.pathname === '/api/store/orders') {
      const customer = customerFor(req);
      if (!customer) return json(res, 401, { error: 'Valid customer token required' });
      const data = await body(req);
      const packageId = String(data.packageId || '');
      const pack = db.prepare('SELECT id,name,bytes,price_cents FROM packages WHERE id=? AND active=1').get(packageId);
      if (!pack) return json(res, 404, { error: 'Active package not found' });
      const id = crypto.randomUUID();
      db.prepare('INSERT INTO orders(id,customer_id,package_id,package_name,package_bytes,price_cents,created_at) VALUES(?,?,?,?,?,?,?)')
        .run(id, customer.id, pack.id, pack.name, Number(pack.bytes), Number(pack.price_cents), now());
      return json(res, 201, {
        orderId: id, status: 'pending', currency: 'USD',
        amountUsd: Number((Number(pack.price_cents) / 100).toFixed(2)),
        trafficBytes: Number(pack.bytes),
        payment: { status: 'not_configured', message: 'This order is not paid. Wait for an official payment method and verified confirmation.' }
      });
    }


    // ROARNET_USDT_INVOICES_V1
    const invoiceCreateMatch = url.pathname.match(/^\/api\/store\/orders\/([0-9a-f-]{36})\/invoice$/i);
    if (req.method === 'POST' && invoiceCreateMatch) {
      const customer = customerFor(req);
      if (!customer) return json(res, 401, { error: 'Valid customer token required' });

      const order = db.prepare(
        "SELECT id, customer_id, price_cents, status FROM orders WHERE id=? AND customer_id=?"
      ).get(invoiceCreateMatch[1], customer.id);

      if (!order) return json(res, 404, { error: 'Order not found' });
      if (order.status !== 'pending') {
        return json(res, 409, { error: 'Only pending orders can have an invoice' });
      }

      let invoice = db.prepare(
        'SELECT * FROM payment_invoices WHERE order_id=?'
      ).get(order.id);

      // ROARNET_PAYMENT_SAFETY_LOCK_V1
      // Payment verification is not implemented yet. Keep real payments disabled.
      const destination = process.env.TRON_RECEIVE_ADDRESS || '';
      const paymentVerificationReady = false;

      if (!invoice) {
        const id = crypto.randomUUID();
        const amount = (Number(order.price_cents) / 100).toFixed(2);
        const status = (destination && paymentVerificationReady)
          ? 'pending' : 'setup_required';

        db.prepare(`
          INSERT INTO payment_invoices
          (id, order_id, customer_id, amount_usdt, network, destination, status, created_at)
          VALUES (?, ?, ?, ?, 'TRC20', ?, ?, ?)
        `).run(id, order.id, customer.id, amount, destination || null, status, now());

        invoice = db.prepare('SELECT * FROM payment_invoices WHERE id=?').get(id);
      }

      if (!destination && invoice.status !== 'paid' && invoice.status !== 'expired') {
        return json(res, 200, {
          invoiceId: invoice.id,
          orderId: order.id,
          status: 'setup_required',
          currency: 'USDT',
          network: 'TRC20',
          amountUSDT: invoice.amount_usdt,
          message: 'Receiving wallet setup is required before payment.'
        });
      }

      // No automatic transition to pending: a verified TRON payment
      // verifier must be implemented before accepting real payments.
      if (!paymentVerificationReady) {
        return json(res, 200, {
          invoiceId: invoice.id,
          orderId: order.id,
          status: 'setup_required',
          currency: 'USDT',
          network: 'TRC20',
          amountUSDT: invoice.amount_usdt,
          message: 'Real payments are disabled until wallet setup and independent TRON transaction verification are implemented.'
        });
      }

      return json(res, 200, {
        invoiceId: invoice.id,
        orderId: order.id,
        status: invoice.status,
        currency: 'USDT',
        network: 'TRC20',
        amountUSDT: invoice.amount_usdt,
        destination: invoice.destination,
        message: 'Not paid until the transaction is independently verified on TRON.'
      });
    }

    const invoiceStatusMatch = url.pathname.match(/^\/api\/store\/invoices\/([0-9a-f-]{36})$/i);
    if (req.method === 'GET' && invoiceStatusMatch) {
      const customer = customerFor(req);
      if (!customer) return json(res, 401, { error: 'Valid customer token required' });

      const invoice = db.prepare(
        'SELECT id, order_id, amount_usdt, network, destination, status, created_at, paid_at FROM payment_invoices WHERE id=? AND customer_id=?'
      ).get(invoiceStatusMatch[1], customer.id);

      if (!invoice) return json(res, 404, { error: 'Invoice not found' });

      return json(res, 200, {
        invoiceId: invoice.id,
        orderId: invoice.order_id,
        currency: 'USDT',
        network: invoice.network,
        amountUSDT: invoice.amount_usdt,
        destination: invoice.destination,
        status: invoice.status,
        createdAt: invoice.created_at,
        paidAt: invoice.paid_at,
        message: invoice.status === 'paid'
          ? 'Payment recorded as paid.'
          : 'Payment has not been verified.'
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/store/me/balance') {
      const customer = customerFor(req);
      if (!customer) return json(res, 401, { error: 'Valid customer token required' });
      return json(res, 200, { customerId: customer.id, ...customerBalance(customer.id), monthlyCapBytes: MONTHLY_CAP_BYTES });
    }

    if (url.pathname.startsWith('/api/admin/')) {
      if (!isAdmin(req)) return json(res, 401, { error: 'Unauthorized' });
    } else {
      return json(res, 404, { error: 'Not found' });
    }



    // ROARNET_PROVIDER_STATUS_V1
    if (req.method === 'GET' && url.pathname === '/api/admin/provider/status') {
      const apiKey = process.env.PROXIES_SX_API_KEY || '';
      if (!apiKey) {
        return json(res, 200, {
          configured: false,
          connected: false,
          message: 'PROXIES_SX_API_KEY is not configured'
        });
      }

      try {
        const response = await fetch(
          'https://api.proxies.sx/v1/reseller/pricebook',
          {
            method: 'GET',
            headers: { 'X-API-Key': apiKey, 'Accept': 'application/json' },
            signal: AbortSignal.timeout(10000)
          }
        );

        // Do not return the provider response body or API key.
        return json(res, 200, {
          configured: true,
          connected: response.ok,
          httpStatus: response.status,
          resellerAccess: response.ok,
          message: response.ok
            ? 'Provider API accepted the key'
            : 'Provider rejected the request; verify API key and reseller access'
        });
      } catch {
        return json(res, 200, {
          configured: true,
          connected: false,
          message: 'Provider connection failed or timed out'
        });
      }
    }

    // ROARNET_SALES_V1 admin management. Confirm only after checking the payment independently.
    if (req.method === 'GET' && url.pathname === '/api/admin/packages') {
      const packages = db.prepare('SELECT id,name,bytes,price_cents,active,created_at FROM packages ORDER BY price_cents ASC').all();
      return json(res, 200, { packages: packages.map(p => ({ id: p.id, name: p.name, bytes: Number(p.bytes), priceUsd: Number((p.price_cents / 100).toFixed(2)), active: Boolean(p.active), createdAt: p.created_at })) });
    }

    if (req.method === 'POST' && url.pathname === '/api/admin/packages') {
      const data = await body(req);
      const id = String(data.id || '').trim();
      const name = String(data.name || '').trim();
      const bytes = Number(data.bytes);
      const priceUsd = Number(data.priceUsd);
      const active = data.active === true ? 1 : 0;
      if (!/^[a-z0-9_-]{3,60}$/.test(id) || !name || name.length > 100 || !Number.isSafeInteger(bytes) || bytes < 1 || bytes > MONTHLY_CAP_BYTES || !Number.isFinite(priceUsd) || priceUsd <= 0 || priceUsd > 1000000) {
        return json(res, 400, { error: 'Invalid package. bytes must be up to 150 GB; priceUsd must be positive.' });
      }
      const cents = Math.round(priceUsd * 100);
      if (!Number.isSafeInteger(cents) || cents < 1) return json(res, 400, { error: 'Invalid price precision' });
      try {
        db.prepare('INSERT INTO packages(id,name,bytes,price_cents,active,created_at) VALUES(?,?,?,?,?,?)').run(id, name, bytes, cents, active, now());
      } catch (e) {
        if (String(e.message).includes('UNIQUE')) return json(res, 409, { error: 'Package ID already exists' });
        throw e;
      }
      return json(res, 201, { id, name, bytes, priceUsd: cents / 100, active: Boolean(active) });
    }

    const packageMatch = url.pathname.match(/^\/api\/admin\/packages\/([a-z0-9_-]{3,60})$/);
    if (req.method === 'POST' && packageMatch) {
      const data = await body(req);
      const old = db.prepare('SELECT * FROM packages WHERE id=?').get(packageMatch[1]);
      if (!old) return json(res, 404, { error: 'Package not found' });
      const name = data.name === undefined ? old.name : String(data.name).trim();
      const bytes = data.bytes === undefined ? Number(old.bytes) : Number(data.bytes);
      const priceUsd = data.priceUsd === undefined ? Number(old.price_cents) / 100 : Number(data.priceUsd);
      const active = data.active === undefined ? Number(old.active) : (data.active === true ? 1 : data.active === false ? 0 : -1);
      if (!name || name.length > 100 || !Number.isSafeInteger(bytes) || bytes < 1 || bytes > MONTHLY_CAP_BYTES || !Number.isFinite(priceUsd) || priceUsd <= 0 || priceUsd > 1000000 || ![0,1].includes(active)) {
        return json(res, 400, { error: 'Invalid package fields' });
      }
      const cents = Math.round(priceUsd * 100);
      db.prepare('UPDATE packages SET name=?,bytes=?,price_cents=?,active=? WHERE id=?').run(name, bytes, cents, active, packageMatch[1]);
      return json(res, 200, { id: packageMatch[1], name, bytes, priceUsd: cents / 100, active: Boolean(active) });
    }

    if (req.method === 'GET' && url.pathname === '/api/admin/orders') {
      const orders = db.prepare(`SELECT o.id,o.customer_id,o.package_id,o.package_name,o.package_bytes,o.price_cents,o.status,o.payment_provider,o.payment_reference,o.net_cents,o.created_at,o.paid_at,c.label AS customer_label FROM orders o JOIN customers c ON c.id=o.customer_id ORDER BY o.created_at DESC LIMIT 500`).all();
      return json(res, 200, { orders: orders.map(o => ({ id: o.id, customerId: o.customer_id, customerLabel: o.customer_label, packageId: o.package_id, packageName: o.package_name, trafficBytes: Number(o.package_bytes), amountUsd: Number((o.price_cents / 100).toFixed(2)), status: o.status, paymentProvider: o.payment_provider, paymentReference: o.payment_reference, netUsd: o.net_cents === null ? null : Number((o.net_cents / 100).toFixed(2)), createdAt: o.created_at, paidAt: o.paid_at })) });
    }

    const confirmOrderMatch = url.pathname.match(/^\/api\/admin\/orders\/([0-9a-f-]{36})\/confirm-payment$/i);
    if (req.method === 'POST' && confirmOrderMatch) {
      const data = await body(req);
      const provider = String(data.provider || '').trim();
      const paymentReference = String(data.paymentReference || '').trim();
      const netUsd = Number(data.netUsd);
      if (!provider || provider.length > 60 || !/^[A-Za-z0-9_.:-]{4,120}$/.test(paymentReference) || !Number.isFinite(netUsd) || netUsd <= 0 || netUsd > 1000000) {
        return json(res, 400, { error: 'Provide provider, unique paymentReference and positive netUsd after fees' });
      }
      const netCents = Math.round(netUsd * 100);
      if (!Number.isSafeInteger(netCents) || netCents < 1) return json(res, 400, { error: 'Invalid net amount precision' });
      const order = db.prepare('SELECT * FROM orders WHERE id=?').get(confirmOrderMatch[1]);
      if (!order) return json(res, 404, { error: 'Order not found' });
      if (order.status !== 'pending') return json(res, 409, { error: 'Order is not pending' });
      if (netCents > Number(order.price_cents)) return json(res, 400, { error: 'Net revenue cannot exceed the order gross amount' });
      try {
        db.exec('BEGIN IMMEDIATE');
        const changed = db.prepare("UPDATE orders SET status='paid',payment_provider=?,payment_reference=?,net_cents=?,paid_at=? WHERE id=? AND status='pending'")
          .run(provider, paymentReference, netCents, now(), order.id);
        if (Number(changed.changes) !== 1) throw new Error('ORDER_STATE_CHANGED');
        db.prepare('INSERT INTO net_revenue(reference,net_cents,created_at) VALUES(?,?,?)')
          .run('roarnet-order-' + order.id, netCents, now());
        db.exec('COMMIT');
      } catch (e) {
        try { db.exec('ROLLBACK'); } catch {}
        if (String(e.message).includes('UNIQUE')) return json(res, 409, { error: 'Payment reference or order revenue already recorded' });
        if (e.message === 'ORDER_STATE_CHANGED') return json(res, 409, { error: 'Order state changed; reload orders' });
        throw e;
      }
      const ownerCents = Math.floor(netCents * 80 / 100);
      const participantCents = Math.floor(netCents * 15 / 100);
      const reserveCents = netCents - ownerCents - participantCents;
      return json(res, 200, {
        ok: true, orderId: order.id, status: 'paid',
        grossUsd: Number((Number(order.price_cents) / 100).toFixed(2)),
        verifiedNetUsd: Number((netCents / 100).toFixed(2)),
        ownerShare80Usd: Number((ownerCents / 100).toFixed(2)),
        participantPool15Usd: Number((participantCents / 100).toFixed(2)),
        operatingReserve5Usd: Number((reserveCents / 100).toFixed(2)),
        note: 'Manual confirmation only: use after independently verifying the funds arrived. This endpoint does not contact a payment provider or send payouts.'
      });
    }

    // ROARNET_NODE_MANAGEMENT_V1
    if (req.method === 'GET' && url.pathname === '/api/admin/nodes') {
      const rows = db.prepare(`
        SELECT n.id, n.label, n.status, n.created_at,
               COALESCE(SUM(u.bytes), 0) AS bytes,
               COUNT(u.id) AS events
        FROM nodes n
        LEFT JOIN usage_events u ON u.node_id = n.id
        GROUP BY n.id
        ORDER BY n.created_at DESC
      `).all();

      return json(res, 200, {
        nodes: rows.map(n => ({
          id: n.id,
          label: n.label,
          status: n.status,
          createdAt: n.created_at,
          reportedBytes: Number(n.bytes),
          reportedEvents: Number(n.events)
        })),
        note: 'Reported usage is not independently verified billable traffic.'
      });
    }

    const statusMatch = url.pathname.match(new RegExp('^/api/admin/nodes/([0-9a-f-]{36})/status$'));

    if (req.method === 'POST' && statusMatch) {
      const b = await body(req);
      const status = String(b.status || '');

      if (!['active', 'inactive'].includes(status)) {
        return json(res, 400, { error: 'Status must be active or inactive' });
      }

      const result = db.prepare(
        'UPDATE nodes SET status=? WHERE id=?'
      ).run(status, statusMatch[1]);

      if (Number(result.changes) !== 1) {
        return json(res, 404, { error: 'Node not found' });
      }

      return json(res, 200, { ok: true, id: statusMatch[1], status });
    }

    if (req.method === 'GET' && url.pathname === '/api/admin/summary') {
      const usage = db.prepare(
        'SELECT COALESCE(SUM(bytes),0) AS bytes, COUNT(*) AS events FROM usage_events'
      ).get();
      const nodes = db.prepare(
        "SELECT COUNT(*) AS count FROM nodes WHERE status='active'"
      ).get().count;
      const cents = db.prepare(
        'SELECT COALESCE(SUM(net_cents),0) AS cents FROM net_revenue'
      ).get().cents;

      const ownerCents = Math.floor(cents * 80 / 100);
      const participantCents = Math.floor(cents * 15 / 100);
      const reserveCents = cents - ownerCents - participantCents;

      return json(res, 200, {
        activeNodes: nodes,
        meteredBytes: Number(usage.bytes),
        usageEvents: Number(usage.events),
        recordedNetRevenueUsd: Number((cents / 100).toFixed(2)),
        ownerShare80Usd: Number((ownerCents / 100).toFixed(2)),
        participantPool15Usd: Number((participantCents / 100).toFixed(2)),
        operatingReserve5Usd: Number((reserveCents / 100).toFixed(2)),
        paidOrderCount: Number(db.prepare("SELECT COUNT(*) AS n FROM orders WHERE status='paid'").get().n),
        pendingOrderCount: Number(db.prepare("SELECT COUNT(*) AS n FROM orders WHERE status='pending'").get().n),
        note: 'Only manually verified paid orders add net revenue. This core does not yet connect to an automatic payment provider or send payouts.'
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/admin/net-revenue') {
      const b = await body(req);
      const reference = String(b.reference || '');
      const amount = Number(b.netUsd);
      if (!/^[A-Za-z0-9_-]{8,100}$/.test(reference) ||
          !Number.isFinite(amount) || amount <= 0 || amount > 1000000) {
        return json(res, 400, { error: 'Provide a unique reference and positive netUsd amount' });
      }

      const cents = Math.round(amount * 100);
      if (!Number.isSafeInteger(cents) || cents < 1) {
        return json(res, 400, { error: 'Invalid amount precision' });
      }

      try {
        db.prepare(
          'INSERT INTO net_revenue(reference,net_cents,created_at) VALUES(?,?,?)'
        ).run(reference, cents, now());
      } catch (e) {
        if (String(e.message).includes('UNIQUE')) {
          return json(res, 409, { error: 'Duplicate revenue reference' });
        }
        throw e;
      }

      const ownerCents = Math.floor(cents * 80 / 100);
      const participantCents = Math.floor(cents * 15 / 100);
      const reserveCents = cents - ownerCents - participantCents;

      return json(res, 201, {
        ok: true,
        recordedNetUsd: cents / 100,
        ownerShare80Usd: ownerCents / 100,
        participantPool15Usd: participantCents / 100,
        operatingReserve5Usd: reserveCents / 100,
        note: 'Shares are calculated from verified net revenue. This does not move money or pay users.'
      });
    }

    return json(res, 404, { error: 'Not found' });
  } catch (e) {
    if (e instanceof SyntaxError) return json(res, 400, { error: 'Invalid JSON' });
    if (e.message === 'BODY_TOO_LARGE') return json(res, 413, { error: 'Request too large' });
    console.error('Request failed:', e.message);
    return json(res, 500, { error: 'Internal server error' });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`RoarNet Independent Core listening on http://${HOST}:${PORT}`);
  console.log('Admin token is stored in .env. Do not share it.');
});

function shutdown() {
  server.close(() => {
    db.close();
    process.exit(0);
  });
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
