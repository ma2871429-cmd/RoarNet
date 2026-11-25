import http from 'node:http';
import { resolvePublicDestination } from './relay/destination-policy.mjs';
import crypto from 'node:crypto';
import { initRewardSchema, handleRewardRequest } from './rewards/reward-engine.mjs';
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
const RELAY_GATEWAY_TOKEN = process.env.RELAY_GATEWAY_TOKEN || '';
const RELAY_GATEWAY_ID = process.env.RELAY_GATEWAY_ID || '';
const SUPABASE_URL = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_PUBLISHABLE_KEY || '';
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


 // ROARNET_GLOBAL_PAYOUT_REGISTRY_V1
 db.exec(`
   CREATE TABLE IF NOT EXISTS payout_countries (
     country_code TEXT PRIMARY KEY CHECK(length(country_code) = 2),
     country_name TEXT NOT NULL,
     currency_code TEXT,
     enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
     created_at TEXT NOT NULL
   );

   CREATE TABLE IF NOT EXISTS payout_methods (
     method_id TEXT PRIMARY KEY,
     provider_name TEXT NOT NULL,
     display_name TEXT NOT NULL,
     destination_type TEXT NOT NULL,
     validation_profile TEXT NOT NULL,
     integration_status TEXT NOT NULL DEFAULT 'manual_review'
       CHECK(integration_status IN (
         'manual_review','verification_required',
         'api_configured','disabled'
       )),
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );

   CREATE TABLE IF NOT EXISTS payout_method_countries (
     method_id TEXT NOT NULL REFERENCES payout_methods(method_id),
     country_code TEXT NOT NULL REFERENCES payout_countries(country_code),
     currency_code TEXT NOT NULL,
     availability_status TEXT NOT NULL DEFAULT 'verification_required'
       CHECK(availability_status IN (
         'verification_required','available',
         'restricted','disabled'
       )),
     notes TEXT,
     created_at TEXT NOT NULL,
     PRIMARY KEY(method_id, country_code)
   );

   CREATE INDEX IF NOT EXISTS idx_payout_methods_status
     ON payout_methods(integration_status);

   CREATE INDEX IF NOT EXISTS idx_payout_country_methods
     ON payout_method_countries(country_code, availability_status);
 `);

 const registryTimestamp = new Date().toISOString();

 const addCountry = db.prepare(`
   INSERT OR IGNORE INTO payout_countries
     (country_code, country_name, currency_code, enabled, created_at)
   VALUES (?, ?, ?, 1, ?)
 `);

 addCountry.run('IQ', 'Iraq', 'IQD', registryTimestamp);
 addCountry.run('US', 'United States', 'USD', registryTimestamp);

 const addMethod = db.prepare(`
   INSERT OR IGNORE INTO payout_methods
     (method_id, provider_name, display_name, destination_type,
      validation_profile, integration_status, created_at, updated_at)
   VALUES (?, ?, ?, ?, ?, 'manual_review', ?, ?)
 `);

 const methods = [
   ['paypal', 'PayPal', 'PayPal', 'email', 'paypal_email'],
   ['usdt_trc20', 'USDT', 'USDT TRC20', 'crypto_address', 'tron_address'],
   ['zaincash', 'ZainCash', 'ZainCash', 'phone', 'iraq_mobile'],
   ['venmo', 'Venmo', 'Venmo', 'username', 'venmo_username']
 ];

 for (const m of methods) {
   addMethod.run(...m, registryTimestamp, registryTimestamp);
 }

 const addCoverage = db.prepare(`
   INSERT OR IGNORE INTO payout_method_countries
     (method_id, country_code, currency_code,
      availability_status, notes, created_at)
   VALUES (?, ?, ?, 'verification_required', ?, ?)
 `);

 addCoverage.run(
   'zaincash', 'IQ', 'IQD',
   'Local method; payout API eligibility requires verification.',
   registryTimestamp
 );
 addCoverage.run(
   'venmo', 'US', 'USD',
   'US coverage; business payout eligibility requires verification.',
   registryTimestamp
 );

 // END ROARNET_GLOBAL_PAYOUT_REGISTRY_V1

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

  CREATE TABLE IF NOT EXISTS participants (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    login_id TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
      CHECK(status IN ('active','suspended')),
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS participant_sessions (
    token_hash TEXT PRIMARY KEY,
    participant_id TEXT NOT NULL REFERENCES participants(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_participant_sessions_account
    ON participant_sessions(participant_id);

  CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    participant_id TEXT REFERENCES participants(id)
  );

  CREATE TABLE IF NOT EXISTS sharing_consents (
    node_id TEXT PRIMARY KEY REFERENCES nodes(id),
    accepted_at TEXT NOT NULL,
    revoked_at TEXT,
    disclosure_version TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS provider_consents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL REFERENCES nodes(id),
    provider TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('accepted','revoked')),
    disclosure_version TEXT NOT NULL,
    accepted_at TEXT NOT NULL,
    revoked_at TEXT,
    UNIQUE(node_id, provider)
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
    owner_share_cents INTEGER CHECK(owner_share_cents IS NULL OR owner_share_cents >= 0),
    participant_pool_cents INTEGER CHECK(participant_pool_cents IS NULL OR participant_pool_cents >= 0),
    created_at TEXT NOT NULL
  );
`);

{
  const columns = db.prepare('PRAGMA table_info(net_revenue)').all().map(c => c.name);
  if (!columns.includes('owner_share_cents')) {
    db.exec('ALTER TABLE net_revenue ADD COLUMN owner_share_cents INTEGER CHECK(owner_share_cents IS NULL OR owner_share_cents >= 0)');
  }
  if (!columns.includes('participant_pool_cents')) {
    db.exec('ALTER TABLE net_revenue ADD COLUMN participant_pool_cents INTEGER CHECK(participant_pool_cents IS NULL OR participant_pool_cents >= 0)');
  }
}

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




// ROARNET_AUTOMATIC_PARTICIPANT_DEVICE_REGISTRATION_V1
{
  const nodeColumns = db.prepare("PRAGMA table_info(nodes)").all();
  if (!nodeColumns.some(column => column.name === 'installation_id')) {
    db.exec("ALTER TABLE nodes ADD COLUMN installation_id TEXT");
  }

  db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_installation_id
    ON nodes(installation_id)
    WHERE installation_id IS NOT NULL;
  `);
}
// END ROARNET_AUTOMATIC_PARTICIPANT_DEVICE_REGISTRATION_V1

// ROARNET_PROVIDER_DEVICE_BINDINGS_V1
db.exec(`
  CREATE TABLE IF NOT EXISTS provider_device_bindings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    node_id TEXT NOT NULL REFERENCES nodes(id),
    provider_device_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK(status IN ('pending','registered','revoked')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(provider, node_id),
    UNIQUE(provider, provider_device_id)
  );

  CREATE INDEX IF NOT EXISTS idx_provider_bindings_node
    ON provider_device_bindings(node_id);

  CREATE INDEX IF NOT EXISTS idx_provider_bindings_status
    ON provider_device_bindings(provider, status);
`);
// END ROARNET_PROVIDER_DEVICE_BINDINGS_V1

// ROARNET_FIFO_ALLOCATIONS_V1
db.exec(`
  CREATE TABLE IF NOT EXISTS traffic_event_allocations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES traffic_events(id),
    order_id TEXT NOT NULL REFERENCES orders(id),
    customer_id TEXT NOT NULL REFERENCES customers(id),
    bytes INTEGER NOT NULL CHECK(bytes > 0),
    created_at TEXT NOT NULL,
    participant_id TEXT REFERENCES participants(id),
    UNIQUE(event_id, order_id)
  );

  CREATE INDEX IF NOT EXISTS idx_fifo_allocations_order
    ON traffic_event_allocations(order_id);

  CREATE INDEX IF NOT EXISTS idx_fifo_allocations_customer
    ON traffic_event_allocations(customer_id, created_at);
`);

// ROARNET_PARTICIPANT_SCHEMA_MIGRATION_V1
{
  const nodeColumns = db.prepare('PRAGMA table_info(nodes)').all().map(c => c.name);
  if (!nodeColumns.includes('participant_id')) {
    db.exec('ALTER TABLE nodes ADD COLUMN participant_id TEXT REFERENCES participants(id)');
  }

  const allocationColumns = db.prepare('PRAGMA table_info(traffic_event_allocations)').all().map(c => c.name);
  if (!allocationColumns.includes('participant_id')) {
    db.exec('ALTER TABLE traffic_event_allocations ADD COLUMN participant_id TEXT REFERENCES participants(id)');
  }
}

// ROARNET_PARTICIPANT_SCHEMA_MIGRATION_V1
{
  const nodeColumns = db.prepare('PRAGMA table_info(nodes)').all().map(c => c.name);
  if (!nodeColumns.includes('participant_id')) {
    db.exec('ALTER TABLE nodes ADD COLUMN participant_id TEXT REFERENCES participants(id)');
  }

  const allocationColumns = db.prepare('PRAGMA table_info(traffic_event_allocations)').all().map(c => c.name);
  if (!allocationColumns.includes('participant_id')) {
    db.exec('ALTER TABLE traffic_event_allocations ADD COLUMN participant_id TEXT REFERENCES participants(id)');
  }
}


// ROARNET_FIFO_EARNINGS_V1

// ROARNET_AUTOMATIC_ACCOUNTING_V1
db.exec(`
  CREATE TABLE IF NOT EXISTS participant_earning_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    allocation_id INTEGER NOT NULL UNIQUE
      REFERENCES traffic_event_allocations(id),
    event_id INTEGER NOT NULL REFERENCES traffic_events(id),
    order_id TEXT NOT NULL REFERENCES orders(id),
    participant_id TEXT REFERENCES participants(id),
    month_key TEXT NOT NULL,
    contribution_bytes INTEGER NOT NULL CHECK(contribution_bytes > 0),
    revenue_cents INTEGER NOT NULL CHECK(revenue_cents >= 0),
    pool_cents INTEGER NOT NULL CHECK(pool_cents >= 0),
    owner_share_cents INTEGER CHECK(owner_share_cents IS NULL OR owner_share_cents >= 0),
    amount_cents INTEGER NOT NULL CHECK(amount_cents >= 0),
    created_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_earning_entries_month
    ON participant_earning_entries(month_key);

  CREATE INDEX IF NOT EXISTS idx_earning_entries_participant
    ON participant_earning_entries(participant_id, month_key);
`);

{
  const columns = db.prepare('PRAGMA table_info(participant_earning_entries)').all().map(c => c.name);
  if (!columns.includes('owner_share_cents')) {
    db.exec('ALTER TABLE participant_earning_entries ADD COLUMN owner_share_cents INTEGER CHECK(owner_share_cents IS NULL OR owner_share_cents >= 0)');
  }
}


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

// ROARNET_NET_REVENUE_ORDER_LINK_V1
{
  const revenueColumns = db.prepare(
    'PRAGMA table_info(net_revenue)'
  ).all().map(c => c.name);

  if (!revenueColumns.includes('order_id')) {
    db.exec(
      'ALTER TABLE net_revenue ADD COLUMN order_id TEXT REFERENCES orders(id)'
    );
  }

  db.exec(`
    UPDATE net_revenue
    SET order_id = substr(reference, length('roarnet-order-') + 1)
    WHERE order_id IS NULL
      AND reference LIKE 'roarnet-order-%'
      AND EXISTS (
        SELECT 1 FROM orders o
        WHERE o.id = substr(
          net_revenue.reference,
          length('roarnet-order-') + 1
        )
      );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_net_revenue_order_id
      ON net_revenue(order_id)
      WHERE order_id IS NOT NULL;
  `);
}
// END ROARNET_NET_REVENUE_ORDER_LINK_V1

// ROARNET_PROVIDER_REVENUE_INTAKE_V1
// Provider receipts are recorded separately until participant allocation
// and settlement reconciliation are implemented.
db.exec(`
  CREATE TABLE IF NOT EXISTS provider_revenue_intake (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    reference TEXT NOT NULL,
    net_cents INTEGER NOT NULL CHECK(net_cents > 0),
    currency TEXT NOT NULL DEFAULT 'USD' CHECK(currency = 'USD'),
    status TEXT NOT NULL DEFAULT 'received'
      CHECK(status IN ('received','settled','rejected')),
    owner_share_cents INTEGER CHECK(owner_share_cents IS NULL OR owner_share_cents >= 0),
    participant_pool_cents INTEGER CHECK(participant_pool_cents IS NULL OR participant_pool_cents >= 0),
    created_at TEXT NOT NULL,
    UNIQUE(provider, reference)
  );

  CREATE INDEX IF NOT EXISTS idx_provider_revenue_intake_status
    ON provider_revenue_intake(status, created_at);
`);

{
  const columns = db.prepare('PRAGMA table_info(provider_revenue_intake)').all().map(c => c.name);
  if (!columns.includes('owner_share_cents')) {
    db.exec('ALTER TABLE provider_revenue_intake ADD COLUMN owner_share_cents INTEGER CHECK(owner_share_cents IS NULL OR owner_share_cents >= 0)');
  }
  if (!columns.includes('participant_pool_cents')) {
    db.exec('ALTER TABLE provider_revenue_intake ADD COLUMN participant_pool_cents INTEGER CHECK(participant_pool_cents IS NULL OR participant_pool_cents >= 0)');
  }
}
// END ROARNET_PROVIDER_REVENUE_INTAKE_V1

// ROARNET_PRIMARY_OWNER_IDENTITY_V1
db.exec(`
  CREATE TABLE IF NOT EXISTS project_owner (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    owner_id TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role = 'owner'),
    owner_share_percent INTEGER NOT NULL
      CHECK(owner_share_percent = 50),
    created_at TEXT NOT NULL
  );

  INSERT OR IGNORE INTO project_owner (
    singleton, owner_id, display_name, role,
    owner_share_percent, created_at
  ) VALUES (
    1, 'roarnet-primary-owner',
    'RoarNet Project Owner', 'owner',
    50, CURRENT_TIMESTAMP
  );
`);

{
  const ownerSchema = db.prepare(
    "SELECT sql FROM sqlite_master WHERE type='table' AND name='project_owner'"
  ).get()?.sql || '';

  if (/owner_share_percent\s*=\s*80/i.test(ownerSchema)) {
    db.exec('BEGIN IMMEDIATE');
    try {
      db.exec(`
        CREATE TABLE project_owner_new (
          singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
          owner_id TEXT NOT NULL UNIQUE,
          display_name TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role = 'owner'),
          owner_share_percent INTEGER NOT NULL CHECK(owner_share_percent = 50),
          created_at TEXT NOT NULL
        );
        INSERT INTO project_owner_new(
          singleton, owner_id, display_name, role, owner_share_percent, created_at
        )
        SELECT singleton, owner_id, display_name, role, 50, created_at
        FROM project_owner;
        DROP TABLE project_owner;
        ALTER TABLE project_owner_new RENAME TO project_owner;
      `);
      db.exec('COMMIT');
    } catch (error) {
      try { db.exec('ROLLBACK'); } catch {}
      throw error;
    }
  }

  db.prepare(`
    INSERT OR IGNORE INTO project_owner(
      singleton, owner_id, display_name, role, owner_share_percent, created_at
    ) VALUES(1, 'roarnet-primary-owner', 'RoarNet Project Owner', 'owner', 50, CURRENT_TIMESTAMP)
  `).run();
}

const providerIntakeColumns = db.prepare(
  'PRAGMA table_info(provider_revenue_intake)'
).all().map(column => column.name);

if (!providerIntakeColumns.includes('owner_id')) {
  db.exec(`
    ALTER TABLE provider_revenue_intake
    ADD COLUMN owner_id TEXT NOT NULL
    DEFAULT 'roarnet-primary-owner';
  `);
}
// END ROARNET_PRIMARY_OWNER_IDENTITY_V1

// ROARNET_PROVIDER_MONTHLY_SETTLEMENT_V1
// Independent monthly accounting for verified provider receipts.
db.exec(`
  CREATE TABLE IF NOT EXISTS provider_settlement_batches (
    month_key TEXT PRIMARY KEY,
    receipt_count INTEGER NOT NULL CHECK(receipt_count > 0),
    revenue_cents INTEGER NOT NULL CHECK(revenue_cents > 0),
    owner_share_cents INTEGER NOT NULL CHECK(owner_share_cents >= 0),
    participant_pool_cents INTEGER NOT NULL CHECK(participant_pool_cents >= 0),
    allocated_cents INTEGER NOT NULL DEFAULT 0 CHECK(allocated_cents >= 0),
    unallocated_cents INTEGER NOT NULL CHECK(unallocated_cents >= 0),
    operating_reserve_cents INTEGER NOT NULL CHECK(operating_reserve_cents >= 0),
    status TEXT NOT NULL DEFAULT 'completed'
      CHECK(status IN ('completed')),
    created_at TEXT NOT NULL
  );
`);
// END ROARNET_PROVIDER_MONTHLY_SETTLEMENT_V1




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

initRewardSchema(db);

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
  const m = (req.headers.authorization || '').match(/^Bearer ([A-Za-z0-9._~-]+)$/i);
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


function makeParticipantPasswordHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(password, salt, 64).toString('hex');
}

function verifyParticipantPassword(password, stored) {
  try {
    const parts = String(stored).split(':');
    if (parts.length !== 2) return false;
    const actual = crypto.scryptSync(password, parts[0], 64);
    const expected = Buffer.from(parts[1], 'hex');
    return actual.length === expected.length &&
      crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

async function participantFor(req) {
  const user = await supabaseUserFor(req);
  if (!user) return null;

  let participant = db.prepare(
    "SELECT id,label,login_id FROM participants WHERE auth_user_id=? AND status='active'"
  ).get(user.id);

  if (!participant) {
    const email = String(user.email || '').trim().toLowerCase();
    const emailConfirmed = Boolean(user.email_confirmed_at || user.confirmed_at);

    if (email && emailConfirmed) {
      const existing = db.prepare(
        "SELECT id,auth_user_id FROM participants WHERE login_id=? COLLATE NOCASE"
      ).get(email);

      if (existing && existing.auth_user_id && existing.auth_user_id !== user.id) {
        return null;
      }

      if (existing && !existing.auth_user_id) {
        db.prepare(
          "UPDATE participants SET auth_user_id=? WHERE id=? AND auth_user_id IS NULL"
        ).run(user.id, existing.id);
      }

      participant = db.prepare(
        "SELECT id,label,login_id FROM participants WHERE auth_user_id=? AND status='active'"
      ).get(user.id);
    }
  }

  if (!participant) {
    const id = crypto.randomUUID();
    const email = String(user.email || '').trim().toLowerCase();
    const label = (email.split('@')[0] || 'RoarNet User').slice(0, 80);
    const loginId = `supabase-${user.id}@roarnet.local`;
    const passwordHash = makeParticipantPasswordHash(
      crypto.randomBytes(48).toString('hex')
    );

    try {
      db.prepare(
        "INSERT INTO participants(id,label,login_id,password_hash,status,created_at,auth_user_id) VALUES(?,?,?,?, 'active',?,?)"
      ).run(id, label, loginId, passwordHash, now(), user.id);
    } catch (error) {
      if (!String(error.message).includes('UNIQUE')) throw error;
    }

    participant = db.prepare(
      "SELECT id,label,login_id FROM participants WHERE auth_user_id=? AND status='active'"
    ).get(user.id);
  }

  return participant || null;
}

async function supabaseUserFor(req) {
  const token = bearer(req);
  if (!token) return null;
  if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
    throw new Error('SUPABASE_NOT_CONFIGURED');
  }

  const response = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    method: 'GET',
    headers: {
      apikey: SUPABASE_ANON_KEY,
      Authorization: `Bearer ${token}`
    },
    signal: AbortSignal.timeout(12000)
  });

  if (!response.ok) return null;
  const user = await response.json();
  if (!user || typeof user.id !== 'string' || !user.id) return null;
  return user;
}


// ROARNET_ACCOUNT_DEVICE_AUTH_V1
async function participantDeviceFor(req, deviceId) {
  const participant = await participantFor(req);
  if (!participant) {
    return { error: 'PARTICIPANT_SESSION_INVALID' };
  }

  const id = String(deviceId || '').trim();
  if (!id) return { error: 'DEVICE_ID_REQUIRED' };

  const device = db.prepare(`
    SELECT id,label,status,participant_id
    FROM nodes
    WHERE id=? AND participant_id=? AND status='active'
  `).get(id, participant.id);

  if (!device) return { error: 'DEVICE_NOT_OWNED' };

  return { participant, device };
}

const participantLoginAttempts = new Map();

function customerBalance(customerId) {
  const purchased = Number(db.prepare("SELECT COALESCE(SUM(package_bytes),0) AS n FROM orders WHERE customer_id=? AND status='paid'").get(customerId).n);
  const used = Number(db.prepare('SELECT COALESCE(SUM(bytes),0) AS n FROM traffic_events WHERE customer_id=?').get(customerId).n);
  return { purchasedBytes: purchased, usedBytes: used, remainingBytes: Math.max(0, purchased - used) };
}

function recordTrafficEventWithFifo({reference, nodeId, customerId, bytes, monthKey}) {
  db.exec('BEGIN IMMEDIATE');

  try {
    const duplicate = db.prepare(
      'SELECT id FROM traffic_events WHERE reference=?'
    ).get(reference);

    if (duplicate) throw new Error('DUPLICATE_USAGE_REFERENCE');

    const node = db.prepare(
      "SELECT id, participant_id FROM nodes WHERE id=? AND status='active'"
    ).get(nodeId);

    const customer = db.prepare(
      "SELECT id FROM customers WHERE id=? AND status='active'"
    ).get(customerId);

    const consent = db.prepare(
      'SELECT node_id FROM sharing_consents WHERE node_id=? AND revoked_at IS NULL'
    ).get(nodeId);

    if (!node || !customer) throw new Error('INACTIVE_NODE_OR_CUSTOMER');
    if (!consent) throw new Error('PARTICIPANT_CONSENT_REQUIRED');

    const balance = customerBalance(customerId);
    if (bytes > balance.remainingBytes) {
      throw new Error('INSUFFICIENT_PREPAID_BALANCE');
    }

    const nodeUsed = Number(db.prepare(
      'SELECT COALESCE(SUM(bytes),0) AS n FROM traffic_events WHERE node_id=? AND month_key=?'
    ).get(nodeId, monthKey).n);

    const customerUsed = Number(db.prepare(
      'SELECT COALESCE(SUM(bytes),0) AS n FROM traffic_events WHERE customer_id=? AND month_key=?'
    ).get(customerId, monthKey).n);

    if (bytes > MONTHLY_CAP_BYTES - nodeUsed) {
      throw new Error('NODE_MONTHLY_CAP_REACHED');
    }

    if (bytes > MONTHLY_CAP_BYTES - customerUsed) {
      throw new Error('CUSTOMER_MONTHLY_CAP_REACHED');
    }

    const eventResult = db.prepare(
      'INSERT INTO traffic_events(reference,node_id,customer_id,bytes,month_key,created_at) VALUES(?,?,?,?,?,?)'
    ).run(reference, nodeId, customerId, bytes, monthKey, now());

    const eventId = Number(eventResult.lastInsertRowid);

    const orders = db.prepare(`
      SELECT o.id, o.package_bytes, o.net_cents,
        COALESCE((
          SELECT SUM(a.bytes)
          FROM traffic_event_allocations a
          WHERE a.order_id=o.id
        ),0) AS allocated_bytes
      FROM orders o
      WHERE o.customer_id=? AND o.status='paid'
      ORDER BY COALESCE(o.paid_at,o.created_at) ASC, o.created_at ASC, o.id ASC
    `).all(customerId);

    let remaining = bytes;

    const insertAllocation = db.prepare(
      'INSERT INTO traffic_event_allocations(event_id,order_id,customer_id,bytes,created_at,participant_id) VALUES(?,?,?,?,?,?)'
    );

    const insertEarningEntry = db.prepare(`
      INSERT INTO participant_earning_entries(
        allocation_id,event_id,order_id,participant_id,month_key,
        contribution_bytes,revenue_cents,pool_cents,owner_share_cents,amount_cents,created_at
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
    `);

    for (const order of orders) {
      if (remaining === 0) break;

      const capacity = Math.max(
        0,
        Number(order.package_bytes) - Number(order.allocated_bytes)
      );

      if (capacity === 0) continue;

      const allocated = Math.min(remaining, capacity);

      if (!Number.isSafeInteger(Number(order.net_cents)) || Number(order.net_cents) <= 0) {
        throw new Error('PAID_ORDER_MISSING_VERIFIED_NET_REVENUE');
      }

      const packageBytes = BigInt(order.package_bytes);
      const previousBytes = BigInt(order.allocated_bytes);
      const allocatedBytes = BigInt(allocated);
      const cumulativeBytes = previousBytes + allocatedBytes;
      const netCents = BigInt(order.net_cents);

      if (packageBytes <= 0n || cumulativeBytes > packageBytes) {
        throw new Error('INVALID_ORDER_ALLOCATION_TOTAL');
      }

      const previousRevenue = (netCents * previousBytes) / packageBytes;
      const cumulativeRevenue = (netCents * cumulativeBytes) / packageBytes;
      const revenueDelta = cumulativeRevenue - previousRevenue;

      const previousPool = (netCents * 50n * previousBytes) / (100n * packageBytes);
      const cumulativePool = (netCents * 50n * cumulativeBytes) / (100n * packageBytes);
      const poolDelta = cumulativePool - previousPool;

      const ownerDelta = revenueDelta - poolDelta;
      const participantId = node.participant_id ?? null;
      const amountCents = participantId ? poolDelta : 0n;

      for (const value of [revenueDelta, poolDelta, ownerDelta, amountCents]) {
        if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
          throw new Error('ACCOUNTING_AMOUNT_OUT_OF_SAFE_RANGE');
        }
      }

      const allocationResult = insertAllocation.run(
        eventId, order.id, customerId, allocated, now(), participantId
      );

      insertEarningEntry.run(
        Number(allocationResult.lastInsertRowid),
        eventId,
        order.id,
        participantId,
        monthKey,
        allocated,
        Number(revenueDelta),
        Number(poolDelta),
        Number(ownerDelta),
        Number(amountCents),
        now()
      );

      remaining -= allocated;
    }

    if (remaining !== 0) {
      throw new Error('FIFO_ALLOCATION_INCOMPLETE');
    }

    db.exec('COMMIT');

    return {
      eventId,
      nodeUsed: nodeUsed + bytes,
      customerUsed: customerUsed + bytes
    };
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch {}
    throw e;
  }
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

// Keep the account identity column available in every database used by this server.
{
  const participantColumns = db.prepare('PRAGMA table_info(participants)').all();
  if (!participantColumns.some(column => column.name === 'auth_user_id')) {
    db.exec('ALTER TABLE participants ADD COLUMN auth_user_id TEXT');
  }
  db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_participants_auth_user_id
    ON participants(auth_user_id)
    WHERE auth_user_id IS NOT NULL
  `);
}


// ROARNET_RELAY_SESSIONS_V1
db.exec(`
  CREATE TABLE IF NOT EXISTS relay_sessions (
    session_id TEXT PRIMARY KEY,
    idempotency_key TEXT UNIQUE,

    provider_id TEXT,
    buyer_request_id TEXT,

    participant_id TEXT REFERENCES participants(id),
    node_id TEXT NOT NULL REFERENCES nodes(id),
    device_id TEXT NOT NULL,

    customer_id TEXT NOT NULL REFERENCES customers(id),
    order_id TEXT NOT NULL REFERENCES orders(id),

    destination_host TEXT,
    destination_port INTEGER
      CHECK(destination_port IS NULL OR destination_port BETWEEN 1 AND 65535),
    protocol TEXT NOT NULL DEFAULT 'tcp'
      CHECK(protocol IN ('tcp','udp')),

    status TEXT NOT NULL DEFAULT 'PENDING'
      CHECK(status IN (
        'PENDING','AUTHORIZED','CONNECTING','ACTIVE',
        'CLOSING','COMPLETED','REJECTED','EXPIRED','FAILED'
      )),

    session_token_hash TEXT UNIQUE,

    created_at TEXT NOT NULL,
    expires_at TEXT,
    started_at TEXT,
    ended_at TEXT,
    updated_at TEXT NOT NULL,

    bytes_sent INTEGER NOT NULL DEFAULT 0 CHECK(bytes_sent >= 0),
    bytes_received INTEGER NOT NULL DEFAULT 0 CHECK(bytes_received >= 0),
    total_bytes INTEGER NOT NULL DEFAULT 0
      CHECK(total_bytes = bytes_sent + bytes_received),
    sequence_number INTEGER NOT NULL DEFAULT 0 CHECK(sequence_number >= 0),

    agent_report_hash TEXT,
    gateway_report_hash TEXT,
    provider_report_reference TEXT UNIQUE,

    agent_report_json TEXT,
    gateway_report_json TEXT,
    provider_report_json TEXT,

    reconciliation_status TEXT NOT NULL DEFAULT 'pending'
      CHECK(reconciliation_status IN (
        'pending','matched','mismatch','rejected'
      )),

    gateway_id TEXT,
    failure_code TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_relay_sessions_node_status
    ON relay_sessions(node_id, status);

  CREATE INDEX IF NOT EXISTS idx_relay_sessions_customer_status
    ON relay_sessions(customer_id, status);

  CREATE INDEX IF NOT EXISTS idx_relay_sessions_participant_status
    ON relay_sessions(participant_id, status);

  CREATE INDEX IF NOT EXISTS idx_relay_sessions_expiry
    ON relay_sessions(status, expires_at);

  CREATE INDEX IF NOT EXISTS idx_relay_sessions_buyer_request
    ON relay_sessions(buyer_request_id);
`);


// ROARNET_BUYER_REQUESTS_V1
db.exec(`
  CREATE TABLE IF NOT EXISTS buyer_requests (
    buyer_request_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    customer_id TEXT NOT NULL REFERENCES customers(id),
    order_id TEXT NOT NULL REFERENCES orders(id),
    destination_host TEXT NOT NULL,
    destination_port INTEGER NOT NULL
      CHECK(destination_port BETWEEN 1 AND 65535),
    protocol TEXT NOT NULL DEFAULT 'tcp'
      CHECK(protocol = 'tcp'),
    request_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending_provider_assignment'
      CHECK(status IN (
        'pending_provider_assignment',
        'provider_accepted',
        'assigned',
        'completed',
        'cancelled',
        'expired',
        'failed',
        'rejected'
      )),
    provider_id TEXT,
    provider_reference TEXT UNIQUE,
    decision_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_buyer_requests_customer_status
    ON buyer_requests(customer_id, status);

  CREATE INDEX IF NOT EXISTS idx_buyer_requests_order
    ON buyer_requests(order_id);

  CREATE INDEX IF NOT EXISTS idx_buyer_requests_expiry
    ON buyer_requests(status, expires_at);
`);

// ROARNET_RELAY_SESSION_EXPIRY_V1
function expirePendingRelaySessions() {
  const timestamp = now();

  try {
    const result = db.prepare(`
      UPDATE relay_sessions
      SET status = 'EXPIRED',
          ended_at = ?,
          updated_at = ?,
          failure_code = 'SESSION_EXPIRED'
      WHERE status IN ('PENDING','AUTHORIZED')
        AND expires_at IS NOT NULL
        AND expires_at <= ?
    `).run(timestamp, timestamp, timestamp);

    db.prepare(`
      UPDATE buyer_requests
      SET status = 'expired',
          updated_at = ?
      WHERE status IN (
        'pending_provider_assignment',
        'provider_accepted',
        'assigned'
      )
      AND EXISTS (
        SELECT 1
        FROM relay_sessions rs
        WHERE rs.buyer_request_id = buyer_requests.buyer_request_id
          AND rs.status = 'EXPIRED'
      )
    `).run(timestamp);

    if (Number(result.changes) > 0) {
      console.log(
        '[RoarNet relay] Expired sessions:',
        Number(result.changes)
      );
    }
  } catch (error) {
    console.error('[RoarNet relay expiry]', error.message);
  }
}

expirePendingRelaySessions();

const relaySessionExpiryTimer = setInterval(
  expirePendingRelaySessions,
  30 * 1000
);

if (typeof relaySessionExpiryTimer.unref === 'function') {
  relaySessionExpiryTimer.unref();
}
// END ROARNET_RELAY_SESSION_EXPIRY_V1




const server = http.createServer(async (req, res) => {
  // ROARNET_REWARD_ENGINE_V1
  if (await handleRewardRequest(req, res, { db, participantFor })) return;

  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);




    // ROARNET_RELAY_SESSION_API_V1

    if (req.method === 'GET' &&
        url.pathname === '/api/participant/relay-sessions') {
      const participant = await participantFor(req);
      if (!participant) {
        return json(res, 401, { error: 'Invalid participant session' });
      }

      const sessions = db.prepare(`
        SELECT session_id, node_id, customer_id, order_id,
          protocol, status, created_at, expires_at,
          started_at, ended_at, bytes_sent, bytes_received,
          total_bytes, reconciliation_status, failure_code
        FROM relay_sessions
        WHERE participant_id = ?
        ORDER BY created_at DESC
        LIMIT 100
      `).all(participant.id);

      return json(res, 200, { sessions });
    }

    if (req.method === 'GET' &&
        url.pathname.startsWith('/api/participant/relay-sessions/')) {
      const participant = await participantFor(req);
      if (!participant) {
        return json(res, 401, { error: 'Invalid participant session' });
      }

      const sessionId = decodeURIComponent(
        url.pathname.slice('/api/participant/relay-sessions/'.length)
      );

      const session = db.prepare(`
        SELECT session_id, node_id, customer_id, order_id,
          destination_host, destination_port, protocol, status,
          created_at, expires_at, started_at, ended_at,
          bytes_sent, bytes_received, total_bytes,
          reconciliation_status, failure_code
        FROM relay_sessions
        WHERE session_id = ? AND participant_id = ?
      `).get(sessionId, participant.id);

      if (!session) {
        return json(res, 404, { error: 'Session not found' });
      }

      return json(res, 200, { session });
    }

    if (req.method === 'POST' &&
        url.pathname === '/api/relay/sessions') {
      return json(res, 503, {
        error: 'PROVIDER_INTEGRATION_UNAVAILABLE',
        message: 'Relay session creation is paused until an approved provider is integrated.'
      });

      const customer = customerFor(req);
      if (!customer) {
        return json(res, 401, { error: 'Invalid customer credentials' });
      }

      const data = await body(req);

      const nodeId = String(data.nodeId || '').trim();
      const deviceId = String(data.deviceId || '').trim();
      const orderId = String(data.orderId || '').trim();
      const destinationHost = String(data.destinationHost || '')
        .trim().toLowerCase();
      const destinationPort = Number(data.destinationPort);
      const protocol = String(data.protocol || 'tcp').toLowerCase();
      const idempotencyKey = String(data.idempotencyKey || '').trim();

      if (!/^[0-9a-f-]{36}$/i.test(nodeId) ||
          deviceId !== nodeId ||
          !/^[0-9a-f-]{36}$/i.test(orderId)) {
        return json(res, 400, { error: 'Invalid node, device, or order ID' });
      }

      if (!/^[A-Za-z0-9_-]{16,100}$/.test(idempotencyKey)) {
        return json(res, 400, { error: 'A valid idempotencyKey is required' });
      }

      const isIPv6Literal =
        destinationHost.includes(':') &&
        /^[0-9a-f:]+$/i.test(destinationHost);

      if (!/^[a-z0-9.-]{1,253}$/.test(destinationHost) &&
          !isIPv6Literal) {
        return json(res, 400, { error: 'Invalid destination hostname' });
      }

      if (!Number.isInteger(destinationPort) ||
          destinationPort < 1 || destinationPort > 65535 ||
          protocol !== 'tcp') {
        return json(res, 400, { error: 'Only valid TCP destinations are accepted' });
      }

      try {
        await resolvePublicDestination(destinationHost);
      } catch (error) {
        const invalidHost = error.message === 'INVALID_DESTINATION_HOST';
        return json(res, invalidHost ? 400 : 403, {
          error: 'DESTINATION_NOT_ALLOWED',
          reason: error.message
        });
      }

      const existing = db.prepare(`
        SELECT session_id, customer_id, buyer_request_id,
          status, created_at, expires_at
        FROM relay_sessions
        WHERE idempotency_key = ?
      `).get(idempotencyKey);

      if (existing) {
        if (existing.customer_id !== customer.id) {
          return json(res, 409, { error: 'IDEMPOTENCY_KEY_ALREADY_USED' });
        }

        delete existing.customer_id;
        return json(res, 200, {
          reused: true,
          session: existing
        });
      }

      db.exec('BEGIN IMMEDIATE');

      try {
        const node = db.prepare(`
          SELECT id, participant_id
          FROM nodes
          WHERE id = ? AND status = 'active'
        `).get(nodeId);

        if (!node || !node.participant_id) {
          db.exec('ROLLBACK');
          return json(res, 403, { error: 'ACTIVE_PARTICIPANT_DEVICE_REQUIRED' });
        }

        const consent = db.prepare(`
          SELECT node_id
          FROM sharing_consents
          WHERE node_id = ?
            AND revoked_at IS NULL
            AND disclosure_version = 'roarnet-sharing-v1'
        `).get(nodeId);

        if (!consent) {
          db.exec('ROLLBACK');
          return json(res, 403, { error: 'CURRENT_SHARING_CONSENT_REQUIRED' });
        }

        const order = db.prepare(`
          SELECT o.id, o.package_bytes, o.net_cents
          FROM orders o
          WHERE o.id = ?
            AND o.customer_id = ?
            AND o.status = 'paid'
            AND o.net_cents IS NOT NULL
            AND o.net_cents > 0
        `).get(orderId, customer.id);

        if (!order) {
          db.exec('ROLLBACK');
          return json(res, 403, { error: 'VERIFIED_PAID_ORDER_REQUIRED' });
        }

        const allocated = Number(db.prepare(`
          SELECT COALESCE(SUM(bytes), 0) AS total
          FROM traffic_event_allocations
          WHERE order_id = ?
        `).get(orderId).total || 0);

        if (!Number.isSafeInteger(allocated) ||
            allocated >= Number(order.package_bytes)) {
          db.exec('ROLLBACK');
          return json(res, 409, { error: 'ORDER_TRAFFIC_CAPACITY_EXHAUSTED' });
        }

        const sessionId = crypto.randomUUID();
        const buyerRequestId = crypto.randomUUID();
        const timestamp = now();
        const expiresAt = new Date(
          Date.now() + 10 * 60 * 1000
        ).toISOString();

        const requestPayload = JSON.stringify({
          customerId: customer.id,
          orderId: order.id,
          destinationHost,
          destinationPort,
          protocol: 'tcp'
        });

        const requestHash = crypto
          .createHash('sha256')
          .update(requestPayload)
          .digest('hex');

        db.prepare(`
          INSERT INTO buyer_requests (
            buyer_request_id, idempotency_key,
            customer_id, order_id,
            destination_host, destination_port,
            protocol, request_hash, status,
            created_at, updated_at, expires_at
          ) VALUES (?, ?, ?, ?, ?, ?, 'tcp', ?,
                    'pending_provider_assignment', ?, ?, ?)
        `).run(
          buyerRequestId,
          idempotencyKey,
          customer.id,
          order.id,
          destinationHost,
          destinationPort,
          requestHash,
          timestamp,
          timestamp,
          expiresAt
        );

        db.prepare(`
          INSERT INTO relay_sessions (
            session_id, idempotency_key, buyer_request_id,
            participant_id, node_id, device_id,
            customer_id, order_id,
            destination_host, destination_port, protocol,
            status, created_at, expires_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'tcp',
                    'PENDING', ?, ?, ?)
        `).run(
          sessionId,
          idempotencyKey,
          buyerRequestId,
          node.participant_id,
          node.id,
          deviceId,
          customer.id,
          order.id,
          destinationHost,
          destinationPort,
          timestamp,
          expiresAt,
          timestamp
        );

        db.exec('COMMIT');

        return json(res, 202, {
          success: true,
          buyerRequest: {
            buyerRequestId,
            status: 'pending_provider_assignment',
            createdAt: timestamp,
            expiresAt
          },
          session: {
            sessionId,
            status: 'PENDING',
            protocol: 'tcp',
            createdAt: timestamp,
            expiresAt
          },
          providerAssignmentReady: false,
          trafficForwarding: false
        });

      } catch (error) {
        try { db.exec('ROLLBACK'); } catch {}

        if (String(error.message).includes('UNIQUE')) {
          const duplicate = db.prepare(`
            SELECT session_id, customer_id, status, created_at, expires_at
            FROM relay_sessions
            WHERE idempotency_key = ?
          `).get(idempotencyKey);

          if (duplicate) {
            if (duplicate.customer_id !== customer.id) {
              return json(res, 409, { error: 'IDEMPOTENCY_KEY_ALREADY_USED' });
            }

            delete duplicate.customer_id;
            return json(res, 200, {
              reused: true,
              session: duplicate
            });
          }
        }

        throw error;
      }
    }


    if (req.method === 'POST' &&
        url.pathname.startsWith('/api/participant/relay-sessions/') &&
        url.pathname.endsWith('/cancel')) {
      const participant = await participantFor(req);
      if (!participant) {
        return json(res, 401, { error: 'Invalid participant session' });
      }

      const prefix = '/api/participant/relay-sessions/';
      const sessionId = decodeURIComponent(
        url.pathname.slice(prefix.length, -'/cancel'.length)
      );

      if (!sessionId || sessionId.includes('/')) {
        return json(res, 400, { error: 'Invalid session ID' });
      }

      const timestamp = now();

      db.exec('BEGIN IMMEDIATE');

      try {
        const session = db.prepare(`
          SELECT session_id, status
          FROM relay_sessions
          WHERE session_id = ? AND participant_id = ?
        `).get(sessionId, participant.id);

        if (!session) {
          db.exec('ROLLBACK');
          return json(res, 404, { error: 'Session not found' });
        }

        if (session.status === 'REJECTED') {
          db.exec('COMMIT');
          return json(res, 200, {
            success: true,
            status: 'REJECTED',
            alreadyCancelled: true
          });
        }

        if (!['PENDING', 'AUTHORIZED'].includes(session.status)) {
          db.exec('ROLLBACK');
          return json(res, 409, {
            error: 'SESSION_CANNOT_BE_CANCELLED_IN_CURRENT_STATE',
            status: session.status
          });
        }

        db.prepare(`
          UPDATE relay_sessions
          SET status = 'REJECTED',
              ended_at = ?,
              updated_at = ?,
              failure_code = 'PARTICIPANT_CANCELLED'
          WHERE session_id = ?
            AND participant_id = ?
            AND status IN ('PENDING','AUTHORIZED')
        `).run(timestamp, timestamp, sessionId, participant.id);

        db.prepare(`
          UPDATE buyer_requests
          SET status = 'rejected',
              updated_at = ?
          WHERE buyer_request_id = (
            SELECT buyer_request_id
            FROM relay_sessions
            WHERE session_id = ?
          )
          AND status IN (
            'pending_provider_assignment',
            'provider_accepted',
            'assigned'
          )
        `).run(timestamp, sessionId);

        db.exec('COMMIT');

        return json(res, 200, {
          success: true,
          status: 'REJECTED',
          trafficForwarding: false
        });

      } catch (error) {
        try { db.exec('ROLLBACK'); } catch {}
        throw error;
      }
    }



    // ROARNET_RELAY_GATEWAY_NEXT_V1
    if (req.method === 'POST' &&
        url.pathname === '/api/relay/gateway/next') {
      return json(res, 503, {
        error: 'PROVIDER_INTEGRATION_UNAVAILABLE',
        message: 'No active provider integration is approved for RoarNet.'
      });


      const supplied = bearer(req);

      if (RELAY_GATEWAY_TOKEN.length < 32 || !supplied) {
        return json(res, 503, { error: 'GATEWAY_AUTH_NOT_CONFIGURED' });
      }

      const actual = Buffer.from(hash(supplied));
      const expected = Buffer.from(hash(RELAY_GATEWAY_TOKEN));

      if (actual.length !== expected.length ||
          !crypto.timingSafeEqual(actual, expected)) {
        return json(res, 401, { error: 'INVALID_GATEWAY_CREDENTIALS' });
      }

      if (RELAY_GATEWAY_ID.length < 3) {
        return json(res, 503, { error: 'GATEWAY_ID_NOT_CONFIGURED' });
      }

      const data = await body(req);
      const gatewayId = String(data.gatewayId || '');
      const deviceId = String(data.deviceId || '');

      if (gatewayId !== RELAY_GATEWAY_ID) {
        return json(res, 403, { error: 'GATEWAY_IDENTITY_MISMATCH' });
      }

      if (!/^[0-9a-f-]{36}$/i.test(deviceId)) {
        return json(res, 400, { error: 'INVALID_DEVICE_ID' });
      }

      const timestamp = now();

      db.exec('BEGIN IMMEDIATE');

      try {
        expirePendingRelaySessions();

        const assignment = db.prepare(`
          SELECT
            rs.session_id,
            rs.node_id,
            rs.device_id,
            rs.customer_id,
            rs.order_id,
            rs.destination_host,
            rs.destination_port,
            rs.protocol,
            rs.expires_at,
            rs.provider_id,
            rs.buyer_request_id
          FROM relay_sessions rs
          JOIN nodes n ON n.id = rs.node_id
          JOIN sharing_consents sc
            ON sc.node_id = rs.node_id
          JOIN provider_consents pc
            ON pc.node_id = rs.node_id
            AND pc.provider = rs.provider_id
            AND pc.status = 'accepted'
            AND pc.revoked_at IS NULL
            AND pc.disclosure_version = CASE rs.provider_id
              WHEN 'proxies_sx' THEN 'roarnet-proxies-sx-v1'
              WHEN 'honeygain' THEN 'roarnet-honeygain-v1'
              ELSE ''
            END
          JOIN orders o
            ON o.id = rs.order_id
          WHERE rs.device_id = ?
            AND rs.node_id = ?
            AND rs.status = 'PENDING'
            AND rs.expires_at > ?
            AND rs.provider_id IS NOT NULL
            AND rs.buyer_request_id IS NOT NULL
            AND (rs.gateway_id IS NULL OR rs.gateway_id = ?)
            AND n.status = 'active'
            AND sc.revoked_at IS NULL
            AND sc.disclosure_version = 'roarnet-sharing-v1'
            AND o.status = 'paid'
            AND o.net_cents > 0
            AND NOT EXISTS (
              SELECT 1
              FROM relay_sessions other
              WHERE other.order_id = rs.order_id
                AND other.session_id != rs.session_id
                AND other.status IN (
                  'AUTHORIZED','CONNECTING','ACTIVE','CLOSING'
                )
            )
          ORDER BY rs.created_at ASC
          LIMIT 1
        `).get(deviceId, deviceId, timestamp, gatewayId);

        if (!assignment) {
          db.exec('COMMIT');
          return json(res, 200, {
            success: true,
            assignment: null,
            reason: 'NO_VERIFIED_BUYER_ASSIGNMENT',
            trafficForwarding: false
          });
        }

        const result = db.prepare(`
          UPDATE relay_sessions
          SET status = 'AUTHORIZED',
              gateway_id = ?,
              updated_at = ?
          WHERE session_id = ?
            AND status = 'PENDING'
            AND expires_at > ?
            AND (gateway_id IS NULL OR gateway_id = ?)
        `).run(
          gatewayId,
          timestamp,
          assignment.session_id,
          timestamp,
          gatewayId
        );

        if (Number(result.changes) !== 1) {
          db.exec('ROLLBACK');
          return json(res, 409, { error: 'SESSION_ASSIGNMENT_CONFLICT' });
        }

        db.prepare(`
          UPDATE buyer_requests
          SET status = 'assigned',
              updated_at = ?
          WHERE buyer_request_id = ?
            AND status IN (
              'pending_provider_assignment',
              'provider_accepted',
              'assigned'
            )
        `).run(timestamp, assignment.buyer_request_id);

        db.exec('COMMIT');

        return json(res, 200, {
          success: true,
          assignment,
          status: 'AUTHORIZED',
          trafficForwarding: false
        });

      } catch (error) {
        try { db.exec('ROLLBACK'); } catch {}
        throw error;
      }
    }
    // END ROARNET_RELAY_GATEWAY_NEXT_V1

    // ROARNET_RELAY_GATEWAY_TRANSITIONS_V1
    if (req.method === 'POST' &&
        url.pathname.startsWith('/api/relay/gateway/sessions/') &&
        url.pathname.endsWith('/transition')) {

      const supplied = bearer(req);

      if (RELAY_GATEWAY_TOKEN.length < 32 || !supplied) {
        return json(res, 503, { error: 'GATEWAY_AUTH_NOT_CONFIGURED' });
      }

      const actual = Buffer.from(hash(supplied));
      const expected = Buffer.from(hash(RELAY_GATEWAY_TOKEN));

      if (actual.length !== expected.length ||
          !crypto.timingSafeEqual(actual, expected)) {
        return json(res, 401, { error: 'INVALID_GATEWAY_CREDENTIALS' });
      }

      const prefix = '/api/relay/gateway/sessions/';
      let sessionId;

      try {
        sessionId = decodeURIComponent(
          url.pathname.slice(prefix.length, -'/transition'.length)
        );
      } catch {
        return json(res, 400, { error: 'INVALID_SESSION_ID' });
      }

      if (!sessionId || sessionId.includes('/') || sessionId.length > 100) {
        return json(res, 400, { error: 'INVALID_SESSION_ID' });
      }

      const data = await body(req);
      const target = String(data.targetStatus || '').toUpperCase();
      const gatewayId = String(data.gatewayId || '').trim();
      const reportHash = String(data.reportHash || '').toLowerCase();
      const failureCode = String(data.failureCode || '').trim();

      if (!/^[A-Za-z0-9._-]{3,80}$/.test(gatewayId)) {
        return json(res, 400, { error: 'INVALID_GATEWAY_ID' });
      }

      if (RELAY_GATEWAY_ID.length < 3 ||
          gatewayId !== RELAY_GATEWAY_ID) {
        return json(res, 403, {
          error: 'GATEWAY_IDENTITY_MISMATCH'
        });
      }

      const allowed = {
        PENDING: ['AUTHORIZED', 'REJECTED', 'FAILED'],
        AUTHORIZED: ['CONNECTING', 'REJECTED', 'FAILED'],
        CONNECTING: ['ACTIVE', 'FAILED'],
        ACTIVE: ['CLOSING', 'FAILED'],
        CLOSING: ['COMPLETED', 'FAILED']
      };

      if (!Object.hasOwn(allowed, target) &&
          !Object.values(allowed).some(states => states.includes(target))) {
        return json(res, 400, { error: 'INVALID_TARGET_STATUS' });
      }

      if (target === 'COMPLETED' &&
          !/^[a-f0-9]{64}$/.test(reportHash)) {
        return json(res, 400, { error: 'VALID_GATEWAY_REPORT_HASH_REQUIRED' });
      }

      if (target === 'ACTIVE' && data.connected !== true) {
        return json(res, 400, { error: 'GATEWAY_CONNECTION_CONFIRMATION_REQUIRED' });
      }

      if (target === 'FAILED' &&
          !/^[A-Z0-9_-]{3,64}$/.test(failureCode)) {
        return json(res, 400, { error: 'VALID_FAILURE_CODE_REQUIRED' });
      }

      const timestamp = now();

      db.exec('BEGIN IMMEDIATE');

      try {
        const session = db.prepare(`
          SELECT session_id, status, provider_id, buyer_request_id,
                 gateway_id, device_id, started_at, ended_at
          FROM relay_sessions
          WHERE session_id = ?
        `).get(sessionId);

        if (!session) {
          db.exec('ROLLBACK');
          return json(res, 404, { error: 'SESSION_NOT_FOUND' });
        }

        const isIdempotentReplay =
          session.status === target &&
          session.gateway_id === gatewayId;

        if (!isIdempotentReplay &&
            !(allowed[session.status] || []).includes(target)) {
          db.exec('ROLLBACK');
          return json(res, 409, {
            error: 'INVALID_SESSION_STATE_TRANSITION',
            currentStatus: session.status,
            requestedStatus: target
          });
        }

        if (session.gateway_id && session.gateway_id !== gatewayId) {
          db.exec('ROLLBACK');
          return json(res, 403, { error: 'GATEWAY_SESSION_OWNERSHIP_MISMATCH' });
        }

        if (target === 'AUTHORIZED' &&
            (!session.provider_id || !session.buyer_request_id)) {
          db.exec('ROLLBACK');
          return json(res, 409, {
            error: 'VERIFIED_BUYER_ASSIGNMENT_REQUIRED'
          });
        }

        const agentReport = data.agentReport;
        const agentReportHash = String(
          data.agentReportHash || ''
        ).toLowerCase();

        let agentReportJson = null;

        if (agentReport !== undefined) {
          if (
            !['FAILED', 'COMPLETED'].includes(target) ||
            !agentReport ||
            typeof agentReport !== 'object' ||
            Array.isArray(agentReport) ||
            agentReport.reportVersion !== 1 ||
            agentReport.sessionId !== sessionId ||
            agentReport.deviceId !== session.device_id ||
            ![agentReport.bytesSent, agentReport.bytesReceived,
              agentReport.totalBytes].every(
                value => Number.isSafeInteger(value) && value >= 0
              ) ||
            !Number.isSafeInteger(
              agentReport.bytesSent + agentReport.bytesReceived
            ) ||
            agentReport.bytesSent + agentReport.bytesReceived !==
              agentReport.totalBytes ||
            !/^[a-f0-9]{64}$/.test(agentReportHash)
          ) {
            db.exec('ROLLBACK');
            return json(res, 400, {
              error: 'INVALID_AGENT_TRAFFIC_REPORT'
            });
          }

          const expectedAgentHash = crypto.createHash('sha256')
            .update(JSON.stringify(agentReport), 'utf8')
            .digest('hex');

          if (expectedAgentHash !== agentReportHash) {
            db.exec('ROLLBACK');
            return json(res, 400, {
              error: 'AGENT_REPORT_HASH_MISMATCH'
            });
          }

          agentReportJson = JSON.stringify({
            ...agentReport,
            reportHash: agentReportHash,
            gatewayId,
            receivedAt: timestamp
          });
        }

        const gatewayReport = data.gatewayReport;

        if (target === 'COMPLETED') {
          if (
            !agentReport ||
            !gatewayReport ||
            typeof gatewayReport !== 'object' ||
            Array.isArray(gatewayReport) ||
            gatewayReport.reportVersion !== 1 ||
            gatewayReport.sessionId !== sessionId ||
            gatewayReport.deviceId !== session.device_id ||
            gatewayReport.gatewayId !== gatewayId ||
            gatewayReport.agentReportHash !== agentReportHash ||
            gatewayReport.bytesSent !== agentReport.bytesSent ||
            gatewayReport.bytesReceived !== agentReport.bytesReceived ||
            gatewayReport.totalBytes !== agentReport.totalBytes
          ) {
            db.exec('ROLLBACK');
            return json(res, 400, {
              error: 'GATEWAY_AGENT_REPORT_MISMATCH'
            });
          }

          const expectedGatewayHash = crypto.createHash('sha256')
            .update(JSON.stringify(gatewayReport), 'utf8')
            .digest('hex');

          if (expectedGatewayHash !== reportHash) {
            db.exec('ROLLBACK');
            return json(res, 400, {
              error: 'GATEWAY_REPORT_HASH_MISMATCH'
            });
          }
        }

        if (isIdempotentReplay) {
          db.exec('COMMIT');
          return json(res, 200, {
            success: true,
            reused: true,
            sessionId,
            status: target
          });
        }

        const reportJson = target === 'COMPLETED'
          ? JSON.stringify({
              gatewayId,
              reportHash,
              receivedAt: timestamp,
              gatewayReport
            })
          : null;

        const result = db.prepare(`
          UPDATE relay_sessions
          SET status = ?,
              updated_at = ?,
              gateway_id = ?,
              started_at = CASE
                WHEN ? = 'ACTIVE' THEN COALESCE(started_at, ?)
                ELSE started_at
              END,
              ended_at = CASE
                WHEN ? IN ('COMPLETED','FAILED','REJECTED')
                  THEN COALESCE(ended_at, ?)
                ELSE ended_at
              END,
              gateway_report_hash = COALESCE(?, gateway_report_hash),
              gateway_report_json = COALESCE(?, gateway_report_json),
              agent_report_hash = COALESCE(?, agent_report_hash),
              agent_report_json = COALESCE(?, agent_report_json),
              bytes_sent = COALESCE(?, bytes_sent),
              bytes_received = COALESCE(?, bytes_received),
              total_bytes = COALESCE(?, total_bytes),
              reconciliation_status = CASE
                WHEN ? = 'COMPLETED' THEN 'pending'
                ELSE reconciliation_status
              END,
              failure_code = COALESCE(?, failure_code)
          WHERE session_id = ? AND status = ?
        `).run(
          target,
          timestamp,
          gatewayId,
          target,
          timestamp,
          target,
          timestamp,
          target === 'COMPLETED' ? reportHash : null,
          reportJson,
          agentReport ? agentReportHash : null,
          agentReportJson,
          agentReport ? agentReport.bytesSent : null,
          agentReport ? agentReport.bytesReceived : null,
          agentReport ? agentReport.totalBytes : null,
          target,
          target === 'FAILED' ? failureCode : null,
          sessionId,
          session.status
        );

        if (Number(result.changes) !== 1) {
          db.exec('ROLLBACK');
          return json(res, 409, { error: 'SESSION_TRANSITION_CONFLICT' });
        }

        const buyerRequestStatus = {
          AUTHORIZED: 'assigned',
          COMPLETED: 'completed',
          FAILED: 'failed',
          REJECTED: 'rejected'
        }[target];

        if (buyerRequestStatus && session.buyer_request_id) {
          db.prepare(`
            UPDATE buyer_requests
            SET status = ?,
                updated_at = ?
            WHERE buyer_request_id = ?
              AND status IN (
                'pending_provider_assignment',
                'provider_accepted',
                'assigned'
              )
          `).run(
            buyerRequestStatus,
            timestamp,
            session.buyer_request_id
          );
        }

        db.exec('COMMIT');

        return json(res, 200, {
          success: true,
          sessionId,
          previousStatus: session.status,
          status: target,
          reconciliationStatus:
            target === 'COMPLETED' ? 'pending' : undefined
        });

      } catch (error) {
        try { db.exec('ROLLBACK'); } catch {}
        throw error;
      }
    }
    // END ROARNET_RELAY_GATEWAY_TRANSITIONS_V1


    // END ROARNET_RELAY_SESSION_API_V1

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
      const page = String.raw`<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#101827">
<title>RoarNet | بوابتك للإنترنت</title>
<style>
:root {
  color-scheme: dark;
  --bg: #080e19;
  --panel: #111c2d;
  --panel2: #16243a;
  --line: #293b53;
  --text: #edf5ff;
  --muted: #9dafc7;
  --accent: #54e0bb;
  --blue: #76a9ff;
  --radius: 20px;
}
* { box-sizing: border-box; }
html { min-height: 100%; scroll-behavior: smooth; }
body {
  margin: 0;
  min-height: 100vh;
  background:
    radial-gradient(ellipse at 85% 0%, #123c3b66 0%, transparent 36%),
    radial-gradient(ellipse at 0% 20%, #1b376044 0%, transparent 34%),
    var(--bg);
  color: var(--text);
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  line-height: 1.65;
}
header {
  max-width: 1120px;
  margin: 0 auto;
  padding: 32px 20px 18px;
  text-align: center;
}
.logo {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  color: var(--accent);
  font-size: clamp(30px, 5vw, 44px);
  font-weight: 900;
  letter-spacing: -1.5px;
  text-shadow: 0 0 32px #54e0bb20;
}
.logo::before {
  content: "♌";
  display: grid;
  place-items: center;
  width: 44px;
  height: 44px;
  border: 1px solid #54e0bb66;
  border-radius: 15px;
  background: #54e0bb12;
  font-size: 26px;
}
header p {
  margin: 8px 0 0;
  color: var(--muted);
  font-size: 14px;
}
main {
  width: min(1120px, calc(100% - 28px));
  margin: 0 auto 48px;
}
#publicStats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
  gap: 12px;
  margin: 18px 0 24px;
}
.card, #publicStats > div {
  min-width: 0;
  padding: 19px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: linear-gradient(145deg, #17253aee, #0f1929f5);
  box-shadow: 0 12px 32px #00000018;
}
#publicStats > div {
  color: var(--muted);
  font-size: 13px;
}
#publicStats strong, #publicStats b {
  display: block;
  color: var(--accent);
  font-size: 25px;
  line-height: 1.4;
  overflow-wrap: anywhere;
}
nav {
  display: flex;
  flex-wrap: wrap;
  gap: 9px;
  padding: 9px;
  margin: 0 0 18px;
  border: 1px solid var(--line);
  border-radius: 18px;
  background: #0e1726e8;
  position: sticky;
  top: 8px;
  z-index: 5;
  backdrop-filter: blur(14px);
}
button {
  min-height: 43px;
  padding: 10px 16px;
  border: 1px solid #36516a;
  border-radius: 12px;
  background: #1a2a40;
  color: var(--text);
  font: inherit;
  font-weight: 700;
  cursor: pointer;
  transition: border-color .18s, background .18s, transform .18s;
}
button:hover {
  border-color: var(--accent);
  transform: translateY(-1px);
}
button:focus-visible, input:focus-visible, select:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 3px;
}
.tab { flex: 1 1 130px; }
.tab.active {
  color: #071b19;
  background: linear-gradient(120deg, var(--accent), #8af0d5);
  border-color: transparent;
}
.panel { display: none; }
.panel.active { display: block; animation: appear .2s ease-out; }
@keyframes appear {
  from { opacity: .6; transform: translateY(4px); }
  to { opacity: 1; transform: translateY(0); }
}
h1, h2, h3 { color: var(--text); line-height: 1.35; }
h2 { font-size: clamp(20px, 3vw, 27px); margin: 4px 0 18px; }
h3 { font-size: 17px; margin: 0 0 12px; }
p { overflow-wrap: anywhere; }
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 260px), 1fr));
  gap: 14px;
  align-items: start;
}
.grid > * { min-width: 0; }
.actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
  margin: 14px 0;
}
input, select, textarea {
  display: block;
  width: 100%;
  min-width: 0;
  margin: 7px 0 13px;
  padding: 12px 13px;
  border: 1px solid #344961;
  border-radius: 12px;
  background: #091321;
  color: var(--text);
  font: inherit;
}
input::placeholder, textarea::placeholder { color: #8295ae; }
label {
  display: block;
  color: #c6d4e7;
  font-size: 13px;
  font-weight: 650;
}
.status {
  margin: 12px 0;
  padding: 12px 14px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: #0a1422;
  overflow-wrap: anywhere;
}
.good { color: var(--accent); }
.warn { color: #ffd28a; }
hr { border: 0; border-top: 1px solid var(--line); margin: 20px 0; }
table {
  display: block;
  width: 100%;
  overflow-x: auto;
  border-collapse: collapse;
}
th, td {
  padding: 11px 13px;
  border-bottom: 1px solid var(--line);
  text-align: start;
  white-space: nowrap;
}
th { color: var(--accent); background: #17253a; }
footer {
  padding: 24px 16px 35px;
  color: var(--muted);
  text-align: center;
  font-size: 12px;
}
a { color: var(--blue); }
button:disabled { opacity: .55; cursor: not-allowed; transform: none; }
@media (max-width: 600px) {
  header { padding-top: 24px; }
  main { width: min(100% - 20px, 1120px); }
  nav { top: 4px; gap: 6px; padding: 7px; }
  .tab { flex: 1 1 100px; padding: 9px 8px; font-size: 13px; }
  .card, #publicStats > div { padding: 15px; border-radius: 16px; }
  #publicStats { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 9px; }
  .actions > button { flex: 1 1 130px; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    scroll-behavior: auto !important;
    animation-duration: .01ms !important;
    transition-duration: .01ms !important;
  }
}
</style>

<style id="roarnet-independent-pro-design">
/* ROARNET_INDEPENDENT_PRO_DESIGN_V1 */

:root {
  --bg: #040d19;
  --panel: #0a1c30;
  --panel2: #102941;
  --line: #1b5068;
  --text: #effaff;
  --muted: #9bb7c9;
  --accent: #13dfd0;
  --blue: #13b7d8;
  --radius: 19px;
  color-scheme: dark;
}

html {
  scroll-behavior: smooth;
  background: var(--bg);
}

body {
  background:
    radial-gradient(ellipse at 50% -15%, #123c50 0%, transparent 48%),
    linear-gradient(160deg, #040d19, #07182a 60%, #04101f) !important;
  color: var(--text) !important;
}

header {
  max-width: 1120px;
  padding: 30px 18px 22px;
}

.logo {
  color: var(--accent) !important;
  font-weight: 900;
  letter-spacing: .3px;
  text-shadow: 0 0 22px #13dfd044;
}

.logo::before {
  content: "" !important;
  width: 52px !important;
  height: 52px !important;
  border: 0 !important;
  border-radius: 15px !important;
  background-color: transparent !important;
  background-image: url("data:image/png;base64,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") !important;
  background-position: center !important;
  background-size: contain !important;
  background-repeat: no-repeat !important;
  filter:
    drop-shadow(0 0 5px #13dfd0)
    drop-shadow(0 0 13px #13b7d8aa);
}

header p {
  color: var(--muted) !important;
}

main {
  max-width: 1120px;
}

.card,
#publicStats > div,
.panel {
  border: 1px solid var(--line) !important;
  border-radius: var(--radius) !important;
  background: linear-gradient(145deg, #102b43, #091a2d) !important;
  box-shadow: 0 10px 28px #0005;
}

.card,
#publicStats > div {
  transition: border-color .2s, transform .2s, box-shadow .2s;
}

.card:hover,
#publicStats > div:hover {
  border-color: var(--accent) !important;
  box-shadow: 0 0 20px #13dfd01c;
}

#publicStats {
  gap: 13px !important;
}

#publicStats strong,
#publicStats b {
  color: var(--accent) !important;
  font-weight: 900;
  font-variant-numeric: tabular-nums;
}

nav {
  gap: 9px;
  margin: 16px auto 22px;
}

.tab {
  border: 1px solid var(--line) !important;
  border-radius: 12px !important;
  background: #0a1c30 !important;
  color: var(--muted) !important;
  font-weight: 750;
}

.tab.active {
  border-color: var(--accent) !important;
  background: #0c3448 !important;
  color: var(--accent) !important;
  box-shadow: 0 0 15px #13dfd018;
}

.panel {
  padding: 20px !important;
}

h1, h2, h3 {
  color: var(--text);
  font-weight: 850;
}

h2 {
  letter-spacing: -.3px;
}

.grid {
  gap: 13px !important;
}

.actions {
  gap: 10px;
}

button {
  min-height: 42px;
  border: 1px solid #28566c !important;
  border-radius: 12px !important;
  background: #102b43 !important;
  color: var(--text) !important;
  font-weight: 800;
  transition: filter .2s, transform .2s, border-color .2s;
}

button:hover {
  border-color: var(--accent) !important;
  filter: brightness(1.12);
}

button:active {
  transform: scale(.98);
}

button.primary {
  border-color: #13b7d8 !important;
  background: linear-gradient(110deg, #087e99, #087f83) !important;
  color: white !important;
}

button:disabled {
  opacity: .55;
}

input,
select,
textarea {
  min-height: 44px;
  border: 1px solid #28566c !important;
  border-radius: 11px !important;
  background: #071a2b !important;
  color: var(--text) !important;
  padding: 10px 12px !important;
}

input:focus,
select:focus,
textarea:focus {
  outline: none !important;
  border-color: var(--accent) !important;
  box-shadow: 0 0 0 3px #13dfd022;
}

input::placeholder,
textarea::placeholder {
  color: #7895a9 !important;
}

label {
  color: var(--muted);
  font-weight: 700;
}

.status {
  border-radius: 11px;
  overflow-wrap: anywhere;
}

.good {
  color: #13dfb0 !important;
}

.warn {
  color: #ffc66d !important;
}

table {
  border-collapse: separate;
  border-spacing: 0;
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: 13px;
}

th {
  background: #102b43 !important;
  color: var(--accent) !important;
}

th, td {
  border-color: #1b4058 !important;
  padding: 11px;
}

a {
  color: var(--accent);
}

hr {
  border-color: var(--line);
}

footer {
  color: var(--muted);
  border-top: 1px solid var(--line);
  padding: 22px 12px;
}

#maintenanceBotReport {
  overflow-wrap: anywhere;
}

#roarnet-adsterra-banner {
  border-radius: 12px;
}

@media (max-width: 600px) {
  header {
    padding: 23px 12px 16px;
  }

  main {
    width: calc(100% - 22px);
  }

  .panel {
    padding: 15px !important;
  }

  .card,
  #publicStats > div {
    padding: 15px;
  }

  .grid {
    gap: 10px !important;
  }

  nav {
    gap: 6px;
  }

  .tab {
    padding: 9px 11px;
    font-size: 12px;
  }

  .actions > button {
    flex: 1 1 130px;
  }
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    scroll-behavior: auto !important;
    transition: none !important;
    animation: none !important;
  }
}

/* END ROARNET_INDEPENDENT_PRO_DESIGN_V1 */
</style>

</head>
<body>
<header><div class="logo">RoarNet</div><p>بوابتك لإدارة الباقات ومشاركة الإنترنت</p></header>
<section class="card" id="publicStats" style="max-width:980px;margin:14px auto;padding:14px">
<h3 style="margin-top:0">إحصائيات RoarNet</h3>
<div class="grid">
<div class="card"><small>المشاركون المسجلون</small><strong id="publicParticipants">—</strong></div>
<div class="card"><small>موافقات المشاركة النشطة</small><strong id="publicConsented">—</strong></div>
<div class="card"><small>الزيارات المسجلة</small><strong id="publicVisits">—</strong></div>
<div class="card"><small>عناوين IP المميزة</small><strong id="publicIps">—</strong></div>
<div class="card"><small>عناوين IP النشطة خلال 24 ساعة</small><strong id="publicIps24h">—</strong></div>
</div>
<small id="publicStatsNote">جارٍ تحميل الإحصائيات...</small>
</section>
<main>
<nav>
<button class="tab active" data-tab="store">شراء الإنترنت</button>
<button class="tab" data-tab="share">مشاركة الإنترنت</button>
<button class="tab" data-tab="admin">لوحة الإدارة</button>
</nav>

<section id="store" class="panel active">
<h2>شراء الإنترنت</h2>
<p>تصفح الباقات المتاحة، وتابع رصيدك وطلباتك باستخدام رمز حساب العميل.</p>
<div class="card">
<label for="customerToken">رمز حساب العميل</label>
<input id="customerToken" type="password" autocomplete="off" placeholder="أدخل رمز العميل">
<div class="actions">
<button class="primary" id="loadPackages">عرض الباقات</button>
<button id="loadBalance">عرض رصيدي</button>
</div>
<small>يُستخدم الرمز في الجلسة الحالية فقط ولا يُحفظ تلقائياً.</small>
</div>
<h3>الباقات المتاحة</h3>
<div id="packages" class="grid"><div class="card muted">اضغط «عرض الباقات» لتحميل الباقات المفعّلة.</div></div>
<div id="balance" class="status">رصيد العميل يظهر هنا بعد التحقق من الرمز.</div>
<div id="storeStatus" class="status" aria-live="polite">جاهز.</div>
</section>

<section id="share" class="panel">
<h2>مشاركة الإنترنت والربح</h2>
<p>تقدر تبدأ من هنا بطلب تسجيل مشارك، باستخدام رمز الإدارة لإنشاء سجل مشارك.</p>
<div class="card">
<p>يُستخدم رمز الإدارة المُدخل في لوحة الإدارة لتسجيل المشارك.</p>
<label for="nodeLabel">اسم المشارك أو الجهاز</label>
<input id="nodeLabel" maxlength="80" placeholder="مثال: جهاز البيت">
<button class="primary" id="registerNode">تسجيل المشارك</button>
<div id="shareStatus" class="status" aria-live="polite">لم يتم تسجيل مشارك بعد.</div>
</div>
<div class="status warn">حالة الخدمة: التسجيل الإداري متاح إذا كان الخادم مهيأً. محرك نقل الإنترنت الفعلي وقياس الاستهلاك المستقل والدفع التلقائي للمشاركين لم تكتمل بعد؛ لذلك لا توجد أرباح فعلية مضمونة من هذه الواجهة حالياً.</div>
</section>

<section id="admin" class="panel">
<h2>لوحة الإدارة</h2>
<p>أدخل رمز الإدارة للوصول إلى ملخص الخادم والطلبات والمشاركين. الرمز يبقى في ذاكرة الصفحة فقط.</p>
<div class="card">
<label for="adminToken">رمز الإدارة</label>
<input id="adminToken" type="password" autocomplete="off" placeholder="ADMIN_TOKEN">
<div class="actions">
<button class="primary" id="loadAdmin">تحميل الملخص</button>
<button id="loadOrders">عرض الطلبات</button>
<button id="loadNodes">عرض المشاركين</button>
</div>
</div>
<div class="grid">
<div class="card"><small>العقد النشطة</small><strong id="activeNodes">—</strong></div>
<div class="card"><small>صافي الإيراد المسجل بالدولار</small><strong id="revenue">—</strong></div>
<div class="card"><small>طلبات مدفوعة</small><strong id="paidOrders">—</strong></div>
<div class="card"><small>طلبات معلّقة</small><strong id="pendingOrders">—</strong></div>
</div>
<h3>إحصائيات الزيارات والمشاركة</h3>
<div class="grid">
<div class="card"><small>الزيارات اليوم</small><strong id="visitsToday">—</strong></div>
<div class="card"><small>إجمالي الزيارات المسجلة</small><strong id="visitsTotal">—</strong></div>
<div class="card"><small>المشاركون المسجلون</small><strong id="registeredParticipants">—</strong></div>
<div class="card"><small>موافقات المشاركة النشطة</small><strong id="consentedParticipants">—</strong></div>
<div class="card"><small>مشاركون لديهم حركة مسجلة هذا الشهر</small><strong id="trafficParticipants">—</strong></div>
<div class="card"><small>عناوين IP المميزة المسجلة</small><strong id="distinctIps">—</strong></div>
<div class="card"><small>عناوين IP النشطة خلال 24 ساعة</small><strong id="activeIps24h">—</strong></div>
</div>
<button type="button" id="loadAnalytics">تحديث إحصائيات الزيارات والمشاركة</button>
<div id="analyticsStatus" class="status" aria-live="polite">لم يتم تحميل الإحصائيات.</div>


<section class="card" id="maintenanceBot">
  <h3>بوت صيانة RoarNet</h3>
  <p>يفحص مسارات الإدارة المتاحة ويعرض تشخيصاً أولياً للاتصال.</p>
  <button class="primary" id="runMaintenanceBot" type="button">تشغيل فحص الصيانة</button>
  <div class="status" id="maintenanceBotStatus" aria-live="polite">جاهز للفحص.</div>
  <pre id="maintenanceBotReport" style="white-space:pre-wrap;overflow-wrap:anywhere"></pre>
</section>

<div id="adminStatus" class="status" aria-live="polite">لم يتم تحميل البيانات.</div>

<h3>إدارة الباقات</h3>
<div class="card">
  <label>اسم الباقة</label><input id="pkgName" placeholder="مثلاً باقة 5GB">
  <label>الحجم بالـ GB</label><input id="pkgGb" type="number" min="0.01" step="0.01" value="5">
  <label>السعر بالدولار</label><input id="pkgPrice" type="number" min="0" step="0.01" value="3">
  <button type="button" id="fillDefaults">تعبئة البيانات الافتراضية</button>
  <button id="createPackage">إنشاء باقة</button>
  <button id="loadAdminPackages">تحديث الباقات</button>
  <p id="packageStatus"></p>
</div>
<div id="packageManager" class="grid"></div>

<h3>الطلبات</h3><div id="orders" class="grid"></div>
<h3>المشاركون</h3><div id="nodes" class="grid"></div>
<hr>
<h3>إنشاء حساب عميل</h3>
<p>يتطلب صلاحية الإدارة؛ يظهر رمز العميل مرة واحدة، انسخه واحفظه بمكان آمن.</p>
<label for="customerLabel">اسم العميل</label>
<input id="customerLabel" maxlength="80" placeholder="اسم أو وصف الحساب">
<button id="createCustomer">إنشاء حساب عميل</button>
<div id="newCustomer" class="status" aria-live="polite"></div>
</section>

<footer>RoarNet Independent Core · واجهة تجريبية مرتبطة بالخادم المحلي</footer>
</main>
<script>
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function say(id,msg){$(id).textContent=msg}
async function loadPublicStats(){
  try {
    const r = await api('/api/public/stats');
    $('publicParticipants').textContent = r.registeredParticipants;
    $('publicConsented').textContent = r.consentedParticipants;
    $('publicVisits').textContent = r.totalVisits;
    $('publicIps').textContent = r.distinctIps ?? 'غير متاح';
    $('publicIps24h').textContent = r.activeIps24h ?? 'غير متاح';
    $('publicStatsNote').textContent = r.note;
  } catch {
    $('publicStatsNote').textContent = 'تعذر تحميل الإحصائيات حالياً.';
  }
}

async function api(path,{token='',method='GET',data}={}){
  const headers={Accept:'application/json'};
  if(token) headers.Authorization='Bearer '+token;
  if(data!==undefined) headers['Content-Type']='application/json';
  const response=await fetch(path,{method,headers,body:data===undefined?undefined:JSON.stringify(data),cache:'no-store'});
  let result;try{result=await response.json()}catch{result={error:'استجابة غير مفهومة من الخادم'}}
  if(!response.ok) throw new Error(result.error||('HTTP '+response.status));
  return result;
}

// ROARNET_SAFE_AUTOFILL_V1
// Defaults are convenience values only; secrets and balances are never fabricated.
function applyRoarNetDefaults(){
  const defaults = {
    nodeLabel: 'RoarNet Home Node',
    customerLabel: 'RoarNet Customer',
    pkgName: 'RoarNet Starter 5GB',
    pkgGb: '5',
    pkgPrice: '3'
  };

  for (const [id, value] of Object.entries(defaults)) {
    const field = $(id);
    if (field && !field.value.trim()) field.value = value;
  }

  const customerToken = $('customerToken');
  const adminTokenField = $('adminToken');

  if (customerToken) customerToken.setAttribute('autocomplete', 'off');
  if (adminTokenField) adminTokenField.setAttribute('autocomplete', 'off');
}

applyRoarNetDefaults();

document.querySelectorAll('input[type="number"]').forEach(field => {
  field.addEventListener('input', () => {
    if (field.value === '') return;
    const value = Number(field.value);
    if (!Number.isFinite(value)) field.setCustomValidity('أدخل رقماً صالحاً.');
    else if (field.min !== '' && value < Number(field.min))
      field.setCustomValidity('القيمة أقل من الحد المسموح.');
    else if (field.max !== '' && value > Number(field.max))
      field.setCustomValidity('القيمة أعلى من الحد المسموح.');
    else field.setCustomValidity('');
  });
});

// END ROARNET_SAFE_AUTOFILL_V1

loadPublicStats();
document.querySelectorAll('[data-tab]').forEach(button=>button.addEventListener('click',()=>{
  document.querySelectorAll('[data-tab]').forEach(b=>b.classList.toggle('active',b===button));
  document.querySelectorAll('section.panel').forEach(p=>p.classList.toggle('active',p.id===button.dataset.tab));
}));
$('loadPackages').onclick=async()=>{
  $('loadPackages').disabled=true;
  try{
    const result=await api('/api/store/packages');
    const list=result.packages||[];
    $('packages').innerHTML=list.length?list.map(p=>\`<article class="card"><strong>\${esc(p.name)}</strong><p>\${(Number(p.bytes)/1e9).toFixed(2)} GB</p><p>$\${Number(p.priceUsd).toFixed(2)}</p><button class="primary" data-buy="\${esc(p.id)}">إنشاء طلب</button></article>\`).join(''):'<div class="card">لا توجد باقات مفعّلة حالياً.</div>';
    $('packages').querySelectorAll('[data-buy]').forEach(button=>button.onclick=async()=>{
      const token=$('customerToken').value.trim();
      if(!token){say('storeStatus','أدخل رمز حساب العميل أولاً.');return}
      button.disabled=true;
      try {
        const order = await api('/api/store/orders', {
          method: 'POST', token, data: { packageId: button.dataset.buy }
        });
        const orderId = order.orderId || order.id;
        if (!orderId) throw new Error('الخادم لم يرجع رقم الطلب');

        let message = 'تم إنشاء الطلب: ' + orderId +
          '\\nالحالة: ' + (order.status || 'pending') +
          '\\nالمبلغ: $' + Number(order.amountUsd || 0).toFixed(2);

        try {
          const invoice = await api('/api/store/orders/' +
            encodeURIComponent(orderId) + '/invoice', { method: 'POST', token });

          message += '\n\nفاتورة الدفع: ' + (invoice.status || 'غير محددة') +
            '\nالمبلغ المطلوب: ' + (invoice.amountUSDT || 'غير متاح') + ' USDT' +
            '\nالشبكة: ' + (invoice.network || 'TRC20');

          if (invoice.destination) {
            message += '\nعنوان الاستقبال: ' + invoice.destination;
          }
          if (invoice.message) message += '\n' + invoice.message;
          message += '\n\nلا يُعد الطلب مدفوعاً إلا بعد التحقق الفعلي من المعاملة.';
        } catch (invoiceError) {
          message += '\nتعذّر تجهيز الفاتورة: ' + invoiceError.message +
            '\nالطلب ما زال بانتظار الدفع والتحقق.';
        }

        say('storeStatus', message);
      } catch (e) {
        say('storeStatus', 'تعذّر إنشاء الطلب: ' + e.message);
      } finally {
        button.disabled = false;
      }
    });
    say('storeStatus','تم تحميل '+list.length+' باقة متاحة.');
  }catch(e){say('storeStatus','تعذّر تحميل الباقات: '+e.message)}
  finally{$('loadPackages').disabled=false}
};
$('loadBalance').onclick=async()=>{
  const token=$('customerToken').value.trim();
  if(!token){say('balance','أدخل رمز العميل أولاً.');return}
  try{const b=await api('/api/store/me/balance',{token});
    $('balance').textContent='الرصيد المشتَرى: '+(Number(b.purchasedBytes||0)/1e9).toFixed(3)+' GB\nالمستهلك المسجل: '+(Number(b.usedBytes||0)/1e9).toFixed(3)+' GB\nالمتبقي: '+(Number(b.remainingBytes||0)/1e9).toFixed(3)+' GB\nالسقف الشهري: 150 GB';
  }catch(e){say('balance','تعذّر جلب الرصيد: '+e.message)}
};
$('registerNode').onclick=async()=>{
  const token=adminToken(),label=$('nodeLabel').value.trim();
  if(!token||!label){say('shareStatus','أدخل رمز الإدارة واسم المشارك.');return}
  $('registerNode').disabled=true;
  try{const r=await api('/api/admin/nodes',{method:'POST',token,data:{label}});
    const issued=r.token||r.nodeToken||r.participantToken;
    say('shareStatus','تم إنشاء سجل المشارك.\nالمعرّف: '+(r.id||'تم')+'\n'+(issued?'رمز المشارك (يظهر مرة واحدة):\n'+issued+'\nاحفظه بأمان.':'راجع رد الخادم للحصول على تفاصيل التسجيل.')+'\nملاحظة: إنشاء السجل لا يشغّل محرك نقل البيانات.');
  }catch(e){say('shareStatus','تعذّر التسجيل: '+e.message)}
  finally{$('registerNode').disabled=false}
};
function adminToken(){return $('adminToken').value.trim()}
$('loadAnalytics').onclick=async()=>{
  try{
    const r=await api('/api/admin/analytics',{token:adminToken()});
    $('visitsToday').textContent=r.visitsToday;
    $('visitsTotal').textContent=r.visitsTotal;
    $('registeredParticipants').textContent=r.registeredParticipants;
    $('consentedParticipants').textContent=r.consentedParticipants;
    $('trafficParticipants').textContent=r.participantsWithTrafficThisMonth;
    $('distinctIps').textContent=r.distinctVerifiedIps ?? 'غير متاح';
    $('activeIps24h').textContent=r.activeDistinctIps24h ?? 'غير متاح';
    say('analyticsStatus',r.note||'تم تحديث الإحصائيات.');
  }catch(e){say('analyticsStatus','تعذّر تحميل الإحصائيات: '+e.message)}
};
$('loadAdmin').onclick=async()=>{
  try{
    const r=await api('/api/admin/summary',{token:adminToken()});
    $('activeNodes').textContent=r.activeNodes??'—';
    $('revenue').textContent='$'+Number(r.recordedNetRevenueUsd||0).toFixed(2);
    $('paidOrders').textContent=r.paidOrderCount??'—';
    $('pendingOrders').textContent=r.pendingOrderCount??'—';

    say('adminStatus',
      'تم تحميل الملخص.' +
      '\nإيرادات التسويات المكتملة: $' + Number(r.settledRevenueUsd||0).toFixed(2) +
      '\nحصة المالك المسجلة: $' + Number(r.settledOwnerShareUsd||0).toFixed(2) +
      '\nحصة المشاركين المسجلة: $' + Number(r.settledParticipantPoolUsd||0).toFixed(2) +
      '\nاحتياطي التشغيل: $' + Number(r.settledOperatingReserveUsd||0).toFixed(2) +
      '\nمستحقات المشاركين الموزعة: $' + Number(r.settledParticipantAllocatedUsd||0).toFixed(2) +
      '\nمستحقات المشاركين غير الموزعة: $' + Number(r.settledParticipantUnallocatedUsd||0).toFixed(2) +
      '\nعدد أشهر التسوية المكتملة: ' + Number(r.completedSettlementMonths||0) +
      '\nأشهر التسوية التي لا تتوفر لها لقطة حصة المالك: ' + Number(r.settledSplitUnknownMonths||0) +
      '\nإيرادات تاريخية بلا لقطة تقسيم محفوظة: $' + Number(r.unclassifiedNetRevenueUsd||0).toFixed(2) +
      '\n' + (r.note||'')
    );

    let report = document.getElementById('adminMonthlySettlements');

    if(!report){
      report=document.createElement('section');
      report.id='adminMonthlySettlements';
      report.className='card';
      report.style.marginTop='16px';
      report.style.padding='12px';
      const status=$('adminStatus');
      status.insertAdjacentElement('afterend',report);
    }

    report.replaceChildren();

    const heading=document.createElement('h3');
    heading.textContent='التقارير الشهرية للتسويات';
    report.appendChild(heading);

    const monthly=await api('/api/admin/settlements',{token:adminToken()});
    const settlements=monthly.settlements||[];

    if(!settlements.length){
      const empty=document.createElement('p');
      empty.textContent='لا توجد تسويات شهرية مكتملة حالياً.';
      report.appendChild(empty);
      return;
    }

    const wrapper=document.createElement('div');
    wrapper.style.overflowX='auto';

    const table=document.createElement('table');
    table.style.width='100%';
    table.style.borderCollapse='collapse';
    table.style.minWidth='1250px';

    const columns=[
      'الشهر',
      'الإيراد المعترف به',
      'حصة المالك',
      'حصة المشاركين',
      'احتياطي التشغيل',
      'الموزع للمشاركين',
      'غير الموزع',
      'المطابقة المحاسبية',
      'عدد الفروقات',
      'تفاصيل الفروقات'
    ];

    const thead=document.createElement('thead');
    const headerRow=document.createElement('tr');

    columns.forEach(label=>{
      const th=document.createElement('th');
      th.textContent=label;
      th.style.padding='10px';
      th.style.borderBottom='1px solid #888';
      th.style.textAlign='center';
      headerRow.appendChild(th);
    });

    thead.appendChild(headerRow);
    table.appendChild(thead);

    const tbody=document.createElement('tbody');

    settlements.forEach(item=>{
      const tr=document.createElement('tr');

      const values=[
        item.monthKey,
        item.revenueUsd,
        item.ownerShareUsd,
        item.participantPoolUsd,
        item.operatingReserveUsd,
        item.allocatedUsd,
        item.unallocatedUsd,
        item.reconciliation?.status,
        item.reconciliation?.issueCount
      ];

      values.forEach((value,index)=>{
        const td=document.createElement('td');

        if(index===0){
          td.textContent=String(value??'—');
        }else if(index>=1 && index<=6){
          td.textContent='$'+Number(value||0).toFixed(2);
        }else if(index===7){
          const matched=value==='matched';
          td.textContent=matched?'مطابقة':'تحتاج مراجعة';
          td.style.fontWeight='bold';
          td.style.color=matched?'#16803c':'#c0392b';
        }else{
          td.textContent=String(Number(value||0));
        }

        td.style.padding='10px';
        td.style.borderBottom='1px solid #888';
        td.style.textAlign='center';
        tr.appendChild(td);
      });

      const details=document.createElement('td');
      const issues=item.reconciliation?.issues||[];
      details.textContent=issues.length ? issues.join(' | ') : 'لا توجد فروقات';
      details.style.padding='10px';
      details.style.borderBottom='1px solid #888';
      details.style.textAlign='right';
      details.style.whiteSpace='normal';
      details.style.minWidth='280px';
      tr.appendChild(details);

      tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    wrapper.appendChild(table);
    report.appendChild(wrapper);

    const count=document.createElement('p');
    count.textContent='عدد التسويات المعروضة: '+settlements.length;
    report.appendChild(count);

  }catch(e){
    say('adminStatus','تعذّر تحميل لوحة الإدارة: '+e.message);
  }
};

$('loadAdminPackages').onclick=async()=>{
  try{
    const r=await api('/api/admin/packages',{token:adminToken()});
    const list=r.packages||[];
    $('packageManager').innerHTML=list.length?list.map(p=>
      '<article class="card"><strong>'+esc(p.name)+'</strong>'+
      '<p>الحجم: '+(Number(p.bytes)/1e9).toFixed(2)+' GB</p>'+
      '<p>السعر: $'+Number(p.priceUsd).toFixed(2)+'</p>'+
      '<p>الحالة: '+(p.active?'مفعّلة':'متوقفة')+'</p>'+
      '<button data-package-id="'+esc(p.id)+'" data-active="'+(p.active?'1':'0')+'">'+(p.active?'إيقاف الباقة':'تفعيل الباقة')+'</button></article>'
    ).join(''):'<div class="card">لا توجد باقات.</div>';
    $('packageManager').querySelectorAll('button[data-package-id]').forEach(b=>{
      b.onclick=async()=>{
        try{
          await api('/api/admin/packages/'+encodeURIComponent(b.dataset.packageId),{
            method:'POST',token:adminToken(),
            data:{active:b.dataset.active!=='1'}
          });
          say('packageStatus','تم تحديث حالة الباقة.');
          $('loadAdminPackages').click();
        }catch(e){say('packageStatus','تعذّر تحديث الباقة: '+e.message)}
      };
    });
    say('packageStatus','تم تحميل '+list.length+' باقة.');
  }catch(e){say('packageStatus','تعذّر تحميل الباقات: '+e.message)}
};

    // ROARNET_CONSENT_UI_V1
    (function () {
      const section = document.createElement('section');
      section.className = 'card';
      section.id = 'participantConsentCard';
      section.innerHTML =
        '<h2>مشاركة الإنترنت - RoarNet</h2>' +
        '<p>من هذه الواجهة تستطيع إدارة موافقتك على مشاركة الاتصال وتسجيل استهلاكه.</p>' +
        '<p>قبل الموافقة، راجع شروط المشاركة ومقدار البيانات المستخدمة وطريقة احتساب المكافآت وسياسة الخصوصية.</p>' +
        '<label for="consentNodeToken">رمز المشارك</label>' +
        '<input id="consentNodeToken" type="password" autocomplete="off" placeholder="ألصق رمز المشارك هنا">' +
        '<label style="display:block;margin-top:12px">' +
        '<input id="consentAcceptCheck" type="checkbox">' +
        ' قرأت تفاصيل مشاركة الاتصال وأوافق عليها طوعاً</label>' +
        '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px">' +
        '<button id="consentStatusBtn" type="button">عرض الحالة</button>' +
        '<button id="consentAcceptBtn" type="button">أوافق على المشاركة</button>' +
        '<button id="consentRevokeBtn" type="button">سحب الموافقة</button></div>' +
        '<p id="consentUiStatus" role="status" aria-live="polite">أدخل رمز المشارك لعرض الحالة.</p>' +
        '<small>الموافقة تسجلها قاعدة البيانات. هذه البطاقة وحدها لا تنشئ اتصال بروكسي أو أرباحاً أو دفعات فعلية.</small>';

      document.body.insertBefore(section, document.body.firstChild);

      const el = id => document.getElementById(id);
      const statusText = message => { el('consentUiStatus').textContent = message; };

      async function consentRequest(path, method, data) {
        const token = el('consentNodeToken').value.trim();
        if (!token) {
          statusText('أدخل رمز المشارك أولاً.');
          return;
        }
        statusText('جارٍ الاتصال بالخادم...');
        try {
          const response = await fetch(path, {
            method: method,
            headers: {
              'Authorization': 'Bearer ' + token,
              'Content-Type': 'application/json'
            },
            body: data === null ? undefined : JSON.stringify(data)
          });
          const result = await response.json();
          if (!response.ok) {
            statusText('تعذر إكمال الطلب: ' + (result.error || response.status));
            return;
          }
          if (path === '/api/node/consent/revoke') {
            el('consentAcceptCheck').checked = false;
            statusText('تم تسجيل سحب الموافقة.');
          } else {
            statusText(result.accepted
              ? 'حالة الموافقة: مفعّلة. تاريخ التسجيل: ' + (result.acceptedAt || 'مسجل')
              : 'حالة الموافقة: غير مفعّلة.');
          }
        } catch (error) {
          statusText('تعذر الوصول إلى الخادم. تحقق من الاتصال وعنوان الخدمة.');
        }
      }

      el('consentStatusBtn').addEventListener('click', function () {
        consentRequest('/api/node/consent', 'GET', null);
      });

      el('consentAcceptBtn').addEventListener('click', function () {
        if (!el('consentAcceptCheck').checked) {
          statusText('اقرأ التفاصيل وحدد مربع الموافقة قبل المتابعة.');
          return;
        }
        consentRequest('/api/node/consent', 'POST', {
          accepted: true,
          disclosureVersion: 'roarnet-sharing-v1'
        });
      });

      el('consentRevokeBtn').addEventListener('click', function () {
        consentRequest('/api/node/consent/revoke', 'POST', {});
      });
    })();

$('createPackage').onclick=async()=>{
  const name=$('pkgName').value.trim();
  const gb=Number($('pkgGb').value);
  const priceUsd=Number($('pkgPrice').value);
  if(!name||!Number.isFinite(gb)||gb<=0||!Number.isFinite(priceUsd)||priceUsd<0){
    say('packageStatus','تحقق من الاسم والحجم والسعر.');return;
  }
  try{
    await api('/api/admin/packages',{
      method:'POST',token:adminToken(),
      data:{name,bytes:Math.round(gb*1e9),priceUsd,active:true}
    });
    say('packageStatus','تم إرسال طلب إنشاء الباقة.');
    $('loadAdminPackages').click();
  }catch(e){say('packageStatus','تعذّر إنشاء الباقة: '+e.message)}
};

$('fillDefaults').onclick=()=>{
  applyRoarNetDefaults();
  say('packageStatus','تمت تعبئة القيم الافتراضية. راجعها قبل الحفظ.');
};
$('loadOrders').onclick=async()=>{
  try{const r=await api('/api/admin/orders',{token:adminToken()}),list=r.orders||[];
    $('orders').innerHTML=list.length?list.map(o=>\`<article class="card"><strong>\${esc(o.packageName)}</strong><p>العميل: \${esc(o.customerLabel)}</p><p>السعر: $\${Number(o.amountUsd).toFixed(2)}</p><p>الحالة: \${esc(o.status)}</p><small>\${esc(o.createdAt)}</small></article>\`).join(''):'<div class="card">لا توجد طلبات.</div>';
  }catch(e){say('adminStatus','تعذّر عرض الطلبات: '+e.message)}
};
$('loadNodes').onclick=async()=>{
  try{const r=await api('/api/admin/nodes',{token:adminToken()}),list=r.nodes||[];
    $('nodes').innerHTML=list.length?list.map(n=>\`<article class="card"><strong>\${esc(n.label)}</strong><p>الحالة: \${esc(n.status)}</p><p>الاستهلاك المُبلّغ: \${(Number(n.reportedBytes||0)/1e9).toFixed(3)} GB</p><small>\${esc(n.id)}</small></article>\`).join(''):'<div class="card">لا يوجد مشاركون مسجلون.</div>';
  }catch(e){say('adminStatus','تعذّر عرض المشاركين: '+e.message)}
};
$('createCustomer').onclick=async()=>{
  const label=$('customerLabel').value.trim();
  if(!label){say('newCustomer','أدخل اسم العميل.');return}
  try{const r=await api('/api/admin/customers',{method:'POST',token:adminToken(),data:{label}});
    const issued=r.customerToken;
    say('newCustomer','تم إنشاء الحساب: '+(r.id||'تم')+'\n'+(issued?'رمز العميل (يظهر مرة واحدة):\n'+issued+'\nاحفظه بأمان.':'لم يرجع الخادم رمز العميل.') );
  }catch(e){say('newCustomer','تعذّر إنشاء الحساب: '+e.message)}
};
</script>

<div id="roarnet-adsterra-banner" style="width:320px;max-width:100%;min-height:50px;margin:20px auto;text-align:center;overflow:hidden">
<script>atOptions={'key':'ee2af095a2b5972a5b6691bec44bbac2','format':'iframe','height':50,'width':320,'params':{}};</script>
<script src="https://bauval.org/22/ee2af095a2b5972a5b6691bec44bbac2"></script>
</div>


<script>
/* ROARNET_MAINTENANCE_BOT_V1 */
(function () {
  const button = document.getElementById('runMaintenanceBot');
  const status = document.getElementById('maintenanceBotStatus');
  const report = document.getElementById('maintenanceBotReport');

  if (!button || !status || !report) return;

  button.addEventListener('click', async function () {
    const tokenField = document.getElementById('adminToken');
    const token = tokenField ? tokenField.value.trim() : '';

    report.textContent = '';
    if (!token) {
      status.textContent = 'أدخل رمز الإدارة في لوحة الإدارة أولاً.';
      return;
    }

    button.disabled = true;
    status.textContent = 'جارٍ فحص مسارات الإدارة...';

    const checks = [
      { name: 'ملخص الإدارة', path: '/api/admin/summary' },
      { name: 'حالة مزوّد الخدمة', path: '/api/admin/provider/status' },
      { name: 'تحليلات الشبكة', path: '/api/admin/analytics' },
      { name: 'ملخص الترافيك', path: '/api/admin/traffic-summary' }
    ];

    const results = await Promise.all(checks.map(async function (check) {
      try {
        const data = await api(check.path, { token: token });
        return { name: check.name, ok: true, data: data };
      } catch (error) {
        return {
          name: check.name,
          ok: false,
          error: String(error && error.message ? error.message : 'تعذر الطلب')
        };
      }
    }));

    const lines = [
      'تقرير صيانة RoarNet',
      'الوقت: ' + new Date().toLocaleString(),
      '------------------------------'
    ];

    let failed = 0;

    results.forEach(function (result) {
      if (!result.ok) {
        failed++;
        lines.push('[تعذر الفحص] ' + result.name + ': ' + result.error);
        return;
      }

      lines.push('[استجابة ناجحة] ' + result.name);

      if (result.name === 'حالة مزوّد الخدمة') {
        if (result.data && result.data.configured === false) {
          lines.push('التشخيص: مفتاح المزوّد غير مضبوط على الخادم.');
        } else if (result.data && result.data.connected === false) {
          lines.push('التشخيص: المزوّد غير متصل أو رفض الطلب؛ راجع إعداداته وسجلات الخادم.');
        } else if (result.data && result.data.connected === true) {
          lines.push('التشخيص: الخادم أفاد بأن اتصال المزوّد ناجح.');
        } else {
          lines.push('التشخيص: الاستجابة وصلت؛ تفاصيل حالة المزوّد غير مكتملة.');
        }
      }
    });

    lines.push('------------------------------');

    if (failed === 0) {
      lines.push('الخلاصة: جميع مسارات الفحص الأربعة استجابت.');
    } else {
      lines.push('الخلاصة: تعذر إكمال ' + failed + ' من أصل ' + checks.length + ' فحوصات.');
      lines.push('هذا وحده لا يثبت وجود عطل عام؛ راجع الخطأ المحدد وسجلات الخادم.');
    }

    lines.push('');
    lines.push('هذا فحص أولي للقراءة فقط، ولا ينفذ إصلاحات تلقائية.');

    report.textContent = lines.join('\n');
    status.textContent = 'انتهى الفحص.';
    button.disabled = false;
  });
})();
</script>

</body></html>`.replaceAll('\\`', '`').replaceAll('\\${', '${');
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://bauval.org; frame-src 'self' https:; style-src 'self' 'unsafe-inline'; connect-src 'self' https://bauval.org; img-src 'self' data: https://bauval.org; base-uri 'none'; frame-ancestors 'none'"
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



    // ROARNET_CENTRAL_PARTICIPANT_API_V1

    if (req.method === 'POST' && url.pathname === '/api/admin/participants') {
      if (!isAdmin(req)) return json(res, 401, { error: 'Unauthorized' });
      const b = await body(req);
      const label = String(b.label || '').trim();
      const loginId = String(b.loginId || '').trim().toLowerCase();
      const password = String(b.password || '');

      if (!label || label.length > 80)
        return json(res, 400, { error: 'Invalid label' });
      if (!/^[a-z0-9_.-]{3,40}$/.test(loginId))
        return json(res, 400, { error: 'Invalid loginId' });
      if (password.length < 10 || password.length > 128)
        return json(res, 400, { error: 'Password must be 10-128 characters' });

      const id = crypto.randomUUID();
      try {
        db.prepare("INSERT INTO participants(id,label,login_id,password_hash,status,created_at) VALUES(?,?,?,?,?,?)")
          .run(id, label, loginId, makeParticipantPasswordHash(password), 'active', now());
      } catch (e) {
        if (String(e.message).includes('UNIQUE'))
          return json(res, 409, { error: 'loginId already exists' });
        throw e;
      }
      return json(res, 201, { id, label, loginId, status: 'active' });
    }

    if (req.method === 'GET' && url.pathname === '/api/participant/account') {
      let user;
      try {
        user = await supabaseUserFor(req);
      } catch (error) {
        if (error.message === 'SUPABASE_NOT_CONFIGURED') {
          return json(res, 503, { error: 'Supabase authentication is not configured' });
        }
        return json(res, 503, { error: 'Supabase authentication service unavailable' });
      }

      if (!user) return json(res, 401, { error: 'Invalid or expired Supabase session' });

      let participant = db.prepare(
        "SELECT id,label,login_id,status FROM participants WHERE auth_user_id=?"
      ).get(user.id);

      if (!participant) {
        const email = String(user.email || '').trim().toLowerCase();
        const emailConfirmed = Boolean(user.email_confirmed_at || user.confirmed_at);

        // Link an existing account only when Supabase confirms ownership of its email.
        if (email && emailConfirmed) {
          const existing = db.prepare(
            "SELECT id,label,login_id,status,auth_user_id FROM participants WHERE login_id=? COLLATE NOCASE"
          ).get(email);

          if (existing && !existing.auth_user_id) {
            db.prepare(
              "UPDATE participants SET auth_user_id=? WHERE id=? AND auth_user_id IS NULL"
            ).run(user.id, existing.id);
          } else if (existing && existing.auth_user_id !== user.id) {
            return json(res, 409, { error: 'This email is already linked to another account' });
          }
        }

        participant = db.prepare(
          "SELECT id,label,login_id,status FROM participants WHERE auth_user_id=?"
        ).get(user.id);
      }

      if (!participant) {
        const id = crypto.randomUUID();
        const internalLogin = `supabase-${user.id}@roarnet.local`;
        const emailName = String(user.email || '').split('@')[0].trim();
        const label = (emailName || 'RoarNet participant').slice(0, 80);
        const randomPassword = crypto.randomBytes(48).toString('hex');

        try {
          db.prepare(
            "INSERT INTO participants(id,label,login_id,password_hash,status,created_at,auth_user_id) VALUES(?,?,?,?,?,?,?)"
          ).run(
            id, label, internalLogin,
            makeParticipantPasswordHash(randomPassword),
            'active', now(), user.id
          );
        } catch (error) {
          if (String(error.message).includes('UNIQUE')) {
            return json(res, 409, { error: 'Account linking conflict; contact support' });
          }
          throw error;
        }

        participant = db.prepare(
          "SELECT id,label,login_id,status FROM participants WHERE id=?"
        ).get(id);
      }

      if (!participant || participant.status !== 'active') {
        return json(res, 403, { error: 'Participant account is suspended' });
      }

      return json(res, 200, {
        participant: {
          id: participant.id,
          label: participant.label,
          loginId: participant.login_id
        },
        auth: { provider: 'supabase', userId: user.id }
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/participant/login') {
      const ip = String(req.socket.remoteAddress || 'unknown');
      const time = Date.now();
      let a = participantLoginAttempts.get(ip);
      if (!a || time - a.start > 15 * 60 * 1000) a = { start: time, count: 0 };
      if (a.count >= 8) return json(res, 429, { error: 'Too many attempts' });
      a.count++;
      participantLoginAttempts.set(ip, a);

      const b = await body(req);
      const loginId = String(b.loginId || '').trim().toLowerCase();
      const password = String(b.password || '');
      const p = db.prepare("SELECT id,label,login_id,password_hash FROM participants WHERE login_id=? AND status='active'")
        .get(loginId);

      if (!p || !verifyParticipantPassword(password, p.password_hash))
        return json(res, 401, { error: 'Invalid credentials' });

      participantLoginAttempts.delete(ip);
      const token = crypto.randomBytes(32).toString('hex');
      const expires = new Date(Date.now() + 30 * 86400000).toISOString();

      db.prepare("INSERT INTO participant_sessions(token_hash,participant_id,created_at,expires_at) VALUES(?,?,?,?)")
        .run(hash(token), p.id, now(), expires);

      return json(res, 200, {
        token,
        expiresAt: expires,
        participant: { id: p.id, label: p.label, loginId: p.login_id }
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/participant/me') {
      const p = await participantFor(req);
      if (!p) return json(res, 401, { error: 'Invalid participant session' });
      return json(res, 200, { participant: p });
    }


    // ROARNET_PARTICIPANT_WALLET_API_V1
    if (req.method === 'GET' && url.pathname === '/api/participant/wallet') {
      const p = await participantFor(req);

      if (!p) {
        return json(res, 401, { error: 'Invalid participant session' });
      }

      const months = db.prepare(`
        SELECT
          substr(e.month_key, 1, 7) AS month_key,
          COALESCE(SUM(e.contribution_bytes), 0) AS contribution_bytes,
          COALESCE(SUM(e.revenue_cents), 0) AS revenue_cents,
          COALESCE(SUM(e.amount_cents), 0) AS earned_cents,
          COALESCE(pe.amount_cents, 0) AS settled_cents,
          COALESCE(sb.status, 'pending') AS settlement_status,
          sb.completed_at AS settled_at
        FROM participant_earning_entries e
        LEFT JOIN settlement_batches sb
          ON sb.month_key = substr(e.month_key, 1, 7)
        LEFT JOIN participant_earnings pe
          ON pe.month_key = substr(e.month_key, 1, 7)
          AND pe.participant_id = e.participant_id
        WHERE e.participant_id = ?
        GROUP BY
          substr(e.month_key, 1, 7),
          pe.amount_cents,
          sb.status,
          sb.completed_at
        ORDER BY month_key DESC
      `).all(p.id);

      const result = months.map(row => {
        const earned = Number(row.earned_cents || 0);
        const settled = Number(row.settled_cents || 0);
        const completed = row.settlement_status === 'completed';

        return {
          month: row.month_key,
          contributionBytes: Number(row.contribution_bytes || 0),
          revenueCents: Number(row.revenue_cents || 0),
          earnedCents: earned,
          settledCents: completed ? settled : 0,
          awaitingSettlementCents: completed ? 0 : earned,
          settlementStatus: completed ? 'completed' : 'pending',
          settledAt: completed ? row.settled_at : null,
          payoutStatus: 'not_integrated'
        };
      });

      const totals = result.reduce((acc, row) => {
        acc.contributionBytes += row.contributionBytes;
        acc.revenueCents += row.revenueCents;
        acc.earnedCents += row.earnedCents;
        acc.settledCents += row.settledCents;
        acc.awaitingSettlementCents += row.awaitingSettlementCents;
        return acc;
      }, {
        contributionBytes: 0,
        revenueCents: 0,
        earnedCents: 0,
        settledCents: 0,
        awaitingSettlementCents: 0
      });

      return json(res, 200, {
        participant: {
          id: p.id,
          label: p.label
        },
        currency: 'USD',
        totals,
        months: result,
        payoutIntegration: {
          status: 'not_integrated',
          message: 'Accounting settlement is separate from actual money transfers.'
        }
      });
    }

    // END ROARNET_PARTICIPANT_WALLET_API_V1


    // ROARNET_WITHDRAWAL_SYSTEM_V1
    if (
      req.method === 'GET' &&
      url.pathname === '/api/participant/withdrawals'
    ) {
      const p = await participantFor(req);
      if (!p) return json(res, 401, {
        error: 'Invalid participant session'
      });

      const earned = Number(db.prepare(`
        SELECT COALESCE(SUM(amount_cents), 0) AS total
        FROM participant_earnings
        WHERE participant_id = ?
      `).get(p.id).total || 0);

      const reserved = Number(db.prepare(`
        SELECT COALESCE(SUM(amount_cents), 0) AS total
        FROM withdrawal_requests
        WHERE participant_id = ?
          AND status IN ('queued', 'processing', 'paid')
      `).get(p.id).total || 0);

      const withdrawals = db.prepare(`
        SELECT id, amount_cents, status, created_at,
               updated_at, processed_at, payout_reference,
               payout_method
        FROM withdrawal_requests
        WHERE participant_id = ?
        ORDER BY id DESC
        LIMIT 100
      `).all(p.id);

      return json(res, 200, {
        currency: 'USD',
        earnedCents: earned,
        reservedCents: reserved,
        availableCents: Math.max(0, earned - reserved),
        withdrawals
      });
    }

    if (
      req.method === 'POST' &&
      url.pathname === '/api/participant/withdrawals'
    ) {
      const p = await participantFor(req);
      if (!p) return json(res, 401, {
        error: 'Invalid participant session'
      });

      const b = await body(req);
      const amountCents = Number(b.amountCents);
      let destinationAddress = String(b.destinationAddress || '').trim();
      const payoutMethod = String(b.payoutMethod || 'usdt_trc20').trim().toLowerCase();

      if (!['usdt_trc20', 'paypal', 'zaincash', 'venmo'].includes(payoutMethod)) {
        return json(res, 400, { error: 'Unsupported payout method' });
      }

      if (!Number.isSafeInteger(amountCents) || amountCents < 100) {
        return json(res, 400, {
          error: 'amountCents must be a positive integer'
        });
      }

      const validDestination = (() => {
        if (payoutMethod === 'paypal') {
          return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(destinationAddress);
        }
        if (payoutMethod === 'usdt_trc20') {
          return /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(destinationAddress);
        }
        if (payoutMethod === 'zaincash') {
          const phone = destinationAddress.replace(/[\s-]/g, '');
          return /^(?:\+964|00964|0)?7\d{9}$/.test(phone);
        }
        if (payoutMethod === 'venmo') {
          return /^@?[A-Za-z0-9_-]{5,30}$/.test(destinationAddress);
        }
        return false;
      })();

      if (!validDestination) {
        const errors = {
          paypal: 'Invalid PayPal email address',
          usdt_trc20: 'Invalid TRC20 address format',
          zaincash: 'Invalid ZainCash phone number',
          venmo: 'Invalid Venmo username'
        };
        return json(res, 400, {
          error: errors[payoutMethod] || 'Invalid payout destination'
        });
      }

      if (payoutMethod === 'zaincash') {
        const phone = destinationAddress.replace(/[\s-]/g, '');
        if (phone.startsWith('00964')) {
          destinationAddress = '+964' + phone.slice(5);
        } else if (phone.startsWith('0')) {
          destinationAddress = '+964' + phone.slice(1);
        } else if (phone.startsWith('7')) {
          destinationAddress = '+964' + phone;
        } else {
          destinationAddress = phone;
        }
      }

      db.exec('BEGIN IMMEDIATE');

      try {
        const earned = Number(db.prepare(`
          SELECT COALESCE(SUM(amount_cents), 0) AS total
          FROM participant_earnings
          WHERE participant_id = ?
        `).get(p.id).total || 0);

        const reserved = Number(db.prepare(`
          SELECT COALESCE(SUM(amount_cents), 0) AS total
          FROM withdrawal_requests
          WHERE participant_id = ?
            AND status IN ('queued', 'processing', 'paid')
        `).get(p.id).total || 0);

        const available = earned - reserved;

        if (amountCents > available) {
          db.exec('ROLLBACK');
          return json(res, 409, {
            error: 'Insufficient available balance',
            availableCents: Math.max(0, available)
          });
        }

        const timestamp = new Date().toISOString();

        const result = db.prepare(`
          INSERT INTO withdrawal_requests
            (participant_id, amount_cents, destination_address, payout_method,
             network, status, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, 'queued', ?, ?)
        `).run(
          p.id,
          amountCents,
          destinationAddress,
          payoutMethod,
          ({ paypal: 'PAYPAL', usdt_trc20: 'TRC20', zaincash: 'ZAINCASH', venmo: 'VENMO' })[payoutMethod],
          timestamp,
          timestamp
        );

        db.exec('COMMIT');

        return json(res, 201, {
          success: true,
          withdrawal: {
            id: Number(result.lastInsertRowid),
            amountCents,
            status: 'queued',
            createdAt: timestamp
          },
          availableCents: available - amountCents
        });
      } catch (error) {
        try { db.exec('ROLLBACK'); } catch {}
        throw error;
      }
    }
    // END ROARNET_WITHDRAWAL_SYSTEM_V1


    // ROARNET_AUTOMATIC_PARTICIPANT_DEVICE_REGISTRATION_V1
    if (req.method === 'POST' &&
        url.pathname === '/api/participant/devices/register') {
      const participant = await participantFor(req);
      if (!participant) {
        return json(res, 401, { error: 'Valid participant login required' });
      }

      const data = await body(req);
      const installationId = String(data.installationId || '').trim().toLowerCase();
      const requestedLabel = String(data.label || 'Android device').trim();
      const label = requestedLabel || 'Android device';

      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(installationId)) {
        return json(res, 400, { error: 'A valid installationId UUID is required' });
      }

      if (label.length > 80) {
        return json(res, 400, { error: 'Device label must be at most 80 characters' });
      }

      db.exec('BEGIN IMMEDIATE');
      try {
        const existing = db.prepare(`
          SELECT id,label,status,participant_id
          FROM nodes
          WHERE installation_id=?
        `).get(installationId);

        if (existing) {
          if (existing.participant_id !== participant.id) {
            db.exec('ROLLBACK');
            return json(res, 409, {
              error: 'This installation is already linked to another account'
            });
          }

          if (existing.status !== 'active') {
            db.exec('ROLLBACK');
            return json(res, 409, { error: 'This device is inactive' });
          }

          db.prepare(`
            UPDATE nodes SET label=?
            WHERE id=? AND participant_id=?
          `).run(label, existing.id, participant.id);

          db.exec('COMMIT');

          return json(res, 200, {
            success: true,
            created: false,
            device: {
              id: existing.id,
              label,
              status: existing.status
            }
          });
        }

        const id = crypto.randomUUID();
        const internalToken = crypto.randomBytes(32).toString('hex');

        db.prepare(`
          INSERT INTO nodes(
            id,label,token_hash,status,created_at,participant_id,installation_id
          )
          VALUES(?,?,?,'active',?,?,?)
        `).run(
          id,
          label,
          hash(internalToken),
          now(),
          participant.id,
          installationId
        );

        db.exec('COMMIT');

        return json(res, 201, {
          success: true,
          created: true,
          device: {
            id,
            label,
            status: 'active'
          }
        });
      } catch (error) {
        try { db.exec('ROLLBACK'); } catch {}
        throw error;
      }
    }
    // END ROARNET_AUTOMATIC_PARTICIPANT_DEVICE_REGISTRATION_V1

    if (req.method === 'GET' && url.pathname === '/api/participant/devices') {
      const p = await participantFor(req);
      if (!p) return json(res, 401, { error: 'Invalid participant session' });
      const devices = db.prepare("SELECT id,label,status,created_at FROM nodes WHERE participant_id=? ORDER BY created_at DESC")
        .all(p.id);
      return json(res, 200, { devices });
    }

    if (req.method === 'POST' && url.pathname === '/api/participant/devices/claim') {
      const p = await participantFor(req);
      if (!p) return json(res, 401, { error: 'Valid participant login required' });

      const b = await body(req);
      const deviceToken = String(b.deviceToken || '').trim();

      if (!/^[a-f0-9]{64}$/i.test(deviceToken)) {
        return json(res, 400, { error: 'Invalid device token' });
      }

      db.exec('BEGIN IMMEDIATE');
      try {
        const node = db.prepare(
          "SELECT id,label,status,participant_id FROM nodes WHERE token_hash=?"
        ).get(hash(deviceToken));

        if (!node || node.status !== 'active') {
          db.exec('ROLLBACK');
          return json(res, 404, { error: 'Active device not found' });
        }

        if (node.participant_id && node.participant_id !== p.id) {
          db.exec('ROLLBACK');
          return json(res, 409, { error: 'Device belongs to another account' });
        }

        db.prepare(
          "UPDATE nodes SET participant_id=? WHERE id=? AND (participant_id IS NULL OR participant_id=?)"
        ).run(p.id, node.id, p.id);

        db.exec('COMMIT');

        return json(res, 200, {
          success: true,
          device: {
            id: node.id,
            label: node.label,
            status: node.status
          }
        });
      } catch (error) {
        try { db.exec('ROLLBACK'); } catch {}
        throw error;
      }
    }

    if (req.method === 'POST' && url.pathname === '/api/participant/logout') {
      const p = await participantFor(req);
      if (!p) return json(res, 401, { error: 'Invalid participant session' });

      // Supabase session revocation is handled by the authenticated client.
      return json(res, 200, { success: true, clientSignOutRequired: true });
    }

    if (req.method === 'POST' && url.pathname === '/api/admin/nodes/participant') {
      if (!isAdmin(req)) return json(res, 401, { error: 'Unauthorized' });
      const b = await body(req);
      const nodeId = String(b.nodeId || '').trim();
      const participantId = String(b.participantId || '').trim() || null;

      if (!nodeId) return json(res, 400, { error: 'nodeId required' });
      if (!db.prepare("SELECT id FROM nodes WHERE id=?").get(nodeId))
        return json(res, 404, { error: 'Node not found' });

      if (participantId && !db.prepare("SELECT id FROM participants WHERE id=? AND status='active'").get(participantId))
        return json(res, 400, { error: 'Invalid participantId' });

      db.prepare("UPDATE nodes SET participant_id=? WHERE id=?")
        .run(participantId, nodeId);
      return json(res, 200, { success: true, nodeId, participantId });
    }

    // ROARNET_MY_CONTRIBUTIONS_V1
    if (req.method === 'GET' && url.pathname === '/api/node/my-contributions') {
      const node = nodeFor(req);
      if (!node) return json(res, 401, { error: 'Invalid node token' });

      const monthKey = getRoarNetBaghdadMonth();
      const total = db.prepare(`
        SELECT COALESCE(SUM(bytes), 0) AS bytes, COUNT(*) AS events
        FROM usage_events WHERE node_id=?
      `).get(node.id);
      const monthly = db.prepare(`
        SELECT COALESCE(SUM(bytes), 0) AS bytes, COUNT(*) AS events
        FROM usage_events WHERE node_id=? AND strftime('%Y-%m', created_at, '+3 hours')=?
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


    // ROARNET_PROVIDER_CONSENTS_API_V1
    if (url.pathname === '/api/node/provider-consents' &&
        req.method === 'GET') {
      const node = nodeFor(req);
      if (!node) return json(res, 401, { error: 'Invalid node token' });

      const versions = {};

      const rows = db.prepare(
        'SELECT provider,status,disclosure_version,accepted_at,revoked_at FROM provider_consents WHERE node_id=?'
      ).all(node.id);

      const consents = Object.entries(versions).map(([provider, version]) => {
        const row = rows.find(r => r.provider === provider);
        return {
          provider,
          disclosureVersion: row?.disclosure_version || version,
          accepted: Boolean(row && row.status === 'accepted' && !row.revoked_at),
          acceptedAt: row?.accepted_at || null,
          revokedAt: row?.revoked_at || null
        };
      });

      return json(res, 200, { ok: true, consents });
    }

    if (url.pathname === '/api/node/provider-consents' &&
        req.method === 'POST') {
      const node = nodeFor(req);
      if (!node) return json(res, 401, { error: 'Invalid node token' });

      const data = await body(req);
      const provider = String(data.provider || '').trim();
      const versions = {};

      if (!versions[provider]) {
        return json(res, 400, {
          error: 'Unsupported provider',
          supportedProviders: Object.keys(versions)
        });
      }

      if (data.accepted !== true ||
          data.disclosureVersion !== versions[provider]) {
        return json(res, 400, {
          error: 'Explicit provider consent and current disclosure version are required',
          requiredDisclosureVersion: versions[provider]
        });
      }

      const acceptedAt = now();

      db.prepare(`
        INSERT INTO provider_consents
          (node_id,provider,status,disclosure_version,accepted_at,revoked_at)
        VALUES(?,?,'accepted',?,?,NULL)
        ON CONFLICT(node_id,provider) DO UPDATE SET
          status='accepted',
          disclosure_version=excluded.disclosure_version,
          accepted_at=excluded.accepted_at,
          revoked_at=NULL
      `).run(node.id, provider, versions[provider], acceptedAt);

      return json(res, 200, {
        ok: true,
        provider,
        accepted: true,
        acceptedAt,
        disclosureVersion: versions[provider]
      });
    }

    if (url.pathname === '/api/node/provider-consents/revoke' &&
        req.method === 'POST') {
      const node = nodeFor(req);
      if (!node) return json(res, 401, { error: 'Invalid node token' });

      const data = await body(req);
      const provider = String(data.provider || '').trim();
      const supportedProviders = ['proxies_sx', 'honeygain'];

      if (!supportedProviders.includes(provider)) {
        return json(res, 400, {
          error: 'Unsupported provider',
          supportedProviders
        });
      }

      const revokedAt = now();

      db.prepare(
        "UPDATE provider_consents SET status='revoked',revoked_at=? WHERE node_id=? AND provider=? AND status='accepted'"
      ).run(revokedAt, node.id, provider);

      return json(res, 200, {
        ok: true,
        provider,
        accepted: false,
        revokedAt
      });
    }

    // ROARNET_ACCOUNT_DEVICE_CONSENTS_V1
    const sharingConsentPaths = [
      '/api/participant/device/consent',
      '/api/participant/device/consent/revoke'
    ];

    const providerConsentPaths = [
      '/api/participant/device/provider-consents'
    ];

    if (sharingConsentPaths.includes(url.pathname) &&
        req.method === 'GET') {
      const auth = await participantDeviceFor(
        req, url.searchParams.get('deviceId')
      );

      if (auth.error) {
        const status = auth.error === 'PARTICIPANT_SESSION_INVALID' ? 401 :
          auth.error === 'DEVICE_ID_REQUIRED' ? 400 : 403;
        return json(res, status, { error: auth.error });
      }

      const consent = db.prepare(`
        SELECT accepted_at, revoked_at, disclosure_version
        FROM sharing_consents WHERE node_id=?
      `).get(auth.device.id);

      return json(res, 200, {
        deviceId: auth.device.id,
        accepted: Boolean(consent && !consent.revoked_at),
        acceptedAt: consent?.accepted_at || null,
        revokedAt: consent?.revoked_at || null,
        disclosureVersion: consent?.disclosure_version || null
      });
    }


    // ROARNET_CUSTOMER_RELAY_PROXY_V1
    const customerRelayMatch = url.pathname.match(
      /^\/api\/relay\/customer\/sessions\/([0-9a-f-]{36})\/(send|receive)$/i
    );

    if (req.method === 'POST' && customerRelayMatch) {
      const customer = customerFor(req);

      if (!customer) {
        return json(res, 401, {
          error: 'VALID_CUSTOMER_CREDENTIALS_REQUIRED'
        });
      }

      const sessionId = customerRelayMatch[1];
      const operation = customerRelayMatch[2].toLowerCase();

      let data;
      try {
        data = await body(req);
      } catch {
        return json(res, 400, {
          error: 'INVALID_CUSTOMER_RELAY_PAYLOAD'
        });
      }

      if (operation === 'send') {
        if (
          typeof data.data !== 'string' ||
          data.data.length < 4 ||
          data.data.length > 87384 ||
          !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(data.data)
        ) {
          return json(res, 400, {
            error: 'INVALID_BASE64_DATA'
          });
        }

        const decoded = Buffer.from(data.data, 'base64');

        if (
          decoded.length < 1 ||
          decoded.length > 64 * 1024 ||
          decoded.toString('base64') !== data.data
        ) {
          return json(res, 413, {
            error: 'CUSTOMER_CHUNK_SIZE_INVALID'
          });
        }
      } else {
        data.maxItems = Number(data.maxItems ?? 16);

        if (
          !Number.isInteger(data.maxItems) ||
          data.maxItems < 1 ||
          data.maxItems > 32
        ) {
          return json(res, 400, {
            error: 'INVALID_RECEIVE_LIMIT'
          });
        }
      }

      const ownedSession = db.prepare(`
        SELECT rs.session_id
        FROM relay_sessions rs
        JOIN nodes n ON n.id = rs.node_id
        JOIN sharing_consents sc ON sc.node_id = rs.node_id
        WHERE rs.session_id = ?
          AND rs.customer_id = ?
          AND rs.status = 'ACTIVE'
          AND rs.provider_id IS NOT NULL
          AND rs.expires_at > ?
          AND n.status = 'active'
          AND sc.revoked_at IS NULL
          AND sc.disclosure_version = 'roarnet-sharing-v1'
        LIMIT 1
      `).get(sessionId, customer.id, now());

      if (!ownedSession) {
        return json(res, 404, {
          error: 'ACTIVE_OWNED_SESSION_OR_CONSENT_NOT_FOUND'
        });
      }

      const gatewayToken = process.env.RELAY_GATEWAY_TOKEN || '';
      const gatewayId = process.env.RELAY_GATEWAY_ID || '';
      const gatewayUrl = (
        process.env.RELAY_GATEWAY_URL ||
        'http://127.0.0.1:3182'
      ).replace(/\/+$/, '');

      if (gatewayToken.length < 32 || gatewayId.length < 3) {
        return json(res, 503, {
          error: 'RELAY_GATEWAY_CREDENTIALS_NOT_CONFIGURED'
        });
      }

      try {
        const gatewayResponse = await fetch(
          new URL(
            '/internal/buyer/sessions/' +
            encodeURIComponent(sessionId) +
            '/' + operation,
            gatewayUrl
          ),
          {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${gatewayToken}`,
              'x-roarnet-gateway-id': gatewayId,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(
              operation === 'send'
                ? { data: data.data }
                : { maxItems: data.maxItems }
            ),
            signal: AbortSignal.timeout(12000)
          }
        );

        let gatewayData;
        try {
          gatewayData = await gatewayResponse.json();
        } catch {
          return json(res, 502, {
            error: 'INVALID_GATEWAY_RELAY_RESPONSE'
          });
        }

        return json(res, gatewayResponse.status, gatewayData);
      } catch {
        return json(res, 502, {
          error: 'RELAY_GATEWAY_UNAVAILABLE'
        });
      }
    }

    // ROARNET_GATEWAY_TRUSTED_SESSION_CONTEXT_V1
    const gatewaySessionContextMatch = url.pathname.match(
      /^\/api\/relay\/gateway\/session-context\/([0-9a-f-]{36})$/i
    );

    if (req.method === 'GET' && gatewaySessionContextMatch) {
      const suppliedGatewayToken = bearer(req);
      const expectedGatewayToken = process.env.RELAY_GATEWAY_TOKEN || '';
      const suppliedGatewayId = String(
        req.headers['x-roarnet-gateway-id'] || ''
      );
      const expectedGatewayId = process.env.RELAY_GATEWAY_ID || '';

      if (!expectedGatewayToken || !expectedGatewayId ||
          suppliedGatewayToken !== expectedGatewayToken ||
          suppliedGatewayId !== expectedGatewayId) {
        return json(res, 401, { error: 'GATEWAY_AUTHENTICATION_REQUIRED' });
      }

      const session = db.prepare(`
        SELECT
          rs.session_id,
          rs.customer_id,
          rs.device_id,
          rs.node_id,
          rs.status,
          rs.expires_at
        FROM relay_sessions rs
        JOIN nodes n ON n.id = rs.node_id
        JOIN sharing_consents sc ON sc.node_id = rs.node_id
        WHERE rs.session_id = ?
          AND rs.status = 'ACTIVE'
          AND rs.provider_id IS NOT NULL
          AND rs.expires_at > ?
          AND n.status = 'active'
          AND sc.revoked_at IS NULL
          AND sc.disclosure_version = 'roarnet-sharing-v1'
        LIMIT 1
      `).get(gatewaySessionContextMatch[1], now());

      if (!session) {
        return json(res, 404, {
          error: 'ACTIVE_SESSION_OR_VALID_DEVICE_CONSENT_NOT_FOUND'
        });
      }

      return json(res, 200, {
        sessionId: session.session_id,
        customerId: session.customer_id,
        deviceId: session.device_id,
        status: session.status,
        consentActive: true,
        expiresAt: session.expires_at
      });
    }

    if (sharingConsentPaths.includes(url.pathname) &&
        req.method === 'POST' &&
        !url.pathname.endsWith('/revoke')) {
      const data = await body(req);
      const auth = await participantDeviceFor(req, data.deviceId);

      if (auth.error) {
        const status = auth.error === 'PARTICIPANT_SESSION_INVALID' ? 401 :
          auth.error === 'DEVICE_ID_REQUIRED' ? 400 : 403;
        return json(res, status, { error: auth.error });
      }

      if (data.accepted !== true ||
          data.disclosureVersion !== 'roarnet-sharing-v1') {
        return json(res, 400, {
          error: 'Explicit consent and the current disclosure version are required',
          requiredDisclosureVersion: 'roarnet-sharing-v1'
        });
      }

      const acceptedAt = now();
      db.prepare(`
        INSERT INTO sharing_consents
          (node_id, accepted_at, revoked_at, disclosure_version)
        VALUES(?,?,NULL,?)
        ON CONFLICT(node_id) DO UPDATE SET
          accepted_at=excluded.accepted_at,
          revoked_at=NULL,
          disclosure_version=excluded.disclosure_version
      `).run(auth.device.id, acceptedAt, 'roarnet-sharing-v1');

      return json(res, 200, {
        ok: true,
        deviceId: auth.device.id,
        accepted: true,
        acceptedAt,
        disclosureVersion: 'roarnet-sharing-v1'
      });
    }

    if (sharingConsentPaths.includes(url.pathname) &&
        req.method === 'POST' &&
        url.pathname.endsWith('/revoke')) {
      const data = await body(req);
      const auth = await participantDeviceFor(req, data.deviceId);

      if (auth.error) {
        const status = auth.error === 'PARTICIPANT_SESSION_INVALID' ? 401 :
          auth.error === 'DEVICE_ID_REQUIRED' ? 400 : 403;
        return json(res, status, { error: auth.error });
      }

      const revokedAt = now();
      db.prepare(`
        UPDATE sharing_consents
        SET revoked_at=?
        WHERE node_id=? AND revoked_at IS NULL
      `).run(revokedAt, auth.device.id);

      return json(res, 200, {
        ok: true,
        deviceId: auth.device.id,
        accepted: false,
        revokedAt
      });
    }

    if (providerConsentPaths.includes(url.pathname) &&
        req.method === 'GET') {
      const auth = await participantDeviceFor(
        req, url.searchParams.get('deviceId')
      );

      if (auth.error) {
        const status = auth.error === 'PARTICIPANT_SESSION_INVALID' ? 401 :
          auth.error === 'DEVICE_ID_REQUIRED' ? 400 : 403;
        return json(res, status, { error: auth.error });
      }

      const versions = {};

      const rows = db.prepare(`
        SELECT provider,status,disclosure_version,accepted_at,revoked_at
        FROM provider_consents WHERE node_id=?
      `).all(auth.device.id);

      const consents = Object.entries(versions).map(([provider, version]) => {
        const row = rows.find(r => r.provider === provider);
        return {
          provider,
          disclosureVersion: row?.disclosure_version || version,
          accepted: Boolean(row && row.status === 'accepted' && !row.revoked_at),
          acceptedAt: row?.accepted_at || null,
          revokedAt: row?.revoked_at || null
        };
      });

      return json(res, 200, {
        ok: true,
        deviceId: auth.device.id,
        consents
      });
    }

    if (providerConsentPaths.includes(url.pathname) &&
        req.method === 'POST') {
      const data = await body(req);
      const auth = await participantDeviceFor(req, data.deviceId);

      if (auth.error) {
        const status = auth.error === 'PARTICIPANT_SESSION_INVALID' ? 401 :
          auth.error === 'DEVICE_ID_REQUIRED' ? 400 : 403;
        return json(res, status, { error: auth.error });
      }

      const provider = String(data.provider || '').trim();
      const versions = {};

      if (!versions[provider]) {
        return json(res, 400, {
          error: 'Unsupported provider',
          supportedProviders: Object.keys(versions)
        });
      }

      if (data.accepted !== true ||
          data.disclosureVersion !== versions[provider]) {
        return json(res, 400, {
          error: 'Explicit provider consent and current disclosure version are required',
          requiredDisclosureVersion: versions[provider]
        });
      }

      const acceptedAt = now();
      db.prepare(`
        INSERT INTO provider_consents
          (node_id,provider,status,disclosure_version,accepted_at,revoked_at)
        VALUES(?,?,'accepted',?,?,NULL)
        ON CONFLICT(node_id,provider) DO UPDATE SET
          status='accepted',
          disclosure_version=excluded.disclosure_version,
          accepted_at=excluded.accepted_at,
          revoked_at=NULL
      `).run(auth.device.id, provider, versions[provider], acceptedAt);

      return json(res, 200, {
        ok: true,
        deviceId: auth.device.id,
        provider,
        accepted: true,
        acceptedAt,
        disclosureVersion: versions[provider]
      });
    }

    if (url.pathname === '/api/participant/device/provider-consents/revoke' &&
        req.method === 'POST') {
      const data = await body(req);
      const auth = await participantDeviceFor(req, data.deviceId);

      if (auth.error) {
        const status = auth.error === 'PARTICIPANT_SESSION_INVALID' ? 401 :
          auth.error === 'DEVICE_ID_REQUIRED' ? 400 : 403;
        return json(res, status, { error: auth.error });
      }

      const provider = String(data.provider || '').trim();
      const supportedProviders = ['proxies_sx', 'honeygain'];

      if (!supportedProviders.includes(provider)) {
        return json(res, 400, {
          error: 'Unsupported provider',
          supportedProviders
        });
      }

      const revokedAt = now();
      db.prepare(`
        UPDATE provider_consents
        SET status='revoked', revoked_at=?
        WHERE node_id=? AND provider=? AND status='accepted'
      `).run(revokedAt, auth.device.id, provider);

      return json(res, 200, {
        ok: true,
        deviceId: auth.device.id,
        provider,
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

      const monthKey = getRoarNetBaghdadMonth();
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

      let recorded;
      try {
        recorded = recordTrafficEventWithFifo({
          reference, nodeId, customerId, bytes, monthKey
        });
      } catch (e) {
        const code = String(e.message);

        if (code === 'DUPLICATE_USAGE_REFERENCE') {
          return json(res, 409, { error: 'Duplicate usage reference' });
        }
        if (code === 'INSUFFICIENT_PREPAID_BALANCE') {
          return json(res, 402, { error: 'Insufficient prepaid traffic balance' });
        }
        if (code === 'PARTICIPANT_CONSENT_REQUIRED') {
          return json(res, 403, { error: 'Participant consent required' });
        }
        if (code === 'INACTIVE_NODE_OR_CUSTOMER') {
          return json(res, 403, { error: 'Active node and customer required' });
        }
        if (code === 'NODE_MONTHLY_CAP_REACHED') {
          return json(res, 429, { error: 'Node monthly cap reached' });
        }
        if (code === 'CUSTOMER_MONTHLY_CAP_REACHED') {
          return json(res, 429, { error: 'Customer monthly cap reached' });
        }
        if (code === 'FIFO_ALLOCATION_INCOMPLETE') {
          return json(res, 409, { error: 'FIFO allocation could not cover this usage event' });
        }
        throw e;
      }

      return json(res, 201, {
        ok: true,
        measuredBytes: bytes,
        participantRemainingBytes: MONTHLY_CAP_BYTES - recorded.nodeUsed,
        customerRemainingBytes: MONTHLY_CAP_BYTES - recorded.customerUsed,
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
      ).get(getRoarNetBaghdadMonth());

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
      const monthKey = getRoarNetBaghdadMonth();

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

    // ROARNET_BUYER_REQUESTS_API_V1
    if (req.method === 'GET' &&
        url.pathname.startsWith('/api/store/buyer-requests/')) {
      const customer = customerFor(req);
      if (!customer) {
        return json(res, 401, { error: 'Valid customer token required' });
      }

      const prefix = '/api/store/buyer-requests/';
      const buyerRequestId = decodeURIComponent(
        url.pathname.slice(prefix.length)
      );

      if (!/^[0-9a-f-]{36}$/i.test(buyerRequestId) ||
          buyerRequestId.includes('/')) {
        return json(res, 400, { error: 'Invalid buyer request ID' });
      }

      const timestamp = now();

      db.exec('BEGIN IMMEDIATE');
      try {
        const request = db.prepare(`
          SELECT buyer_request_id, status, created_at,
            updated_at, expires_at, destination_host,
            destination_port, protocol, decision_reason
          FROM buyer_requests
          WHERE buyer_request_id = ? AND customer_id = ?
        `).get(buyerRequestId, customer.id);

        if (!request) {
          db.exec('ROLLBACK');
          return json(res, 404, { error: 'Buyer request not found' });
        }

        if (request.status === 'pending_provider_assignment' &&
            request.expires_at <= timestamp) {
          db.prepare(`
            UPDATE buyer_requests
            SET status = 'expired', updated_at = ?,
                decision_reason = 'REQUEST_EXPIRED'
            WHERE buyer_request_id = ?
              AND status = 'pending_provider_assignment'
          `).run(timestamp, buyerRequestId);

          db.prepare(`
            UPDATE relay_sessions
            SET status = 'EXPIRED', ended_at = ?,
                updated_at = ?, failure_code = 'BUYER_REQUEST_EXPIRED'
            WHERE buyer_request_id = ? AND status = 'PENDING'
          `).run(timestamp, timestamp, buyerRequestId);

          request.status = 'expired';
          request.updated_at = timestamp;
          request.decision_reason = 'REQUEST_EXPIRED';
        }

        const relaySession = db.prepare(`
          SELECT session_id, status, expires_at
          FROM relay_sessions
          WHERE buyer_request_id = ? AND customer_id = ?
          ORDER BY created_at DESC
          LIMIT 1
        `).get(buyerRequestId, customer.id);

        db.exec('COMMIT');
        return json(res, 200, {
          buyerRequest: request,
          relaySession: relaySession ? {
            sessionId: relaySession.session_id,
            status: relaySession.status,
            expiresAt: relaySession.expires_at
          } : null
        });
      } catch (error) {
        try { db.exec('ROLLBACK'); } catch {}
        throw error;
      }
    }

    if (req.method === 'POST' &&
        url.pathname.startsWith('/api/store/buyer-requests/') &&
        url.pathname.endsWith('/cancel')) {
      const customer = customerFor(req);
      if (!customer) {
        return json(res, 401, { error: 'Valid customer token required' });
      }

      const prefix = '/api/store/buyer-requests/';
      const buyerRequestId = decodeURIComponent(
        url.pathname.slice(prefix.length, -'/cancel'.length)
      );

      if (!/^[0-9a-f-]{36}$/i.test(buyerRequestId) ||
          buyerRequestId.includes('/')) {
        return json(res, 400, { error: 'Invalid buyer request ID' });
      }

      const timestamp = now();

      db.exec('BEGIN IMMEDIATE');
      try {
        const request = db.prepare(`
          SELECT buyer_request_id, status
          FROM buyer_requests
          WHERE buyer_request_id = ? AND customer_id = ?
        `).get(buyerRequestId, customer.id);

        if (!request) {
          db.exec('ROLLBACK');
          return json(res, 404, { error: 'Buyer request not found' });
        }

        if (request.status === 'cancelled') {
          db.exec('COMMIT');
          return json(res, 200, {
            success: true,
            buyerRequestId,
            status: 'cancelled',
            reused: true
          });
        }

        if (request.status !== 'pending_provider_assignment') {
          db.exec('ROLLBACK');
          return json(res, 409, {
            error: 'BUYER_REQUEST_NOT_CANCELLABLE',
            status: request.status
          });
        }

        db.prepare(`
          UPDATE buyer_requests
          SET status = 'cancelled', updated_at = ?,
              decision_reason = 'CANCELLED_BY_CUSTOMER'
          WHERE buyer_request_id = ?
            AND status = 'pending_provider_assignment'
        `).run(timestamp, buyerRequestId);

        db.prepare(`
          UPDATE relay_sessions
          SET status = 'REJECTED', ended_at = ?,
              updated_at = ?, failure_code = 'BUYER_REQUEST_CANCELLED'
          WHERE buyer_request_id = ? AND status = 'PENDING'
        `).run(timestamp, timestamp, buyerRequestId);

        db.exec('COMMIT');
        return json(res, 200, {
          success: true,
          buyerRequestId,
          status: 'cancelled'
        });
      } catch (error) {
        try { db.exec('ROLLBACK'); } catch {}
        throw error;
      }
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



    // ROARNET_PROVIDER_STATUS_V2
    if (req.method === 'GET' && url.pathname === '/api/admin/provider/status') {
      const apiKey = process.env.PROXIES_SX_API_KEY || '';

      const readiness = {
        trafficReady: false,
        buyerAssignmentReady: false,
        sessionProvisioningReady: false,
        integrationStage: 'PRICEBOOK_CHECK_ONLY',
        authorizationRequired: true,
        officialTrafficApiConfigured: false
      };

      if (!apiKey) {
        return json(res, 200, {
          configured: false,
          connected: false,
          resellerAccess: false,
          ...readiness,
          message: 'PROXIES_SX_API_KEY is not configured'
        });
      }

      try {
        const response = await fetch(
          'https://api.proxies.sx/v1/reseller/pricebook',
          {
            method: 'GET',
            headers: {
              'X-API-Key': apiKey,
              'Accept': 'application/json'
            },
            signal: AbortSignal.timeout(10000)
          }
        );

        return json(res, 200, {
          configured: true,
          connected: response.ok,
          resellerAccess: response.ok,
          httpStatus: response.status,
          ...readiness,
          message: response.ok
            ? 'Pricebook access confirmed; traffic integration is not enabled'
            : 'Provider rejected the pricebook request'
        });
      } catch {
        return json(res, 200, {
          configured: true,
          connected: false,
          resellerAccess: false,
          ...readiness,
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
      const participantCents = Math.floor(netCents * 50 / 100);
      const ownerCents = netCents - participantCents;
      const order = db.prepare('SELECT * FROM orders WHERE id=?').get(confirmOrderMatch[1]);
      if (!order) return json(res, 404, { error: 'Order not found' });
      if (order.status !== 'pending') return json(res, 409, { error: 'Order is not pending' });
      if (netCents > Number(order.price_cents)) return json(res, 400, { error: 'Net revenue cannot exceed the order gross amount' });
      try {
        db.exec('BEGIN IMMEDIATE');
        const changed = db.prepare("UPDATE orders SET status='paid',payment_provider=?,payment_reference=?,net_cents=?,paid_at=? WHERE id=? AND status='pending'")
          .run(provider, paymentReference, netCents, now(), order.id);
        if (Number(changed.changes) !== 1) throw new Error('ORDER_STATE_CHANGED');
        db.prepare(`INSERT INTO net_revenue(
          reference,net_cents,created_at,order_id,owner_share_cents,participant_pool_cents
        ) VALUES(?,?,?,?,?,?)`).run(
          'roarnet-order-' + order.id, netCents, now(), order.id, ownerCents, participantCents
        );
        db.exec('COMMIT');
      } catch (e) {
        try { db.exec('ROLLBACK'); } catch {}
        if (String(e.message).includes('UNIQUE')) return json(res, 409, { error: 'Payment reference or order revenue already recorded' });
        if (e.message === 'ORDER_STATE_CHANGED') return json(res, 409, { error: 'Order state changed; reload orders' });
        throw e;
      }
      const reserveCents = 0;
      return json(res, 200, {
        ok: true, orderId: order.id, status: 'paid',
        grossUsd: Number((Number(order.price_cents) / 100).toFixed(2)),
        verifiedNetUsd: Number((netCents / 100).toFixed(2)),
        ownerShare50Usd: Number((ownerCents / 100).toFixed(2)),
        participantPool50Usd: Number((participantCents / 100).toFixed(2)),
        operatingReserve0Usd: Number((reserveCents / 100).toFixed(2)),
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


    // ROARNET_ADMIN_WITHDRAWAL_MANAGEMENT_V1

    if (req.method === 'GET' && url.pathname === '/api/admin/withdrawals') {
      if (!isAdmin(req)) return json(res, 401, { error: 'Unauthorized' });

      const withdrawals = db.prepare(`
        SELECT id, participant_id, amount_cents, destination_address,
               payout_method, network, status, attempt_count, last_error,
               created_at, updated_at, processed_at,
               payout_reference, admin_note
        FROM withdrawal_requests
        ORDER BY
          CASE status
            WHEN 'queued' THEN 1
            WHEN 'processing' THEN 2
            WHEN 'failed' THEN 3
            WHEN 'paid' THEN 4
            ELSE 5
          END,
          created_at ASC
        LIMIT 300
      `).all();

      return json(res, 200, { ok: true, withdrawals });
    }

    const adminWithdrawalMatch =
      url.pathname.match(/^\/api\/admin\/withdrawals\/([0-9]+)\/status$/);

    if (req.method === 'POST' && adminWithdrawalMatch) {
      if (!isAdmin(req)) return json(res, 401, { error: 'Unauthorized' });

      const withdrawalId = Number(adminWithdrawalMatch[1]);
      if (!Number.isSafeInteger(withdrawalId) || withdrawalId <= 0) {
        return json(res, 400, { error: 'Invalid withdrawal ID' });
      }

      const data = await body(req);
      const status = String(data.status || '').trim();
      const payoutReference = String(data.payoutReference || '').trim();
      const adminNote = String(data.adminNote || '').trim();

      if (!['processing', 'paid', 'failed'].includes(status)) {
        return json(res, 400, { error: 'Invalid withdrawal status' });
      }

      const payoutMethodRow = db.prepare(`
        SELECT payout_method
        FROM withdrawal_requests
        WHERE id=?
      `).get(withdrawalId);

      const payoutMethod = payoutMethodRow?.payout_method || 'usdt_trc20';

      if (status === 'paid') {
        const validReference = payoutMethod === 'usdt_trc20'
          ? /^[a-fA-F0-9]{64}$/.test(payoutReference)
          : payoutReference.length >= 3 && payoutReference.length <= 200;

        if (!validReference) {
          return json(res, 400, {
            error: payoutMethod === 'usdt_trc20'
              ? 'A valid 64-character TRON transaction hash is required'
              : 'A valid payout reference is required'
          });
        }
      }

      if (status === 'failed' && adminNote.length < 3) {
        return json(res, 400, {
          error: 'A reason is required when rejecting a withdrawal'
        });
      }

      db.exec('BEGIN IMMEDIATE');
      try {
        const row = db.prepare(`
          SELECT id, status
          FROM withdrawal_requests
          WHERE id=?
        `).get(withdrawalId);

        if (!row) {
          db.exec('ROLLBACK');
          return json(res, 404, { error: 'Withdrawal not found' });
        }

        const validTransition =
          (status === 'processing' && row.status === 'queued') ||
          (status === 'failed' &&
            ['queued', 'processing'].includes(row.status)) ||
          (status === 'paid' && row.status === 'processing');

        if (!validTransition) {
          db.exec('ROLLBACK');
          return json(res, 409, {
            error: 'Invalid status transition',
            currentStatus: row.status
          });
        }

        const timestamp = now();

        const result = db.prepare(`
          UPDATE withdrawal_requests
          SET status=?,
              payout_reference=CASE
                WHEN ?='paid' THEN ?
                ELSE payout_reference
              END,
              admin_note=CASE
                WHEN ?<>'' THEN ?
                ELSE admin_note
              END,
              attempt_count=CASE
                WHEN ?='processing' THEN attempt_count+1
                ELSE attempt_count
              END,
              updated_at=?,
              processed_at=CASE
                WHEN ? IN ('paid','failed') THEN ?
                ELSE processed_at
              END
          WHERE id=? AND status=?
        `).run(
          status,
          status, payoutReference,
          adminNote, adminNote,
          status,
          timestamp,
          status, timestamp,
          withdrawalId, row.status
        );

        if (Number(result.changes) !== 1) {
          db.exec('ROLLBACK');
          return json(res, 409, { error: 'Withdrawal changed concurrently' });
        }

        db.exec('COMMIT');

        return json(res, 200, {
          ok: true,
          id: withdrawalId,
          status,
          payoutReference: status === 'paid' ? payoutReference : null
        });
      } catch (error) {
        try { db.exec('ROLLBACK'); } catch (_) {}
        throw error;
      }
    }

    // END ROARNET_ADMIN_WITHDRAWAL_MANAGEMENT_V1

    if (req.method === 'GET' && url.pathname === '/api/admin/settlements') {
      const rows = db.prepare(`
        SELECT month_key, revenue_cents, owner_share_cents,
               participant_pool_cents, operating_reserve_cents,
               allocated_cents, unallocated_cents, completed_at
        FROM settlement_batches
        WHERE status = 'completed'
        ORDER BY month_key DESC
        LIMIT 36
      `).all();

      const bi = value => BigInt(String(value ?? 0));

      const reconcileMonth = batch => {
        const monthKey = String(batch.month_key);
        const issues = [];

        const entries = db.prepare(`
          SELECT COALESCE(SUM(revenue_cents),0) revenue,
                 COALESCE(SUM(pool_cents),0) pool,
                 COALESCE(SUM(owner_share_cents),0) owner,
                 COALESCE(SUM(CASE WHEN owner_share_cents IS NULL THEN 1 ELSE 0 END),0) owner_unknown,
                 COALESCE(SUM(amount_cents),0) allocated,
                 COUNT(*) entry_count
          FROM participant_earning_entries
          WHERE substr(month_key,1,7)=?
        `).get(monthKey);

        const earnings = db.prepare(`
          SELECT COALESCE(SUM(amount_cents),0) allocated
          FROM participant_earnings WHERE month_key=?
        `).get(monthKey);

        const sourceRows = db.prepare(`
          SELECT participant_id,
                 SUM(contribution_bytes) contribution_bytes,
                 SUM(revenue_cents) revenue_cents,
                 SUM(amount_cents) amount_cents
          FROM participant_earning_entries
          WHERE substr(month_key,1,7)=?
            AND participant_id IS NOT NULL AND amount_cents>0
          GROUP BY participant_id
        `).all(monthKey);

        const earningRows = db.prepare(`
          SELECT participant_id, contribution_bytes, revenue_cents, amount_cents
          FROM participant_earnings WHERE month_key=?
        `).all(monthKey);

        const compare = (label, actual, expected) => {
          if (bi(actual) !== bi(expected)) issues.push(label);
        };

        const revenue = bi(batch.revenue_cents);
        const pool = bi(batch.participant_pool_cents);
        const owner = bi(batch.owner_share_cents);
        const reserve = bi(batch.operating_reserve_cents);
        const allocated = bi(batch.allocated_cents);
        const unallocated = bi(batch.unallocated_cents);

        const ownerUnknown = Number(entries.owner_unknown || 0);
        const expectedOwner = bi(entries.owner);

        compare('إيراد القيود لا يطابق التسوية', entries.revenue, revenue);
        compare('حصة المشاركين لا تطابق القيود', entries.pool, pool);
        compare('الموزع في القيود لا يطابق التسوية', entries.allocated, allocated);
        compare('إجمالي أرباح المشاركين لا يطابق الموزع', earnings.allocated, allocated);
        if (ownerUnknown === 0 && batch.owner_share_cents !== null) {
          compare('حصة المالك لا تطابق لقطات القيود المحفوظة', owner, expectedOwner);
        }
        if (batch.owner_share_cents !== null &&
            batch.operating_reserve_cents !== null) {
          compare('مجموع الحصص لا يساوي الإيراد', revenue, owner + pool + reserve);
        }
        compare('الموزع وغير الموزع لا يساويان حصة المشاركين',
                pool, allocated + unallocated);

        const sourceMap = new Map(sourceRows.map(r => [String(r.participant_id), r]));
        const earningMap = new Map(earningRows.map(r => [String(r.participant_id), r]));
        const ids = new Set([...sourceMap.keys(), ...earningMap.keys()]);

        for (const id of ids) {
          const a = sourceMap.get(id);
          const b = earningMap.get(id);

          if (!a || !b ||
              bi(a.contribution_bytes) !== bi(b.contribution_bytes) ||
              bi(a.revenue_cents) !== bi(b.revenue_cents) ||
              bi(a.amount_cents) !== bi(b.amount_cents)) {
            issues.push('اختلاف قيود أرباح المشارك: ' + id);
          }
        }

        const orderCheck = db.prepare(`
          SELECT COUNT(*) mismatches
          FROM (
            SELECT DISTINCT order_id
            FROM participant_earning_entries
            WHERE substr(month_key,1,7)=? AND order_id IS NOT NULL
          ) used
          LEFT JOIN orders o ON o.id=used.order_id
          LEFT JOIN net_revenue r ON r.order_id=o.id
          WHERE o.id IS NULL OR o.status<>'paid' OR o.net_cents IS NULL
             OR r.id IS NULL OR r.net_cents<>o.net_cents
        `).get(monthKey);

        const orderMismatches = Number(orderCheck.mismatches || 0);
        if (orderMismatches) issues.push('عدم تطابق ربط إيراد الطلبات');

        return {
          status: issues.length ? 'mismatch' : 'matched',
          issueCount: issues.length,
          issues,
          checkedParticipants: ids.size,
          checkedEntries: Number(entries.entry_count || 0),
          ownerSnapshotStatus: ownerUnknown === 0 ? 'verified' : 'historical-snapshot-unavailable',
          ownerSnapshotUnknownRows: ownerUnknown,
          orderMismatches
        };
      };

      return json(res, 200, {
        settlements: rows.map(row => ({
          monthKey: String(row.month_key),
          revenueUsd: Number((Number(row.revenue_cents)/100).toFixed(2)),
          ownerShareUsd: row.owner_share_cents === null ? null : Number((Number(row.owner_share_cents)/100).toFixed(2)),
          participantPoolUsd: Number((Number(row.participant_pool_cents)/100).toFixed(2)),
          operatingReserveUsd: row.operating_reserve_cents === null ? null : Number((Number(row.operating_reserve_cents)/100).toFixed(2)),
          allocatedUsd: Number((Number(row.allocated_cents)/100).toFixed(2)),
          unallocatedUsd: Number((Number(row.unallocated_cents)/100).toFixed(2)),
          completedAt: row.completed_at,
          reconciliation: reconcileMonth(row)
        }))
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/admin/summary') {
      const usage = db.prepare(
        'SELECT COALESCE(SUM(bytes),0) AS bytes, COUNT(*) AS events FROM usage_events'
      ).get();
      const nodes = db.prepare(
        "SELECT COUNT(*) AS count FROM nodes WHERE status='active'"
      ).get().count;
      const revenueTotals = db.prepare(`
        SELECT
          COALESCE(SUM(net_cents),0) AS cents,
          COALESCE(SUM(owner_share_cents),0) AS owner_cents,
          COALESCE(SUM(participant_pool_cents),0) AS participant_cents,
          COALESCE(SUM(CASE
            WHEN owner_share_cents IS NULL OR participant_pool_cents IS NULL
            THEN net_cents ELSE 0 END),0) AS unclassified_cents
        FROM net_revenue
      `).get();
      const cents = Number(revenueTotals.cents);
      const ownerCents = Number(revenueTotals.owner_cents);
      const participantCents = Number(revenueTotals.participant_cents);
      const unclassifiedCents = Number(revenueTotals.unclassified_cents);
      const reserveCents = 0;

      const settlement = db.prepare(`
        SELECT
          COUNT(*) AS months,
          COALESCE(SUM(CASE WHEN owner_share_cents IS NULL THEN 1 ELSE 0 END), 0) AS unknown_owner_months,
          COALESCE(SUM(revenue_cents), 0) AS revenue_cents,
          COALESCE(SUM(owner_share_cents), 0) AS owner_share_cents,
          COALESCE(SUM(participant_pool_cents), 0) AS participant_pool_cents,
          COALESCE(SUM(operating_reserve_cents), 0) AS operating_reserve_cents,
          COALESCE(SUM(allocated_cents), 0) AS allocated_cents,
          COALESCE(SUM(unallocated_cents), 0) AS unallocated_cents
        FROM settlement_batches
        WHERE status = 'completed'
      `).get();

      return json(res, 200, {
        activeNodes: nodes,
        meteredBytes: Number(usage.bytes),
        usageEvents: Number(usage.events),
        recordedNetRevenueUsd: Number((cents / 100).toFixed(2)),
        ownerShare50Usd: Number((ownerCents / 100).toFixed(2)),
        participantPool50Usd: Number((participantCents / 100).toFixed(2)),
        unclassifiedNetRevenueUsd: Number((unclassifiedCents / 100).toFixed(2)),
        operatingReserve0Usd: Number((reserveCents / 100).toFixed(2)),
        completedSettlementMonths: Number(settlement.months),
        settledSplitUnknownMonths: Number(settlement.unknown_owner_months),
        settledRevenueUsd: Number((settlement.revenue_cents / 100).toFixed(2)),
        settledOwnerShareUsd: Number((settlement.owner_share_cents / 100).toFixed(2)),
        settledParticipantPoolUsd: Number((settlement.participant_pool_cents / 100).toFixed(2)),
        settledOperatingReserveUsd: Number((settlement.operating_reserve_cents / 100).toFixed(2)),
        settledParticipantAllocatedUsd: Number((settlement.allocated_cents / 100).toFixed(2)),
        settledParticipantUnallocatedUsd: Number((settlement.unallocated_cents / 100).toFixed(2)),
        paidOrderCount: Number(db.prepare("SELECT COUNT(*) AS n FROM orders WHERE status='paid'").get().n),
        pendingOrderCount: Number(db.prepare("SELECT COUNT(*) AS n FROM orders WHERE status='pending'").get().n),
        note: 'Only manually verified paid orders add net revenue. This core does not yet connect to an automatic payment provider or send payouts.'
      });
    }


    // ROARNET_OWNER_IDENTITY_API_V1
    if (url.pathname === '/api/admin/owner' &&
        req.method === 'GET') {
      const owner = db.prepare(`
        SELECT owner_id, display_name, role,
               owner_share_percent, created_at
        FROM project_owner
        WHERE singleton = 1
      `).get();

      return json(res, 200, {
        owner,
        identitySource: 'RoarNet primary owner record',
        note: 'Owner identity is registered. Revenue allocation and payouts require settlement integration.'
      });
    }
    // END ROARNET_OWNER_IDENTITY_API_V1

    // ROARNET_PROVIDER_REVENUE_INTAKE_API_V1
    if (url.pathname === '/api/admin/provider-revenue' &&
        req.method === 'GET') {
      const rows = db.prepare(`
        SELECT provider, reference, net_cents, currency, status,
               owner_share_cents, participant_pool_cents, created_at
        FROM provider_revenue_intake
        ORDER BY id DESC
        LIMIT 500
      `).all();

      return json(res, 200, {
        receipts: rows.map(row => ({
          provider: row.provider,
          reference: row.reference,
          netUsd: Number((row.net_cents / 100).toFixed(2)),
          ownerShareUsd: row.owner_share_cents === null ? null : Number((row.owner_share_cents / 100).toFixed(2)),
          participantPoolUsd: row.participant_pool_cents === null ? null : Number((row.participant_pool_cents / 100).toFixed(2)),
          currency: row.currency,
          status: row.status,
          createdAt: row.created_at
        })),
        note: 'Received provider revenue is tracked separately and is not yet included in monthly settlement.'
      });
    }

    if (url.pathname === '/api/admin/provider-revenue' &&
        req.method === 'POST') {
      const b = await body(req);
      const provider = String(b.provider || '').trim();
      const reference = String(b.reference || '').trim();
      const amount = Number(b.netUsd);

      if (
        !/^[A-Za-z0-9_.-]{2,60}$/.test(provider) ||
        !/^[A-Za-z0-9_.:-]{4,160}$/.test(reference) ||
        !Number.isFinite(amount) ||
        amount <= 0 ||
        amount > 1000000
      ) {
        return json(res, 400, {
          error: 'Provide a valid provider, transaction reference and positive netUsd amount.'
        });
      }

      const cents = Math.round(amount * 100);
      if (!Number.isSafeInteger(cents) || cents < 1) {
        return json(res, 400, { error: 'Invalid amount precision' });
      }

      const participantPoolCents = Math.floor(cents * 50 / 100);
      const ownerShareCents = cents - participantPoolCents;

      try {
        db.prepare(`
          INSERT INTO provider_revenue_intake
            (provider, reference, net_cents, currency, status,
             owner_share_cents, participant_pool_cents, created_at)
          VALUES (?, ?, ?, 'USD', 'received', ?, ?, ?)
        `).run(provider, reference, cents, ownerShareCents, participantPoolCents, now());
      } catch (e) {
        if (String(e.message).includes('UNIQUE')) {
          return json(res, 409, {
            error: 'This provider transaction reference has already been recorded.'
          });
        }
        throw e;
      }

      return json(res, 201, {
        ok: true,
        provider,
        reference,
        receivedNetUsd: Number((cents / 100).toFixed(2)),
        ownerShareUsd: ownerShareCents / 100,
        participantPoolUsd: participantPoolCents / 100,
        status: 'received',
        includedInSettlement: false,
        note: 'Receipt recorded. Settlement inclusion requires verified participant traffic allocation.'
      });
    }
    // END ROARNET_PROVIDER_REVENUE_INTAKE_API_V1


    // ROARNET_PROVIDER_MONTHLY_SETTLEMENT_API_V1
    if (req.method === 'GET' &&
        url.pathname === '/api/admin/provider-settlements') {
      const rows = db.prepare(`
        SELECT *
        FROM provider_settlement_batches
        ORDER BY month_key DESC
        LIMIT 100
      `).all();

      return json(res, 200, {
        settlements: rows.map(row => ({
          monthKey: row.month_key,
          receiptCount: Number(row.receipt_count),
          revenueUsd: Number((row.revenue_cents / 100).toFixed(2)),
          ownerShareUsd: Number((row.owner_share_cents / 100).toFixed(2)),
          participantPoolUsd: Number((row.participant_pool_cents / 100).toFixed(2)),
          allocatedUsd: Number((row.allocated_cents / 100).toFixed(2)),
          unallocatedUsd: Number((row.unallocated_cents / 100).toFixed(2)),
          operatingReserveUsd: Number((row.operating_reserve_cents / 100).toFixed(2)),
          status: row.status,
          createdAt: row.created_at
        })),
        note: 'Provider settlements are separate from customer-order settlements. Participant funds remain reserved until verified allocation data is available.'
      });
    }

    if (req.method === 'POST' &&
        url.pathname === '/api/admin/provider-settlements/settle') {
      const b = await body(req);
      const monthKey = String(b.monthKey || '').trim();

      if (!/^20\d{2}-(0[1-9]|1[0-2])$/.test(monthKey)) {
        return json(res, 400, {
          error: 'Provide monthKey in YYYY-MM format.'
        });
      }

      // Only close past months; avoid settling an incomplete current month.
      if (monthKey >= getRoarNetBaghdadMonth()) {
        return json(res, 400, {
          error: 'Only a completed past month can be settled.'
        });
      }

      db.exec('BEGIN IMMEDIATE');

      try {
        const existing = db.prepare(`
          SELECT month_key, revenue_cents
          FROM provider_settlement_batches
          WHERE month_key = ?
        `).get(monthKey);

        if (existing) {
          db.exec('COMMIT');
          return json(res, 200, {
            ok: true,
            status: 'already-settled',
            monthKey,
            revenueUsd: Number((existing.revenue_cents / 100).toFixed(2))
          });
        }

        const totals = db.prepare(`
          SELECT
            COUNT(*) AS receipt_count,
            COALESCE(SUM(net_cents), 0) AS revenue_cents,
            COALESCE(SUM(owner_share_cents), 0) AS owner_share_cents,
            COALESCE(SUM(participant_pool_cents), 0) AS participant_pool_cents,
            COALESCE(SUM(CASE
              WHEN owner_share_cents IS NULL OR participant_pool_cents IS NULL
              THEN 1 ELSE 0 END), 0) AS unknown_split_count
          FROM provider_revenue_intake
          WHERE status = 'received'
            AND substr(created_at, 1, 7) = ?
        `).get(monthKey);

        const receiptCount = Number(totals.receipt_count);
        const revenueCents = Number(totals.revenue_cents);

        if (
          !Number.isSafeInteger(receiptCount) ||
          !Number.isSafeInteger(revenueCents) ||
          receiptCount < 1 ||
          revenueCents < 1
        ) {
          db.exec('ROLLBACK');
          return json(res, 404, {
            error: 'No unsettled provider receipts found for this month.'
          });
        }

        if (Number(totals.unknown_split_count) > 0) {
          db.exec('ROLLBACK');
          return json(res, 409, {
            error: 'Legacy provider receipts have no saved allocation snapshots; settlement is blocked.',
            monthKey,
            unknownReceipts: Number(totals.unknown_split_count)
          });
        }

        const revenue = BigInt(revenueCents);
        const ownerCents = BigInt(totals.owner_share_cents);
        const participantCents = BigInt(totals.participant_pool_cents);
        const reserveCents = revenue - ownerCents - participantCents;

        if (reserveCents !== 0n) {
          throw new Error('Provider receipt snapshots do not equal verified revenue.');
        }

        const owner = Number(ownerCents);
        const participants = Number(participantCents);
        const reserve = 0;

        if (![owner, participants, reserve].every(Number.isSafeInteger)) {
          throw new Error('Provider settlement amounts are unsafe.');
        }

        const timestamp = now();

        db.prepare(`
          INSERT INTO provider_settlement_batches (
            month_key, receipt_count, revenue_cents,
            owner_share_cents, participant_pool_cents,
            allocated_cents, unallocated_cents,
            operating_reserve_cents, status, created_at
          )
          VALUES (?, ?, ?, ?, ?, 0, ?, ?, 'completed', ?)
        `).run(
          monthKey,
          receiptCount,
          revenueCents,
          owner,
          participants,
          participants,
          reserve,
          timestamp
        );

        const update = db.prepare(`
          UPDATE provider_revenue_intake
          SET status = 'settled'
          WHERE status = 'received'
            AND substr(created_at, 1, 7) = ?
        `).run(monthKey);

        if (Number(update.changes) !== receiptCount) {
          throw new Error('Provider receipt count changed during settlement.');
        }

        db.exec('COMMIT');

        return json(res, 201, {
          ok: true,
          status: 'completed',
          monthKey,
          receiptCount,
          revenueUsd: revenueCents / 100,
          ownerShare50Usd: owner / 100,
          participantPool50Usd: participants / 100,
          allocatedToParticipantsUsd: 0,
          reservedForParticipantsUsd: participants / 100,
          operatingReserve0Usd: reserve / 100,
          note: 'Accounting settlement completed. Participant funds are reserved, not yet distributed. No money has been transferred.'
        });

      } catch (error) {
        try { db.exec('ROLLBACK'); } catch {}
        throw error;
      }
    }
    // END ROARNET_PROVIDER_MONTHLY_SETTLEMENT_API_V1

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
          'INSERT INTO net_revenue(reference,net_cents,created_at,owner_share_cents,participant_pool_cents) VALUES(?,?,?,?,?)'
        ).run(reference, cents, now(), cents - Math.floor(cents * 50 / 100), Math.floor(cents * 50 / 100));
      } catch (e) {
        if (String(e.message).includes('UNIQUE')) {
          return json(res, 409, { error: 'Duplicate revenue reference' });
        }
        throw e;
      }

      const participantCents = Math.floor(cents * 50 / 100);
      const ownerCents = cents - participantCents;
      const reserveCents = 0;

      return json(res, 201, {
        ok: true,
        recordedNetUsd: cents / 100,
        ownerShare50Usd: ownerCents / 100,
        participantPool50Usd: participantCents / 100,
        operatingReserve0Usd: reserveCents / 100,
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


// ROARNET_MONTHLY_SETTLEMENT_V2
// Automatic monthly settlement using Baghdad timezone.

const getRoarNetBaghdadMonth = () => {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: 'Asia/Baghdad',
    year: 'numeric',
    month: '2-digit'
  }).formatToParts(new Date());

  const year = parts.find(x => x.type === 'year').value;
  const month = parts.find(x => x.type === 'month').value;
  return `${year}-${month}`;
};

// Create only missing accounting tables.
// Existing financial rows are preserved.
db.exec(`
  CREATE TABLE IF NOT EXISTS settlement_batches (
    month_key TEXT PRIMARY KEY,
    revenue_cents INTEGER NOT NULL CHECK(revenue_cents >= 0),
    participant_pool_cents INTEGER NOT NULL CHECK(participant_pool_cents >= 0),
    allocated_cents INTEGER NOT NULL DEFAULT 0 CHECK(allocated_cents >= 0),
    unallocated_cents INTEGER NOT NULL DEFAULT 0 CHECK(unallocated_cents >= 0),
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK(status IN ('pending','completed')),
    created_at TEXT NOT NULL,
    completed_at TEXT
  );

  CREATE TABLE IF NOT EXISTS participant_earnings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    month_key TEXT NOT NULL REFERENCES settlement_batches(month_key),
    participant_id TEXT NOT NULL REFERENCES participants(id),
    contribution_bytes INTEGER NOT NULL CHECK(contribution_bytes > 0),
    revenue_cents INTEGER NOT NULL CHECK(revenue_cents >= 0),
    amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
    created_at TEXT NOT NULL,
    UNIQUE(month_key, participant_id)
  );
`);



// ROARNET_SETTLEMENT_OWNER_RESERVE_V1
{
  const columns = db.prepare(
    'PRAGMA table_info(settlement_batches)'
  ).all().map(c => c.name);

  if (!columns.includes('owner_share_cents')) {
    db.exec(`
      ALTER TABLE settlement_batches
      ADD COLUMN owner_share_cents INTEGER
      CHECK(owner_share_cents IS NULL OR owner_share_cents >= 0)
    `);
  }

  if (!columns.includes('operating_reserve_cents')) {
    db.exec(`
      ALTER TABLE settlement_batches
      ADD COLUMN operating_reserve_cents INTEGER
      CHECK(operating_reserve_cents IS NULL OR operating_reserve_cents >= 0)
    `);
  }

  const invalid = db.prepare(`
    SELECT COUNT(*) AS count
    FROM settlement_batches
    WHERE participant_pool_cents > revenue_cents
  `).get();

  if (Number(invalid.count) !== 0) {
    throw new Error('SETTLEMENT_OWNER_RESERVE_MIGRATION_INVALID');
  }

  // Historical settlement rows are immutable. Never infer or backfill their split.
}
// END ROARNET_SETTLEMENT_OWNER_RESERVE_V1

// ROARNET_WITHDRAWAL_SCHEMA_V1
db.exec(`
  CREATE TABLE IF NOT EXISTS withdrawal_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    participant_id TEXT NOT NULL
      REFERENCES participants(id),
    amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
    destination_address TEXT,
    network TEXT NOT NULL DEFAULT 'TRC20',
    provider_reference TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    status TEXT NOT NULL DEFAULT 'queued'
      CHECK(status IN ('queued','processing','paid','failed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    processed_at TEXT,
    payout_reference TEXT,
    admin_note TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_withdrawals_participant_status
    ON withdrawal_requests(participant_id, status);
`);
// END ROARNET_WITHDRAWAL_SCHEMA_V1

// ROARNET_WITHDRAWAL_PAYOUT_METHOD_MIGRATION_V1
{
  const columns = db.prepare(
    'PRAGMA table_info(withdrawal_requests)'
  ).all().map(column => column.name);

  if (!columns.includes('payout_method')) {
    db.exec(`
      ALTER TABLE withdrawal_requests
      ADD COLUMN payout_method TEXT NOT NULL DEFAULT 'usdt_trc20'
    `);
  }
}
// END ROARNET_WITHDRAWAL_PAYOUT_METHOD_MIGRATION_V1



function settleRoarNetMonth(monthKey) {
  db.exec('BEGIN IMMEDIATE');

  try {
    const existingBatch = db.prepare(`
      SELECT status
      FROM settlement_batches
      WHERE month_key = ?
    `).get(monthKey);

    if (existingBatch?.status === 'completed') {
      db.exec('COMMIT');
      return 'already-completed';
    }

    const revenueIntegrity = db.prepare(`
      SELECT COUNT(*) AS mismatches
      FROM (
        SELECT DISTINCT order_id
        FROM participant_earning_entries
        WHERE substr(month_key, 1, 7) = ?
      ) used
      JOIN orders o ON o.id = used.order_id
      LEFT JOIN net_revenue r ON r.order_id = o.id
      WHERE o.status <> 'paid'
         OR o.net_cents IS NULL
         OR r.id IS NULL
         OR r.net_cents <> o.net_cents
    `).get(monthKey);

    if (Number(revenueIntegrity.mismatches) !== 0) {
      throw new Error('ORDER_REVENUE_LEDGER_MISMATCH:' + monthKey);
    }

    const totals = db.prepare(`
      SELECT
        COALESCE(SUM(revenue_cents), 0) AS revenue,
        COALESCE(SUM(pool_cents), 0) AS pool,
        COALESCE(SUM(owner_share_cents), 0) AS owner,
        COALESCE(SUM(CASE WHEN owner_share_cents IS NULL THEN 1 ELSE 0 END), 0) AS owner_unknown
      FROM participant_earning_entries
      WHERE substr(month_key, 1, 7) = ?
    `).get(monthKey);

    if (Number(totals.owner_unknown) > 0) {
      throw new Error('SETTLEMENT_BLOCKED_LEGACY_OWNER_SPLIT_UNKNOWN:' + monthKey);
    }

    const revenueCents = Number(totals.revenue);
    const poolCents = Number(totals.pool);
    const ownerBigTotal = BigInt(totals.owner);

    if (
      !Number.isSafeInteger(revenueCents) ||
      !Number.isSafeInteger(poolCents) ||
      revenueCents < 0 ||
      poolCents < 0
    ) {
      throw new Error('Settlement revenue totals failed validation');
    }

    const revenueBig = BigInt(revenueCents);
    const poolBig = BigInt(poolCents);
    const ownerBig = ownerBigTotal;
    const reserveBig = revenueBig - ownerBig - poolBig;

    if (reserveBig !== 0n) {
      throw new Error('Settlement saved owner/participant snapshots do not equal revenue');
    }

    const ownerShareCents = Number(ownerBig);
    const reserveCents = 0;

    if (
      !Number.isSafeInteger(ownerShareCents) ||
      !Number.isSafeInteger(reserveCents)
    ) {
      throw new Error('Settlement owner/reserve totals are unsafe');
    }



    const sourceRows = db.prepare(`
      SELECT
        participant_id,
        SUM(contribution_bytes) AS contribution_bytes,
        SUM(revenue_cents) AS revenue_cents,
        SUM(amount_cents) AS amount_cents
      FROM participant_earning_entries
      WHERE substr(month_key, 1, 7) = ?
        AND participant_id IS NOT NULL
        AND amount_cents > 0
      GROUP BY participant_id
      ORDER BY participant_id
    `).all(monthKey);

    const existingRows = db.prepare(`
      SELECT participant_id, contribution_bytes,
             revenue_cents, amount_cents
      FROM participant_earnings
      WHERE month_key = ?
    `).all(monthKey);

    const sourceMap = new Map(
      sourceRows.map(row => [row.participant_id, row])
    );

    // Never silently overwrite or ignore inconsistent financial rows.
    for (const row of existingRows) {
      const source = sourceMap.get(row.participant_id);

      if (
        !source ||
        Number(row.contribution_bytes) !== Number(source.contribution_bytes) ||
        Number(row.revenue_cents) !== Number(source.revenue_cents) ||
        Number(row.amount_cents) !== Number(source.amount_cents)
      ) {
        throw new Error(
          `Existing earning mismatch for participant ${row.participant_id}`
        );
      }
    }

    const timestamp = now();

    db.prepare(`
      INSERT INTO settlement_batches (
        month_key, revenue_cents, participant_pool_cents,
        allocated_cents, unallocated_cents,
        owner_share_cents, operating_reserve_cents,
        status, created_at, completed_at
      )
      VALUES (?, ?, ?, 0, ?, ?, ?, 'pending', ?, NULL)
      ON CONFLICT(month_key) DO NOTHING
    `).run(
      monthKey,
      revenueCents,
      poolCents,
      poolCents,
      ownerShareCents,
      reserveCents,
      timestamp
    );

    const insertEarning = db.prepare(`
      INSERT INTO participant_earnings (
        month_key, participant_id, contribution_bytes,
        revenue_cents, amount_cents, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    const existingIds = new Set(
      existingRows.map(row => row.participant_id)
    );

    for (const row of sourceRows) {
      if (existingIds.has(row.participant_id)) continue;

      insertEarning.run(
        monthKey,
        row.participant_id,
        Number(row.contribution_bytes),
        Number(row.revenue_cents),
        Number(row.amount_cents),
        timestamp
      );
    }

    const allocated = db.prepare(`
      SELECT COALESCE(SUM(amount_cents), 0) AS cents
      FROM participant_earnings
      WHERE month_key = ?
    `).get(monthKey).cents;

    const pool = poolCents;
    const allocatedCents = Number(allocated);

    if (
      !Number.isSafeInteger(pool) ||
      !Number.isSafeInteger(allocatedCents) ||
      pool < 0 ||
      allocatedCents < 0 ||
      allocatedCents > pool
    ) {
      throw new Error('Settlement totals failed financial validation');
    }

    const unallocated = pool - allocatedCents;

    db.prepare(`
      UPDATE settlement_batches
      SET revenue_cents = ?,
          participant_pool_cents = ?,
          allocated_cents = ?,
          unallocated_cents = ?,
          owner_share_cents = ?,
          operating_reserve_cents = ?,
          status = 'completed',
          completed_at = ?
      WHERE month_key = ?
        AND status = 'pending'
    `).run(
      revenueCents,
      pool,
      allocatedCents,
      unallocated,
      ownerShareCents,
      reserveCents,
      timestamp,
      monthKey
    );

    db.exec('COMMIT');
    return 'completed';

  } catch (error) {
    try {
      db.exec('ROLLBACK');
    } catch {}

    throw error;
  }
}

function runRoarNetMonthlySettlement() {
  try {
    const currentMonth = getRoarNetBaghdadMonth();

    // Include traffic months even if no participant earned anything.
    // Also recover months that have earning entries but no traffic row.
    const months = db.prepare(`
      SELECT month_key FROM (
        SELECT DISTINCT substr(month_key, 1, 7) AS month_key
        FROM traffic_events

        UNION

        SELECT DISTINCT substr(month_key, 1, 7) AS month_key
        FROM participant_earning_entries
      )
      WHERE month_key GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]'
        AND month_key < ?
      ORDER BY month_key
    `).all(currentMonth);

    for (const row of months) {
      try {
        const result = settleRoarNetMonth(row.month_key);
        console.log(
          '[RoarNet monthly settlement]',
          row.month_key,
          result
        );
      } catch (error) {
        console.error(
          '[RoarNet settlement blocked]',
          row.month_key,
          error.message
        );
      }
    }
  } catch (error) {
    console.error(
      '[RoarNet settlement scheduler]',
      error.message
    );
  }
}

// Recover eligible months after every server startup.
runRoarNetMonthlySettlement();

// Retry pending months every 15 minutes.
const roarNetMonthlySettlementTimer = setInterval(
  runRoarNetMonthlySettlement,
  15 * 60 * 1000
);

if (typeof roarNetMonthlySettlementTimer.unref === 'function') {
  roarNetMonthlySettlementTimer.unref();
}

// END ROARNET_MONTHLY_SETTLEMENT_V2



// ROARNET_ANDROID_GATEWAY_AUTOSTART_V1
// Start the authenticated Relay Gateway in the same Node process.
try {
  await import('./relay/gateway.mjs');
  console.log('[RoarNet] Relay Gateway module loaded on port 3182');
} catch (error) {
  console.error('[RoarNet] Relay Gateway startup failed:', error);
}
// END ROARNET_ANDROID_GATEWAY_AUTOSTART_V1

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
