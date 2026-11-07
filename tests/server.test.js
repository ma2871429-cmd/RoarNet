import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

async function freePort() {
  return await new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

test('health, auth, demo ledger, and dashboard are reachable', async (t) => {
  const port = await freePort();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'roarnet-test-'));
  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', SESSION_SECRET: 'test-secret-'.repeat(4), ADMIN_USER: 'test-admin', ADMIN_PASSWORD: 'A-strong-test-password-123', DB_PATH: path.join(dir, 'test.sqlite'), PROVIDER_ENABLED: 'false', PAYOUTS_ENABLED: 'false' },
    stdio: 'ignore'
  });
  t.after(() => { child.kill('SIGTERM'); fs.rmSync(dir, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${port}`;
  let health;
  for (let i = 0; i < 60; i++) {
    try { health = await fetch(`${base}/api/health`); break; } catch { await delay(100); }
  }
  assert.ok(health, 'server should start');
  assert.equal(health.status, 200);
  const h = await health.json();
  assert.equal(h.app, 'RoarNet');
  assert.equal(h.provider, 'not_connected');

  const denied = await fetch(`${base}/api/dashboard`);
  assert.equal(denied.status, 401);

  const login = await fetch(`${base}/api/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'test-admin', password: 'A-strong-test-password-123' }) });
  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie').split(';')[0];

  const credit = await fetch(`${base}/api/demo-credit`, { method: 'POST', headers: { cookie, 'content-type': 'application/json' }, body: JSON.stringify({ amount: 0.01 }) });
  assert.equal(credit.status, 201);
  const c = await credit.json();
  assert.equal(c.totals.demoUsd, 0.01);
  assert.equal(c.totals.confirmedUsd, 0);

  const dashboard = await fetch(`${base}/api/dashboard`, { headers: { cookie } });
  assert.equal(dashboard.status, 200);
  const d = await dashboard.json();
  assert.equal(d.ledger.length, 1);
  assert.equal(d.ledger[0].kind, 'demo');
});

test('provider settings are saved encrypted in an isolated test database', async (t) => {
  const port = await freePort();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'roarnet-provider-test-'));
  const dbPath = path.join(dir, 'test.sqlite');
  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: {
      ...process.env,
      PORT: String(port),
      HOST: '127.0.0.1',
      SESSION_SECRET: 'provider-test-session-secret-123456789',
      APP_ENCRYPTION_KEY: 'roarnet-test-encryption-key-32chars-minimum',
      ADMIN_USER: 'provider-test-admin',
      ADMIN_PASSWORD: 'Provider-test-password-123!',
      DB_PATH: dbPath,
      PROVIDER_ENABLED: 'false',
      PAYOUTS_ENABLED: 'false'
    },
    stdio: 'ignore'
  });

  t.after(() => {
    child.kill('SIGTERM');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const base = `http://127.0.0.1:${port}`;
  let ready = false;
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`${base}/api/health`);
      if (r.ok) { ready = true; break; }
    } catch {}
    await delay(100);
  }
  assert.ok(ready, 'test server should start');

  const login = await fetch(`${base}/api/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      username: 'provider-test-admin',
      password: 'Provider-test-password-123!'
    })
  });
  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie').split(';')[0];

  const apiKey = 'FAKE_TEST_API_KEY_123';
  const deviceToken = 'FAKE_TEST_DEVICE_TOKEN_456';
  const saved = await fetch(`${base}/api/provider/settings`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json' },
    body: JSON.stringify({
      name: 'Test Provider',
      apiBase: 'https://api.example.test',
      deviceId: 'test-device-001',
      apiKey,
      deviceToken
    })
  });
  assert.equal(saved.status, 200, await saved.text());

  const response = await fetch(`${base}/api/provider/settings`, {
    headers: { cookie }
  });
  assert.equal(response.status, 200);
  const settings = await response.json();
  assert.equal(settings.name, 'Test Provider');
  assert.equal(settings.hasApiKey, true);
  assert.equal(settings.hasDeviceToken, true);
  assert.equal(settings.enabled, false);

  const { DatabaseSync } = await import('node:sqlite');
  const db = new DatabaseSync(dbPath, { readOnly: true });
  try {
    const rows = db.prepare(
      "SELECT key, value FROM app_settings WHERE key IN ('apiKey','token')"
    ).all();
    assert.equal(rows.length, 2);
    for (const row of rows) {
      assert.ok(row.value.includes('.'), 'encrypted value should contain separators');
      assert.ok(!row.value.includes(apiKey));
      assert.ok(!row.value.includes(deviceToken));
    }
  } finally {
    db.close();
  }
});


test('homepage and health are public, provider settings require authentication', async (t) => {
  const port = await freePort();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'roarnet-security-test-'));

  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: {
      ...process.env,
      PORT: String(port),
      HOST: '127.0.0.1',
      SESSION_SECRET: 'security-test-session-secret-123456789',
      ADMIN_USER: 'security-test-admin',
      ADMIN_PASSWORD: 'Security-test-password-123!',
      APP_ENCRYPTION_KEY: 'roarnet-test-encryption-key-32chars-minimum',
      DB_PATH: path.join(dir, 'test.sqlite'),
      PROVIDER_ENABLED: 'false',
      PAYOUTS_ENABLED: 'false'
    },
    stdio: 'ignore'
  });

  t.after(() => {
    child.kill('SIGTERM');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const base = 'http://127.0.0.1:' + port;
  let health;

  for (let i = 0; i < 60; i++) {
    try {
      health = await fetch(base + '/api/health');
      break;
    } catch {
      await delay(100);
    }
  }

  assert.ok(health, 'server should start');
  assert.equal(health.status, 200);

  const home = await fetch(base + '/');
  assert.equal(home.status, 200);
  assert.match(home.headers.get('content-type') || '', /text\/html/i);

  const settingsGet = await fetch(base + '/api/provider/settings');
  assert.equal(settingsGet.status, 401);

  const settingsPost = await fetch(base + '/api/provider/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({})
  });
  assert.equal(settingsPost.status, 401);
});


test('developer payout rejects a reused transfer reference', async (t) => {
  const port = await freePort();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'roarnet-dev-payout-test-'));
  const dbPath = path.join(dir, 'test.sqlite');

  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: {
      ...process.env,
      PORT: String(port),
      HOST: '127.0.0.1',
      SESSION_SECRET: 'developer-payout-test-session-secret-123',
      ADMIN_USER: 'developer-payout-test-admin',
      ADMIN_PASSWORD: 'Developer-payout-test-password-123!',
      DB_PATH: dbPath,
      PROVIDER_ENABLED: 'false',
      PAYOUTS_ENABLED: 'false'
    },
    stdio: 'ignore'
  });

  t.after(() => {
    child.kill('SIGTERM');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const base = `http://127.0.0.1:${port}`;
  let ready = false;

  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`${base}/api/health`);
      if (r.ok) { ready = true; break; }
    } catch {}
    await delay(100);
  }

  assert.ok(ready, 'isolated test server should start');

  const login = await fetch(`${base}/api/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      username: 'developer-payout-test-admin',
      password: 'Developer-payout-test-password-123!'
    })
  });

  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie').split(';')[0];

  const createPayout = (destination) => fetch(`${base}/api/developer-payouts`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json' },
    body: JSON.stringify({
      method: 'zain_cash',
      amount: 5,
      destination
    })
  });

  const first = await createPayout('07800000001');
  const second = await createPayout('07800000002');

  assert.equal(first.status, 202);
  assert.equal(second.status, 202);

  const firstData = await first.json();
  const secondData = await second.json();

  const markPaid = (reference, transferReference) => fetch(
    `${base}/api/admin/developer-payouts/mark-paid`,
    {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ reference, transferReference })
    }
  );

  const paid = await markPaid(firstData.reference, 'BANK-TRANSFER-UNIQUE-001');
  assert.equal(paid.status, 200);

  const duplicate = await markPaid(secondData.reference, 'BANK-TRANSFER-UNIQUE-001');
  assert.equal(duplicate.status, 409);

  const duplicateData = await duplicate.json();
  assert.equal(duplicateData.error, 'مرجع التحويل مستخدم مسبقاً لطلب آخر');

  const db = new (await import('node:sqlite')).DatabaseSync(dbPath, { readOnly: true });
  try {
    const rows = db.prepare(`
      SELECT reference, status, transfer_reference
      FROM developer_payouts
      ORDER BY id
    `).all();

    assert.equal(rows[0].status, 'paid');
    assert.equal(rows[1].status, 'pending');
    assert.equal(rows[1].transfer_reference, null);
  } finally {
    db.close();
  }
});

test('concurrent withdrawals never exceed confirmed balance', async (t) => {
  const { DatabaseSync } = await import('node:sqlite');
  const port = await freePort();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'roarnet-withdrawal-test-'));
  const dbPath = path.join(dir, 'test.sqlite');

  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: {
      ...process.env,
      PORT: String(port),
      HOST: '127.0.0.1',
      SESSION_SECRET: 'withdrawal-test-session-secret-123456789',
      APP_ENCRYPTION_KEY: 'roarnet-test-encryption-key-32chars-minimum',
      ADMIN_USER: 'withdrawal-test-admin',
      ADMIN_PASSWORD: 'Withdrawal-test-password-123!',
      DB_PATH: dbPath,
      PROVIDER_ENABLED: 'false',
      PAYOUTS_ENABLED: 'false'
    },
    stdio: 'ignore'
  });

  t.after(() => {
    child.kill('SIGTERM');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const base = `http://127.0.0.1:${port}`;
  let ready = false;

  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`${base}/api/health`);
      if (r.ok) {
        ready = true;
        break;
      }
    } catch {}
    await delay(100);
  }

  assert.ok(ready, 'isolated test server should start');

  const login = await fetch(`${base}/api/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      username: 'withdrawal-test-admin',
      password: 'Withdrawal-test-password-123!'
    })
  });

  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie').split(';')[0];

  // Seed confirmed earnings directly into the isolated test database.
  const db = new DatabaseSync(dbPath);
  try {
    db.prepare(`
      INSERT INTO ledger
        (kind, amount, currency, reference, status, source, created_at)
      VALUES
        ('provider_confirmed', 10, 'USD', ?, 'confirmed', 'automated_test', ?)
    `).run('test-confirmed-earning-001', new Date().toISOString());
  } finally {
    db.close();
  }

  const requestWithdrawal = () => fetch(`${base}/api/withdrawals`, {
    method: 'POST',
    headers: {
      cookie,
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      amount: 7,
      wallet: 'TTestWalletAddress123456789'
    })
  });

  const responses = await Promise.all([
    requestWithdrawal(),
    requestWithdrawal()
  ]);

  const statuses = responses.map(r => r.status).sort((a, b) => a - b);
  assert.deepEqual(
    statuses,
    [202, 400],
    'only one $7 withdrawal may be accepted from a $10 balance'
  );

  const dashboard = await fetch(`${base}/api/dashboard`, {
    headers: { cookie }
  });
  assert.equal(dashboard.status, 200);

  const data = await dashboard.json();
  assert.equal(data.totals.confirmedUsd, 10);
  assert.equal(data.totals.pendingPayoutUsd, 7);
  assert.ok(
    data.totals.confirmedUsd - data.totals.pendingPayoutUsd >= 0,
    'available balance must never become negative'
  );
});


test('withdrawal rejection releases balance and paid withdrawal stays deducted', async (t) => {
  const { DatabaseSync } = await import('node:sqlite');
  const port = await freePort();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'roarnet-withdrawal-lifecycle-'));
  const dbPath = path.join(dir, 'test.sqlite');

  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: path.resolve(import.meta.dirname, '..'),
    env: {
      ...process.env,
      PORT: String(port),
      HOST: '127.0.0.1',
      SESSION_SECRET: 'withdrawal-lifecycle-session-secret-123456',
      APP_ENCRYPTION_KEY: 'roarnet-test-encryption-key-32chars-minimum',
      ADMIN_USER: 'lifecycle-admin',
      ADMIN_PASSWORD: 'Lifecycle-test-password-123!',
      DB_PATH: dbPath,
      PROVIDER_ENABLED: 'false',
      PAYOUTS_ENABLED: 'false'
    },
    stdio: 'ignore'
  });

  t.after(() => {
    child.kill('SIGTERM');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const base = `http://127.0.0.1:${port}`;
  let ready = false;
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`${base}/api/health`);
      if (r.ok) { ready = true; break; }
    } catch {}
    await delay(100);
  }
  assert.ok(ready, 'isolated test server should start');

  const login = await fetch(`${base}/api/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      username: 'lifecycle-admin',
      password: 'Lifecycle-test-password-123!'
    })
  });
  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie').split(';')[0];

  const db = new DatabaseSync(dbPath);
  try {
    db.prepare(`
      INSERT INTO ledger
        (kind, amount, currency, reference, status, source, created_at)
      VALUES
        ('provider_confirmed', 20, 'USD', ?, 'confirmed', 'automated_test', ?)
    `).run('lifecycle-confirmed-earning', new Date().toISOString());
  } finally {
    db.close();
  }

  const request = async (amount) => {
    const response = await fetch(`${base}/api/withdrawals`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        amount,
        wallet: 'TTestWalletAddress123456789'
      })
    });
    assert.equal(response.status, 202);
    return response.json();
  };

  const rejectedRequest = await request(5);
  const paidRequest = await request(6);

  const update = (reference, action, transferReference) =>
    fetch(`${base}/api/admin/withdrawals/update`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ reference, action, transferReference })
    });

  const rejected = await update(rejectedRequest.reference, 'rejected', '');
  assert.equal(rejected.status, 200);
  const rejectedData = await rejected.json();
  assert.equal(rejectedData.status, 'rejected');
  assert.equal(rejectedData.totals.pendingPayoutUsd, 6);
  assert.equal(rejectedData.totals.paidPayoutUsd, 0);
  assert.equal(rejectedData.totals.availableUsd, 14);

  const paid = await update(paidRequest.reference, 'paid', 'TX-ROARNET-TEST-001');
  assert.equal(paid.status, 200);
  const paidData = await paid.json();
  assert.equal(paidData.status, 'paid');
  assert.equal(paidData.totals.pendingPayoutUsd, 0);
  assert.equal(paidData.totals.paidPayoutUsd, 6);
  assert.equal(paidData.totals.availableUsd, 14);

  const duplicate = await update(rejectedRequest.reference, 'paid', 'TX-ROARNET-TEST-002');
  assert.equal(duplicate.status, 409);
});
