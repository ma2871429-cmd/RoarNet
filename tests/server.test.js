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
