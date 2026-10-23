import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
function loadEnv(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (m && !m[1].startsWith('#') && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
  }
}
loadEnv(path.join(root, '.env'));
const cfg = {
  port: Number(process.env.PORT || 3000), host: process.env.HOST || '127.0.0.1',
  sessionSecret: process.env.SESSION_SECRET || '',
  adminUser: process.env.ADMIN_USER || 'admin', adminPassword: process.env.ADMIN_PASSWORD || '',
  dbPath: process.env.DB_PATH || './data/roarnet.sqlite',
  providerEnabled: process.env.PROVIDER_ENABLED === 'true', providerName: process.env.PROVIDER_NAME || 'unconfigured',
  providerApiBase: process.env.PROVIDER_API_BASE || '', providerApiKey: process.env.PROVIDER_API_KEY || '',
  providerDeviceId: process.env.PROVIDER_DEVICE_ID || '', providerDeviceToken: process.env.PROVIDER_DEVICE_TOKEN || '',
  payoutsEnabled: process.env.PAYOUTS_ENABLED === 'true',
  encryptionKey: process.env.APP_ENCRYPTION_KEY || ''
};
if (cfg.sessionSecret.length < 32 || cfg.adminPassword.length < 12 || cfg.adminPassword === 'change-this-long-password-now') {
  console.error('Setup required: copy .env.example to .env, set SESSION_SECRET (32+ chars) and a strong ADMIN_PASSWORD (12+ chars).');
  process.exit(1);
}
const dbFile = path.resolve(root, cfg.dbPath);
fs.mkdirSync(path.dirname(dbFile), { recursive: true });
const db = new DatabaseSync(dbFile);
db.exec(`PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, created_at TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL CHECK(kind IN ('demo','provider_confirmed','payout_request')), amount REAL NOT NULL, currency TEXT NOT NULL, reference TEXT NOT NULL UNIQUE, status TEXT NOT NULL, source TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS provider_snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT, provider TEXT NOT NULL, device_id TEXT, payload_json TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
`);
const now = () => new Date().toISOString();
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const safeEqual = (a,b) => { const aa=Buffer.from(String(a)); const bb=Buffer.from(String(b)); return aa.length===bb.length && crypto.timingSafeEqual(aa,bb); };
function audit(event, detail='') { db.prepare('INSERT INTO audit_log(event,detail,created_at) VALUES(?,?,?)').run(event, detail.slice(0,500), now()); }
function json(res, status, data, extra={}) { res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...extra}); res.end(JSON.stringify(data)); }
function readBody(req, max=16_384) { return new Promise((resolve,reject)=>{let data=''; req.on('data',c=>{data+=c; if(data.length>max){reject(new Error('BODY_TOO_LARGE'));req.destroy();}});req.on('end',()=>{try{resolve(data?JSON.parse(data):{});}catch{reject(new Error('BAD_JSON'));}});req.on('error',reject);}); }
function cookies(req) { return Object.fromEntries((req.headers.cookie||'').split(';').map(x=>x.trim()).filter(Boolean).map(x=>{const i=x.indexOf('=');return [x.slice(0,i),decodeURIComponent(x.slice(i+1))]})); }
function authorized(req) { const raw=cookies(req).roarnet_session; if(!raw) return false; const row=db.prepare('SELECT expires_at FROM sessions WHERE token_hash=?').get(sha(raw)); if(!row || row.expires_at < Date.now()){ if(row) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha(raw)); return false;} return true; }
function requireAuth(req,res) { if(!authorized(req)){json(res,401,{error:'يلزم تسجيل الدخول'});return false;} return true; }
function totals() {
 const confirmed=db.prepare("SELECT COALESCE(SUM(amount),0) AS v FROM ledger WHERE kind='provider_confirmed' AND status='confirmed'").get().v;
 const demo=db.prepare("SELECT COALESCE(SUM(amount),0) AS v FROM ledger WHERE kind='demo'").get().v;
 const pending=db.prepare("SELECT COALESCE(SUM(-amount),0) AS v FROM ledger WHERE kind='payout_request' AND status='pending'").get().v;
 return {confirmedUsd:Number(confirmed.toFixed(6)), demoUsd:Number(demo.toFixed(6)), pendingPayoutUsd:Number(pending.toFixed(6))};
}
function sealSetting(value) {
 if (cfg.encryptionKey.length < 32) throw new Error('APP_ENCRYPTION_KEY_MISSING');
 const key=crypto.createHash('sha256').update(cfg.encryptionKey).digest(); const iv=crypto.randomBytes(12);
 const cipher=crypto.createCipheriv('aes-256-gcm',key,iv); const data=Buffer.concat([cipher.update(String(value),'utf8'),cipher.final()]);
 return [iv.toString('base64'),cipher.getAuthTag().toString('base64'),data.toString('base64')].join('.');
}
function unsealSetting(value) { try { if(cfg.encryptionKey.length<32)return ''; const [iv,tag,data]=value.split('.'); const key=crypto.createHash('sha256').update(cfg.encryptionKey).digest(); const d=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(iv,'base64')); d.setAuthTag(Buffer.from(tag,'base64')); return Buffer.concat([d.update(Buffer.from(data,'base64')),d.final()]).toString('utf8'); } catch { return ''; } }
function getSetting(key) { const row=db.prepare('SELECT value FROM app_settings WHERE key=?').get(key); return row?unsealSetting(row.value):''; }
function providerConfig() { const name=getSetting('name')||cfg.providerName, base=getSetting('base')||cfg.providerApiBase, apiKey=getSetting('apiKey')||cfg.providerApiKey, deviceId=getSetting('deviceId')||cfg.providerDeviceId, token=getSetting('token')||cfg.providerDeviceToken; const configured=!!(base&&apiKey&&deviceId&&token); return {name,base,apiKey,deviceId,token,configured,enabled:cfg.providerEnabled&&configured}; }
async function providerGet(endpoint) {
 const pc=providerConfig(); if(!pc.enabled) throw new Error('PROVIDER_NOT_CONFIGURED');
 const url=new URL(endpoint, pc.base);
 const response=await fetch(url,{headers:{'Authorization':`Bearer ${pc.token}`,'X-API-Key':pc.apiKey,'Accept':'application/json'},signal:AbortSignal.timeout(8000)});
 if(!response.ok) throw new Error(`PROVIDER_HTTP_${response.status}`);
 return response.json();
}
const server=http.createServer(async(req,res)=>{
 try {
  const url=new URL(req.url,'http://localhost');
  if(req.method==='GET' && url.pathname==='/api/health') return json(res,200,{ok:true,app:'RoarNet',provider:cfg.providerEnabled?'configured':'not_connected',payouts:cfg.payoutsEnabled?'enabled':'disabled'});
  if(req.method==='GET' && url.pathname==='/api/session') return json(res,200,{authenticated:authorized(req)});
  if(req.method==='POST' && url.pathname==='/api/login') {
   const b=await readBody(req); if(!safeEqual(b.username||'',cfg.adminUser)||!safeEqual(b.password||'',cfg.adminPassword)){audit('login_failed');return json(res,401,{error:'بيانات الدخول غير صحيحة'});}
   const token=crypto.randomBytes(32).toString('base64url'); const expiry=Date.now()+8*60*60*1000;
   db.prepare('INSERT INTO sessions(token_hash,created_at,expires_at) VALUES(?,?,?)').run(sha(token),now(),expiry); audit('login_success');
   return json(res,200,{ok:true},{'Set-Cookie':`roarnet_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`});
  }
  if(req.method==='POST' && url.pathname==='/api/logout') { const c=cookies(req).roarnet_session;if(c)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha(c));return json(res,200,{ok:true},{'Set-Cookie':'roarnet_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'}); }
  if(url.pathname.startsWith('/api/')) {
   if(!requireAuth(req,res)) return;
   if(req.method==='GET' && url.pathname==='/api/provider/settings') { const p=providerConfig(); return json(res,200,{name:p.name,apiBase:p.base,deviceId:p.deviceId,hasApiKey:!!p.apiKey,hasDeviceToken:!!p.token,configured:p.configured,enabled:p.enabled}); }
   if(req.method==='POST' && url.pathname==='/api/provider/settings') {
    const b=await readBody(req); const name=String(b.name||'').trim().slice(0,80); const apiBase=String(b.apiBase||'').trim().replace(/\/$/,''); const deviceId=String(b.deviceId||'').trim().slice(0,200); const apiKey=String(b.apiKey||'').trim(); const token=String(b.deviceToken||'').trim();
    if(!name || !/^https:\/\//i.test(apiBase) || apiBase.length>300 || !deviceId) return json(res,400,{error:'أدخل اسم المزوّد ورابط API رسمي يبدأ بـ HTTPS ومعرّف الجهاز'});
    try { const host=new URL(apiBase).hostname.toLowerCase(); if(host==='localhost'||host.endsWith('.local')||/^127\./.test(host)||/^10\./.test(host)||/^192\.168\./.test(host)) return json(res,400,{error:'رابط API المحلي غير مسموح'}); } catch { return json(res,400,{error:'رابط API غير صالح'}); }
    const old=providerConfig(); if((!apiKey&&!old.apiKey)||(!token&&!old.token)) return json(res,400,{error:'أدخل مفتاح API ورمز الجهاز اللذين يمنحهما المزوّد'});
    try { const values={name,base:apiBase,deviceId}; if(apiKey)values.apiKey=apiKey;if(token)values.token=token; for(const [k,v] of Object.entries(values)) db.prepare('INSERT INTO app_settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at').run(k,sealSetting(v),now()); audit('provider_settings_saved',name); return json(res,200,{ok:true,message:'حُفظت بيانات المزوّد مشفّرة على الخادم. الاتصال الحقيقي يبقى متوقفاً حتى تفعيل PROVIDER_ENABLED بعد اعتماد API الرسمي.'}); } catch(e) { return json(res,503,{error:e.message==='APP_ENCRYPTION_KEY_MISSING'?'أضف APP_ENCRYPTION_KEY بطول 32 حرفاً أو أكثر إلى إعدادات الخادم':'تعذّر حفظ إعدادات المزوّد'}); }
   }
   if(req.method==='GET' && url.pathname==='/api/dashboard') {
    const latest=db.prepare('SELECT provider,device_id,payload_json,created_at FROM provider_snapshots ORDER BY id DESC LIMIT 1').get();
    const ledger=db.prepare('SELECT kind,amount,currency,reference,status,source,created_at FROM ledger ORDER BY id DESC LIMIT 30').all();
    return json(res,200,{totals:totals(),provider:{name:providerConfig().name,enabled:providerConfig().enabled,accountLinked:providerConfig().configured,latestSnapshotAt:latest?.created_at||null},ledger});
   }
   if(req.method==='POST' && url.pathname==='/api/demo-credit') {
    const b=await readBody(req);const amount=Number(b.amount);if(!Number.isFinite(amount)||amount<=0||amount>1)return json(res,400,{error:'المبلغ التجريبي يجب أن يكون بين 0 و1 USD'});
    const ref=`demo_${crypto.randomUUID()}`;db.prepare("INSERT INTO ledger(kind,amount,currency,reference,status,source,created_at) VALUES('demo',?,'USD',?,'demo_only','local_demo',?)").run(amount,ref,now());audit('demo_credit',ref);return json(res,201,{ok:true,totals:totals(),notice:'رصيد تجريبي للعرض فقط ولا يمكن سحبه'});
   }
   if(req.method==='POST' && url.pathname==='/api/provider/refresh') {
    try {
     // Confirm endpoint names and token format with provider before enabling this adapter in production.
     const payload=await providerGet(`/v1/peer/agents/${encodeURIComponent(providerConfig().deviceId)}/earnings`);
     const reference=String(payload.reference||payload.transactionId||'');
     db.prepare('INSERT INTO provider_snapshots(provider,device_id,payload_json,created_at) VALUES(?,?,?,?)').run(providerConfig().name,providerConfig().deviceId,JSON.stringify(payload).slice(0,100000),now());
     // Never create a confirmed cash ledger entry without a provider-issued unique earning/settlement reference.
     if(reference && Number.isFinite(Number(payload.confirmedUsd)) && Number(payload.confirmedUsd)>=0) {
      const exists=db.prepare('SELECT id FROM ledger WHERE reference=?').get(`provider:${reference}`);
      if(!exists) db.prepare("INSERT INTO ledger(kind,amount,currency,reference,status,source,created_at) VALUES('provider_confirmed',?,'USD',?,'confirmed',?,?)").run(Number(payload.confirmedUsd),`provider:${reference}`,providerConfig().name,now());
     }
     audit('provider_refresh_success',cfg.providerName);return json(res,200,{ok:true,message:'تم تحديث لقطة المزوّد؛ راجع تفاصيله قبل اعتماد أي رصيد.',totals:totals()});
    } catch(e) { audit('provider_refresh_failed',e.message);return json(res,503,{error:'تعذر تحديث بيانات المزوّد',detail:e.message==='PROVIDER_NOT_CONFIGURED'?'أكمل حساب الشراكة والمفاتيح أولاً':'تحقق من API والاعتماد الرسمي'}); }
   }
   if(req.method==='POST' && url.pathname==='/api/withdrawals') {
    const b=await readBody(req);const amount=Number(b.amount);const wallet=String(b.wallet||'').trim();
    if(!Number.isFinite(amount)||amount<=0||amount>totals().confirmedUsd)return json(res,400,{error:'المبلغ يتجاوز الرصيد المؤكد أو غير صالح'});
    if(wallet.length<20||wallet.length>120)return json(res,400,{error:'أدخل عنوان محفظة صالحاً'});
    if(cfg.payoutsEnabled) return json(res,503,{error:'تنفيذ السحب الآلي يحتاج تكامل دفع تمت مراجعته. لم تُرسل أي معاملة.'});
    const ref=`withdrawal_${crypto.randomUUID()}`;db.prepare("INSERT INTO ledger(kind,amount,currency,reference,status,source,created_at) VALUES('payout_request',?,'USDT',?,'pending',?,?)").run(-amount,ref,`manual_review_wallet:${wallet.slice(0,6)}…${wallet.slice(-4)}`,now());audit('withdrawal_requested',ref);
    return json(res,202,{ok:true,reference:ref,status:'pending_review',message:'سُجّل الطلب للمراجعة فقط. لم يتم إرسال USDT.'});
   }
   return json(res,404,{error:'مسار API غير موجود'});
  }
  if(req.method==='GET' && url.pathname==='/') {res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});return res.end(fs.readFileSync(path.join(root,'public/index.html')));}
  if(req.method==='GET' && url.pathname==='/favicon.ico'){res.writeHead(204);return res.end();}
  return json(res,404,{error:'غير موجود'});
 } catch(e) { if(!res.headersSent)json(res,e.message==='BAD_JSON'?400:500,{error:e.message==='BAD_JSON'?'صيغة البيانات غير صحيحة':'حدث خطأ داخلي'}); }
});
server.listen(cfg.port,cfg.host,()=>console.log(`RoarNet listening at http://${cfg.host}:${cfg.port}`));
process.on('SIGINT',()=>{db.close();server.close(()=>process.exit(0));});
process.on('SIGTERM',()=>{db.close();server.close(()=>process.exit(0));});
