#!/usr/bin/env node
'use strict';

/**
 * Fail2Scan daemon - integrated version
 * - watches fail2ban log for "Ban" events (handles rotation)
 * - extracts IPv4/IPv6
 * - queue with persistence and rescan TTL
 * - fallback output dir if /var/log/fail2scan not writable
 * - single-ip CLI --scan-ip
 *
 * Usage:
 *   fail2scan-daemon --log /var/log/fail2ban.log --out /var/log/fail2scan --concurrency 2 --nmap-args "-sS -Pn -p- -T4 -sV" --quiet
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFile, spawn } = require('child_process');
const { promisify } = require('util');
const execFileP = promisify(execFile);

// -------------------- CLI / CONFIG --------------------
const argv = process.argv.slice(2);
function getArg(key, def) {
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === key && argv[i + 1]) return argv[++i];
    if (a.startsWith(key + '=')) return a.split('=')[1];
  }
  return def;
}
if (argv.includes('--help') || argv.includes('-h')) {
  console.log('Fail2Scan daemon\n--log PATH (default /var/log/fail2ban.log)\n--out PATH (default /var/log/fail2scan)\n--concurrency N (default 1)\n--nmap-args "args" (default "-sS -Pn -p- -T4 -sV")\n--scan-ip IP (do one scan and exit)\n--quiet');
  process.exit(0);
}

const LOG_PATH = getArg('--log', '/var/log/fail2ban.log');
const OUT_ROOT = getArg('--out', '/var/log/fail2scan');
const CONCURRENCY = Math.max(1, parseInt(getArg('--concurrency', '1'), 10) || 1);
const NMAP_ARGS_STR = getArg('--nmap-args', '-sS -Pn -p- -T4 -sV');
const SINGLE_IP = getArg('--scan-ip', null);
const QUIET = argv.includes('--quiet');

function log(...args) { if (!QUIET) console.log(new Date().toISOString(), ...args); appendLog(args.join(' ')); }

// -------------------- small logger to file --------------------
const STATE_FILE = path.join(os.homedir(), '.fail2scan_state.json');
const LOG_FILE = path.join(os.homedir(), '.fail2scan.log');
function appendLog(msg) {
  try { fs.appendFileSync(LOG_FILE, new Date().toISOString() + ' ' + msg + '\n'); } catch (e) {}
}

// -------------------- utilities --------------------
function sanitizeFilename(s) { return String(s).replace(/[:\/\\<>?"|* ]+/g, '_'); }
async function which(bin) { try { await execFileP('which', [bin]); return true; } catch { return false; } }
async function runCmdCapture(cmd, args, opts = {}) {
  try {
    const { stdout, stderr } = await execFileP(cmd, args, { maxBuffer: 1024 * 1024 * 32, ...opts });
    return { ok: true, stdout: stdout || '', stderr: stderr || '' };
  } catch (e) {
    return { ok: false, stdout: (e.stdout || '') + '', stderr: (e.stderr || e.message) + '' };
  }
}
function safeMkdirSyncWithFallback(p) {
  try { fs.mkdirSync(p, { recursive: true, mode: 0o750 }); return p; }
  catch (e) {
    const fallback = path.join('/tmp', 'fail2scan');
    try { fs.mkdirSync(fallback, { recursive: true, mode: 0o750 }); return fallback; }
    catch (ee) { throw e; }
  }
}

// -------------------- prerequisites --------------------
(async function checkTools() {
  const tools = ['nmap', 'dig', 'whois', 'which'];
  for (const t of tools) {
    if (t === 'which') continue;
    if (!(await which(t))) {
      console.error(`Missing required binary: ${t}. Please install it (eg: apt install ${t}).`);
      process.exit(2);
    }
  }
})().catch(e => { console.error('Prereq check failed', e); process.exit(2); });

// -------------------- persistence state --------------------
function loadState() {
  try {
    if (fs.existsSync(STATE_FILE)) {
      const raw = fs.readFileSync(STATE_FILE, 'utf8');
      const j = JSON.parse(raw);
      return {
        seen: new Set(Array.isArray(j.seen) ? j.seen : []),
        retryAfter: typeof j.retryAfter === 'object' ? j.retryAfter : {}
      };
    }
  } catch (e) {}
  return { seen: new Set(), retryAfter: {} };
}
function saveState(state) {
  try {
    const obj = { seen: Array.from(state.seen || []), retryAfter: state.retryAfter || {} };
    const dir = path.dirname(STATE_FILE);
    try { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); } catch (e) {}
    fs.writeFileSync(STATE_FILE, JSON.stringify(obj, null, 2));
  } catch (e) {}
}
const STATE = loadState();
const RESCAN_TTL_SEC = 60 * 60; // default 1 hour

// -------------------- IP extraction --------------------
function extractIpFromLine(line) {
  // prefer strict IPv4
  const ipv4 = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  if (ipv4 && ipv4[0]) return ipv4[0];
  // simple IPv6 match
  const ipv6 = line.match(/\b([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b/);
  if (ipv6 && ipv6[0]) return ipv6[0];
  return null;
}

// -------------------- Scan implementation --------------------
function spawnNmap(ip, outDir, nmapArgs) {
  return new Promise((resolve, reject) => {
    const outNmap = path.join(outDir, 'nmap.txt');
    const args = nmapArgs.concat([ip]);
    const proc = spawn('nmap', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const outStream = fs.createWriteStream(outNmap, { flags: 'w' });
    proc.stdout.pipe(outStream);
    let stderr = '';
    proc.stderr.on('data', c => { stderr += c.toString(); });
    proc.on('close', code => {
      if (stderr) fs.appendFileSync(outNmap, '\n\nSTDERR:\n' + stderr);
      resolve({ code, ok: code === 0 });
    });
    proc.on('error', err => reject(err));
  });
}

async function performScan(ip) {
  const now = new Date();
  const dateDir = now.toISOString().slice(0, 10);
  const safeIp = sanitizeFilename(ip);
  let outDir = path.join(OUT_ROOT, dateDir, `${safeIp}_${now.toISOString().replace(/[:.]/g, '-')}`);
  try {
    outDir = path.join(safeMkdirSyncWithFallback(path.dirname(outDir)), path.basename(outDir));
    fs.mkdirSync(outDir, { recursive: true, mode: 0o750 });
  } catch (e) {
    log('Cannot create out dir for', ip, '-', e.message);
    // schedule quick retry and exit
    STATE.retryAfter[ip] = Math.floor(Date.now() / 1000) + 60;
    saveState(STATE);
    return;
  }

  const summary = { ip, ts: now.toISOString(), cmds: {} };

  // choose nmap args and adapt if not root
  const requested = NMAP_ARGS_STR.trim().split(/\s+/).filter(Boolean);
  const isRoot = (typeof process.getuid === 'function' && process.getuid() === 0);
  const nmapArgs = requested.map(a => (!isRoot && a === '-sS') ? '-sT' : a);

  try {
    log('Running nmap on', ip, 'args:', nmapArgs.join(' '));
    await spawnNmap(ip, outDir, nmapArgs);
    summary.cmds.nmap = { ok: true, args: nmapArgs.join(' '), path: 'nmap.txt' };
  } catch (e) {
    log('nmap failed for', ip, e.message);
    summary.cmds.nmap = { ok: false, err: e.message };
  }

  // dig
  try {
    const dig = await runCmdCapture('dig', ['-x', ip, '+short']);
    fs.writeFileSync(path.join(outDir, 'dig.txt'), (dig.stdout || '') + (dig.stderr ? '\n\nSTDERR:\n' + dig.stderr : ''));
    summary.cmds.dig = { ok: dig.ok, path: 'dig.txt' };
  } catch (e) { summary.cmds.dig = { ok: false, err: e.message }; }

  // whois
  try {
    const who = await runCmdCapture('whois', [ip]);
    fs.writeFileSync(path.join(outDir, 'whois.txt'), (who.stdout || '') + (who.stderr ? '\n\nSTDERR:\n' + who.stderr : ''));
    summary.cmds.whois = { ok: who.ok, path: 'whois.txt' };
  } catch (e) { summary.cmds.whois = { ok: false, err: e.message }; }

  // minimal parse for open ports
  try {
    const nmapTxt = fs.readFileSync(path.join(outDir, 'nmap.txt'), 'utf8');
    const open = nmapTxt.split(/\r?\n/).filter(l => /^\d+\/tcp\s+open/.test(l)).map(l => l.trim());
    summary.open_ports = open;
  } catch (e) { summary.open_ports = []; }

  fs.writeFileSync(path.join(outDir, 'summary.json'), JSON.stringify(summary, null, 2));
  try { fs.chmodSync(outDir, 0o750); } catch (e) {}
  log('Scan written for', ip, '->', outDir);
}

// -------------------- Queue with concurrency and TTL --------------------
class ScanQueue {
  constructor(concurrency = 1) {
    this.concurrency = concurrency;
    this.running = 0;
    this.q = [];
    this.set = STATE.seen; // persistent set
  }
  push(ip) {
    const now = Math.floor(Date.now() / 1000);
    const next = STATE.retryAfter[ip] || 0;
    if (this.set.has(ip) && next > now) {
      log('IP already queued or running (TTL not expired):', ip);
      return;
    }
    if (this.set.has(ip) && next <= now) {
      log('Re-queueing after TTL:', ip);
      this.set.delete(ip);
    }
    this.set.add(ip);
    STATE.seen = this.set;
    saveState(STATE);
    this.q.push(ip);
    this._next();
  }
  _next() {
    if (this.running >= this.concurrency) return;
    const ip = this.q.shift();
    if (!ip) return;
    this.running++;
    (async () => {
      try {
        log('Scanning', ip);
        await performScan(ip);
        log('Done', ip);
      } catch (e) {
        log('Error scanning', ip, e && e.message ? e.message : e);
      } finally {
        STATE.retryAfter[ip] = Math.floor(Date.now() / 1000) + RESCAN_TTL_SEC;
        saveState(STATE);
        this.set.delete(ip); // allow future re-queue after TTL (state still records retryAfter)
        this.running--;
        setImmediate(() => this._next());
      }
    })();
  }
}

// -------------------- File tail (watch + read new lines, handle rotation) --------------------
class FileTail {
  constructor(filePath, onLine) {
    this.filePath = filePath;
    this.onLine = onLine;
    this.pos = 0;
    this.inode = null;
    this.buf = '';
    this.watch = null;
    this.start();
  }
  start() {
    try {
      const st = fs.statSync(this.filePath);
      this.inode = st.ino;
      this.pos = st.size;
    } catch (e) {
      this.inode = null;
      this.pos = 0;
    }
    this._watch();
    // try initial read (if file exists and appended)
    this._readNew().catch(()=>{});
  }
  _watch() {
    try {
      this.watch = fs.watch(this.filePath, { persistent: true }, async () => {
        try {
          let st;
          try { st = fs.statSync(this.filePath); } catch { st = null; }
          if (!st) { this.inode = null; this.pos = 0; return; }
          if (this.inode !== null && st.ino !== this.inode) { // rotated
            this.inode = st.ino;
            this.pos = 0;
          } else if (this.inode === null) {
            this.inode = st.ino;
            this.pos = 0;
          }
          await this._readNew();
        } catch (e) { /* ignore transient */ }
      });
    } catch (e) { log('fs.watch failed:', e.message); }
  }
  async _readNew() {
    try {
      const st = fs.statSync(this.filePath);
      if (st.size < this.pos) this.pos = 0;
      if (st.size === this.pos) return;
      const stream = fs.createReadStream(this.filePath, { start: this.pos, end: st.size - 1, encoding: 'utf8' });
      for await (const chunk of stream) {
        this.buf += chunk;
        let idx;
        while ((idx = this.buf.indexOf('\n')) >= 0) {
          const line = this.buf.slice(0, idx);
          this.buf = this.buf.slice(idx + 1);
          if (line.trim()) this.onLine(line);
        }
      }
      this.pos = st.size;
    } catch (e) { /* ignore */ }
  }
  close() { try { if (this.watch) this.watch.close(); } catch (e) {} }
}

// -------------------- Main startup --------------------
if (SINGLE_IP) {
  (async () => {
    const q = new ScanQueue(CONCURRENCY);
    q.push(SINGLE_IP);
  })();
  return;
}

const q = new ScanQueue(CONCURRENCY);
log('Fail2Scan started. Watching', LOG_PATH, ' -> output', OUT_ROOT, 'concurrency', CONCURRENCY);

// On each new line, extract IP and push to queue if Ban detected
const BAN_RE = /\bBan\b/i;
const tail = new FileTail(LOG_PATH, (line) => {
  try {
    if (!BAN_RE.test(line)) return;
    const ip = extractIpFromLine(line);
    if (!ip) return;
    q.push(ip);
  } catch (e) { log('onLine handler error', e && e.message ? e.message : e); }
});

// graceful shutdown
function shutdown() {
  log('Shutting down Fail2Scan...');
  tail.close();
  // wait briefly for running tasks
  const start = Date.now();
  const wait = () => {
    if (q.running === 0 || Date.now() - start > 10000) process.exit(0);
    setTimeout(wait, 500);
  };
  wait();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
