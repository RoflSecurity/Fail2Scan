#!/usr/bin/env node
'use strict';

/**
 * Fail2Scan v0.0.1 - daemon.js
 * Watches Fail2Ban log for ban events, queues IPs and scans them with nmap/dig/whois.
 * Node 18+, CommonJS, no external dependencies.
 *
 * Usage:
 *   fail2scan-daemon --log /var/log/fail2ban.log --out /var/log/fail2scan --concurrency 1 --nmap-args "-sS -Pn -p- -T4 -sV" --quiet
 */

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileP = promisify(execFile);
const argv = process.argv.slice(2);

// --------- CLI helpers ----------
function getArg(key, def) {
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === key && argv[i + 1]) return argv[++i];
    if (a.startsWith(key + '=')) return a.split('=')[1];
  }
  return def;
}

if (argv.includes('--help') || argv.includes('-h')) {
  console.log('Fail2Scan daemon\n--log PATH (default /var/log/fail2ban.log)\n--out PATH (default /var/log/fail2scan)\n--concurrency N (default 1)\n--nmap-args "args" (default "-sS -Pn -p- -T4 -sV")\n--quiet');
  process.exit(0);
}

const LOG_PATH = getArg('--log', '/var/log/fail2ban.log');
const OUT_ROOT = getArg('--out', '/var/log/fail2scan');
const CONCURRENCY = Math.max(1, parseInt(getArg('--concurrency', '1'), 10) || 1);
const NMAP_ARGS_STR = getArg('--nmap-args', '-sS -Pn -p- -T4 -sV');
const QUIET = argv.includes('--quiet');

function log(...args) { if (!QUIET) console.log(new Date().toISOString(), ...args); }

// --------- Utilities ----------
function safeMkdirSync(p) { fs.mkdirSync(p, { recursive: true, mode: 0o750 }); }

async function which(bin) {
  try { await execFileP('which', [bin]); return true; } catch { return false; }
}

async function runCmd(cmd, args, opts = {}) {
  try {
    const { stdout, stderr } = await execFileP(cmd, args, { maxBuffer: 1024 * 1024 * 32, ...opts });
    return { ok: true, stdout: stdout || '', stderr: stderr || '' };
  } catch (e) {
    return { ok: false, stdout: (e.stdout || '') + '', stderr: (e.stderr || e.message) + '' };
  }
}

function sanitizeFilename(s) { return String(s).replace(/[:\/\\<>?"|* ]+/g, '_'); }

// --------- Prerequisites check ----------
(async function checkPrereqs() {
  const tools = ['nmap', 'dig', 'whois'];
  for (const t of tools) {
    if (!(await which(t))) {
      console.error(`Missing required binary: ${t}. Install it (eg: apt install ${t}).`);
      process.exit(2);
    }
  }
})().catch(e => { console.error('Prereq check failed', e); process.exit(2); });

// --------- File tail (handles rotation) ----------
class FileTail {
  constructor(filePath, onLine) {
    this.filePath = filePath;
    this.onLine = onLine;
    this.position = 0;
    this.inode = null;
    this.buffer = '';
    this.watcher = null;
    this.start().catch(err => { console.error('Tail start error', err); process.exit(1); });
  }

  async start() {
    try { const st = fs.statSync(this.filePath); this.inode = st.ino; this.position = st.size; } catch (e) { this.inode = null; this.position = 0; }
    this._watchFile();
    await this._readNew();
  }

  _watchFile() {
    try {
      this.watcher = fs.watch(this.filePath, { persistent: true }, async () => {
        try {
          let st; try { st = fs.statSync(this.filePath); } catch { st = null; }
          if (!st) { this.inode = null; this.position = 0; return; }
          if (this.inode !== null && st.ino !== this.inode) { this.inode = st.ino; this.position = 0; }
          else if (this.inode === null) { this.inode = st.ino; this.position = 0; }
          await this._readNew();
        } catch (err) {}
      });
    } catch (e) { console.error('fs.watch failed:', e.message); process.exit(1); }
  }

  async _readNew() {
    try {
      const st = fs.statSync(this.filePath);
      if (st.size < this.position) this.position = 0;
      if (st.size === this.position) return;
      const stream = fs.createReadStream(this.filePath, { start: this.position, end: st.size - 1, encoding: 'utf8' });
      for await (const chunk of stream) {
        this.buffer += chunk;
        let idx;
        while ((idx = this.buffer.indexOf('\n')) >= 0) {
          const line = this.buffer.slice(0, idx);
          this.buffer = this.buffer.slice(idx + 1);
          if (line.trim()) this.onLine(line);
        }
      }
      this.position = st.size;
    } catch (e) {}
  }

  close() { try { if (this.watcher) this.watcher.close(); } catch (e) {} }
}

// --------- Scan queue ----------
class ScanQueue {
  constructor(concurrency = 1) { this.concurrency = concurrency; this.running = 0; this.queue = []; this.set = new Set(); }
  push(ip) {
    if (this.set.has(ip)) { log('IP already queued or running:', ip); return; }
    this.set.add(ip); this.queue.push(ip); this._next();
  }
  _next() {
    if (this.running >= this.concurrency) return;
    const ip = this.queue.shift();
    if (!ip) return;
    this.running++;
    this._run(ip).finally(() => { this.running--; this.set.delete(ip); setImmediate(() => this._next()); });
  }
  async _run(ip) {
    try { log('Scanning', ip); await performScan(ip); log('Done', ip); } catch (e) { console.error('Error scanning', ip, e); }
  }
}

function extractIpFromLine(line) {
  const ipv4 = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  if (ipv4 && ipv4[0]) return ipv4[0];
  const ipv6 = line.match(/\b([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b/);
  if (ipv6 && ipv6[0]) return ipv6[0];
  return null;
}

// --------- Scan logic ----------
async function performScan(ip) {
  const now = new Date();
  const iso = now.toISOString().replace(/\..+$/, '').replace(/:/g, '-');
  const dateDir = now.toISOString().slice(0, 10);
  const safeIp = sanitizeFilename(ip);
  const outDir = path.join(OUT_ROOT, dateDir, `${safeIp}_${iso}`);
  try { safeMkdirSync(outDir); } catch (e) { throw new Error('Cannot create outDir: ' + e.message); }

  const summary = { ip, timestamp: now.toISOString(), commands: {} };

  // Nmap
  const requestedArgs = NMAP_ARGS_STR.trim().split(/\s+/).filter(Boolean);
  let nmapArgsBase = requestedArgs.slice();
  const isRoot = (typeof process.getuid === 'function' && process.getuid() === 0);
  if (!isRoot) { nmapArgsBase = nmapArgsBase.map(a => a === '-sS' ? '-sT' : a); }
  const nmapArgs = nmapArgsBase.concat([ip]);
  summary.commands.nmap = { args: nmapArgs.join(' ') };
  const nmapRes = await runCmd('nmap', nmapArgs);
  fs.writeFileSync(path.join(outDir, 'nmap.txt'), (nmapRes.stdout || '') + (nmapRes.stderr ? '\n\nSTDERR:\n' + nmapRes.stderr : ''));
  summary.commands.nmap.result = { ok: nmapRes.ok, path: 'nmap.txt' };

  // Dig
  const digRes = await runCmd('dig', ['-x', ip, '+short']);
  fs.writeFileSync(path.join(outDir, 'dig.txt'), (digRes.stdout || '') + (digRes.stderr ? '\n\nSTDERR:\n' + digRes.stderr : ''));
  summary.commands.dig = { ok: digRes.ok, path: 'dig.txt', reverse: (digRes.stdout || '').trim() };

  // Whois
  const whoisRes = await runCmd('whois', [ip]);
  fs.writeFileSync(path.join(outDir, 'whois.txt'), (whoisRes.stdout || '') + (whoisRes.stderr ? '\n\nSTDERR:\n' + whoisRes.stderr : ''));
  summary.commands.whois = { ok: whoisRes.ok, path: 'whois.txt' };

  // Open ports from Nmap
  try {
    const openLines = (nmapRes.stdout || '').split(/\r?\n/).filter(l => /^\d+\/tcp\s+open/.test(l)).map(l => l.trim());
    summary.open_ports = openLines;
  } catch (e) { summary.open_ports = []; }

  fs.writeFileSync(path.join(outDir, 'summary.json'), JSON.stringify(summary, null, 2));
  try { fs.chmodSync(outDir, 0o750); } catch (e) {}
}

// --------- Start daemon ----------
const queue = new ScanQueue(CONCURRENCY);
log('Fail2Scan daemon started on', LOG_PATH, 'output ->', OUT_ROOT, 'concurrency', CONCURRENCY);

const tail = new FileTail(LOG_PATH, (line) => {
  const ip = extractIpFromLine(line);
  if (ip) queue.push(ip);
});

// --------- Graceful shutdown ----------
function shutdown() {
  log('Shutting down Fail2Scan daemon...');
  tail.close();
  const start = Date.now();
  const wait = () => {
    if (queue.running === 0 || Date.now() - start > 10000) process.exit(0);
    setTimeout(wait, 500);
  };
  wait();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
