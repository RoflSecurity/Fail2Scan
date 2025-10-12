#!/usr/bin/env node
'use strict';

/**
 * Fail2Scan v0.0.1
 * Watches Fail2Ban logs for "Ban <IP>" entries and scans the banned IPs using
 * system tools (nmap, dig, whois). Results are saved to /var/log/fail2scan/<date>/<ip>_<ts>/
 *
 * Node 18+, CommonJS, no external dependencies.
 */

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileP = promisify(execFile);
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
  console.log('Usage: fail2scan-daemon [--log /path/to/fail2ban.log] [--out /path/to/output] [--concurrency N] [--nmap-args "args"] [--quiet]');
  process.exit(0);
}

const LOG_PATH = getArg('--log', '/var/log/fail2ban.log');
const OUT_ROOT = getArg('--out', '/var/log/fail2scan');
const CONCURRENCY = Math.max(1, parseInt(getArg('--concurrency', '1'), 10) || 1);
const NMAP_ARGS_STR = getArg('--nmap-args', '-sS -Pn -p- -T4 -sV');
const QUIET = argv.includes('--quiet');

function log(...args) { if (!QUIET) console.log(new Date().toISOString(), ...args); }

function safeMkdirSync(p) { fs.mkdirSync(p, { recursive: true, mode: 0o750 }); }
async function which(bin) { try { await execFileP('which', [bin]); return true; } catch { return false; } }
async function runCmd(cmd, args, opts = {}) {
  try {
    const { stdout, stderr } = await execFileP(cmd, args, { maxBuffer: 1024 * 1024 * 32, ...opts });
    return { ok: true, stdout, stderr };
  } catch (e) {
    return { ok: false, stdout: e.stdout || '', stderr: e.stderr || e.message };
  }
}

function sanitizeFilename(s) { return s.replace(/[:\/\\<>?"|* ]+/g, '_'); }

async function checkPrereqs() {
  const tools = ['nmap', 'dig', 'whois'];
  for (const t of tools) if (!(await which(t))) {
    console.error(`Missing required binary: ${t}. Please install it (e.g. apt install ${t}).`);
    process.exit(2);
  }
}
checkPrereqs();

class FileTail {
  constructor(filePath, onLine) {
    this.filePath = filePath;
    this.onLine = onLine;
    this.position = 0;
    this.inode = null;
    this.buffer = '';
    this.watch = null;
    this.start();
  }

  async start() {
    try {
      const st = fs.statSync(this.filePath);
      this.inode = st.ino;
      this.position = st.size;
    } catch {}
    this.watch = fs.watch(this.filePath, { persistent: true }, async () => {
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
      } catch {}
    });
  }

  close() { try { if (this.watch) this.watch.close(); } catch {} }
}

class ScanQueue {
  constructor(concurrency = 1) { this.c = concurrency; this.r = 0; this.q = []; this.set = new Set(); }
  push(ip) { if (this.set.has(ip)) return; this.set.add(ip); this.q.push(ip); this.next(); }
  next() {
    if (this.r >= this.c) return;
    const ip = this.q.shift(); if (!ip) return;
    this.r++; this.run(ip).finally(() => { this.r--; this.set.delete(ip); this.next(); });
  }
  async run(ip) {
    try { log('Scanning', ip); await performScan(ip); log('Done', ip); }
    catch (e) { console.error('Error scanning', ip, e); }
  }
}

const IPV4 = '(?:\\d{1,3}\\.){3}\\d{1,3}';
const IPV6 = '(?:[0-9a-fA-F:]+)';
const IP_RE = new RegExp(`(${IPV4}|${IPV6})`);
const BAN_RE = new RegExp('\\bBan\\b.*(' + IPV4 + '|' + IPV6 + ')', 'i');

async function performScan(ip) {
  const now = new Date();
  const dateDir = now.toISOString().slice(0, 10);
  const safeIp = sanitizeFilename(ip);
  const outDir = path.join(OUT_ROOT, dateDir, `${safeIp}_${now.toISOString().replace(/[:.]/g, '-')}`);
  safeMkdirSync(outDir);

  const summary = { ip, ts: now.toISOString(), cmds: {} };

  const nmapRes = await runCmd('nmap', NMAP_ARGS_STR.trim().split(/\s+/).concat([ip]));
  fs.writeFileSync(path.join(outDir, 'nmap.txt'), nmapRes.stdout + (nmapRes.stderr ? '\n\n' + nmapRes.stderr : ''));
  summary.cmds.nmap = { ok: nmapRes.ok };

  const digRes = await runCmd('dig', ['-x', ip, '+short']);
  fs.writeFileSync(path.join(outDir, 'dig.txt'), digRes.stdout + (digRes.stderr ? '\n\n' + digRes.stderr : ''));
  summary.cmds.dig = { ok: digRes.ok };

  const whoisRes = await runCmd('whois', [ip]);
  fs.writeFileSync(path.join(outDir, 'whois.txt'), whoisRes.stdout + (whoisRes.stderr ? '\n\n' + whoisRes.stderr : ''));
  summary.cmds.whois = { ok: whoisRes.ok };

  fs.writeFileSync(path.join(outDir, 'summary.json'), JSON.stringify(summary, null, 2));
}

const q = new ScanQueue(CONCURRENCY);
log('Fail2Scan daemon started on', LOG_PATH);
const tail = new FileTail(LOG_PATH, (line) => {
  const match = BAN_RE.exec(line);
  if (match && match[1]) q.push(match[1]);
});

process.on('SIGINT', () => { log('Stopping...'); tail.close(); process.exit(0); });
process.on('SIGTERM', () => { log('Stopping...'); tail.close(); process.exit(0); });
