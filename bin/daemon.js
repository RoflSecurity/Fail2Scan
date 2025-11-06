#!/usr/bin/env node
'use strict';
const fs = require('fs'), path = require('path'), os = require('os');
const { execFile, spawn } = require('child_process');
const { promisify } = require('util');
const execFileP = promisify(execFile);

// -------------------- CLI / CONFIG --------------------
const argv = process.argv.slice(2);
const getArg = (k,d) => { for(let i=0;i<argv.length;i++){const a=argv[i]; if(a===k&&argv[i+1]) return argv[++i]; if(a.startsWith(k+'=')) return a.split('=')[1]; } return d; };
if(argv.includes('--help')||argv.includes('-h')){console.log(`Fail2Scan optimized daemon
--log PATH (default /var/log/fail2ban.log)
--out PATH (default /var/log/fail2scan)
--concurrency N (default 1)
--cores N (override concurrency with CPU cores)
--nmap-args "args" (default "-sS -Pn -p- -T4 -sV")
--scan-ip IP (do one scan and exit)
--quiet
`); process.exit(0); }

const LOG_PATH = getArg('--log','/var/log/fail2ban.log');
const OUT_ROOT = getArg('--out','/var/log/fail2scan');
const USER_CONCURRENCY = parseInt(getArg('--concurrency','0'),10)||0;
const CORE_OVERRIDE = parseInt(getArg('--cores','0'),10)||0;
const NMAP_ARGS_STR = getArg('--nmap-args','-sS -Pn -p- -T4 -sV');
const SINGLE_IP = getArg('--scan-ip',null);
const QUIET = argv.includes('--quiet');
const RESCAN_TTL_SEC = 60*60;
const STATE_FILE = path.join(os.homedir(),'.fail2scan_state.json');
const LOG_FILE = path.join(os.homedir(),'.fail2scan.log');

const log=(...a)=>{if(!QUIET)console.log(new Date().toISOString(),...a); try{fs.appendFileSync(LOG_FILE,new Date().toISOString()+' '+a.join(' ')+'\n');}catch{}};

// -------------------- utilities --------------------
const sanitizeFilename=s=>String(s).replace(/[:\/\\<>?"|* ]+/g,'_');
async function which(bin){try{await execFileP('which',[bin]);return true;}catch{return false;}}
async function runCmdCapture(cmd,args,opts={}){try{const {stdout,stderr}=await execFileP(cmd,args,{maxBuffer:1024*1024*32,...opts}); return {ok:true,stdout:stdout||'',stderr:stderr||''};}catch(e){return {ok:false,stdout:(e.stdout||'')+'',stderr:(e.stderr||e.message)+''};}}
function safeMkdirSyncWithFallback(p){try{return fs.mkdirSync(p,{recursive:true,mode:0o750})||p}catch(e){const f=path.join('/tmp','fail2scan');try{return fs.mkdirSync(f,{recursive:true,mode:0o750})||f}catch(ee){throw e;}}}

// -------------------- prerequisites --------------------
(async()=>{for(const t of ['nmap','dig','whois','which']){if(t==='which')continue;if(!(await which(t))){console.error(`Missing required binary: ${t}`);process.exit(2);}}})().catch(e=>{console.error('Prereq check failed',e);process.exit(2);});

// -------------------- state --------------------
function loadState(){try{if(fs.existsSync(STATE_FILE)){const j=JSON.parse(fs.readFileSync(STATE_FILE,'utf8'));return{seen:new Set(Array.isArray(j.seen)?j.seen:[]),retryAfter:typeof j.retryAfter==='object'?j.retryAfter:{}};}}catch{}return{seen:new Set(),retryAfter:{}};}
function saveState(s){try{fs.mkdirSync(path.dirname(STATE_FILE),{recursive:true,mode:0o700});fs.writeFileSync(STATE_FILE,JSON.stringify({seen:Array.from(s.seen||[]),retryAfter:s.retryAfter||{}},null,2));}catch{}}
const STATE=loadState();

// -------------------- IP extraction --------------------
function extractIpFromLine(line){const v4=line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);if(v4&&v4[0])return v4[0];const v6=line.match(/\b([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b/);if(v6&&v6[0])return v6[0];return null;}

// -------------------- scan --------------------
function spawnNmap(ip,outDir,args){return new Promise((res,rej)=>{const outNmap=path.join(outDir,'nmap.txt');const proc=spawn('nmap',[...args,ip],{stdio:['ignore','pipe','pipe']});const outStream=fs.createWriteStream(outNmap,{flags:'w'});proc.stdout.pipe(outStream);let err='';proc.stderr.on('data',c=>{err+=c.toString();});proc.on('close',code=>{if(err)fs.appendFileSync(outNmap,'\n\nSTDERR:\n'+err);res({code,ok:code===0});});proc.on('error',e=>rej(e));});}
async function performScan(ip){
  const now=new Date(),dateDir=now.toISOString().slice(0,10),safeIp=sanitizeFilename(ip);
  let outDir=path.join(OUT_ROOT,dateDir,`${safeIp}_${now.toISOString().replace(/[:.]/g,'-')}`);
  outDir=path.join(safeMkdirSyncWithFallback(path.dirname(outDir)),path.basename(outDir));
  fs.mkdirSync(outDir,{recursive:true,mode:0o750});
  const summary={ip,ts:now.toISOString(),cmds:{}};
  const requested=NMAP_ARGS_STR.trim().split(/\s+/).filter(Boolean);
  const isRoot=(typeof process.getuid==='function'&&process.getuid()===0);
  const nmapArgs=requested.map(a=>(!isRoot&&a==='-sS')?'-sT':a);
  try{log('Running nmap on',ip,'args:',nmapArgs.join(' '));await spawnNmap(ip,outDir,nmapArgs);summary.cmds.nmap={ok:true,args:nmapArgs.join(' '),path:'nmap.txt'}}catch(e){log('nmap failed for',ip,e.message);summary.cmds.nmap={ok:false,err:e.message};}
  try{const dig=await runCmdCapture('dig',['-x',ip,'+short']);fs.writeFileSync(path.join(outDir,'dig.txt'),(dig.stdout||'')+(dig.stderr?'\n\nSTDERR:\n'+dig.stderr:''));summary.cmds.dig={ok:dig.ok,path:'dig.txt'}}catch(e){summary.cmds.dig={ok:false,err:e.message};}
  try{const who=await runCmdCapture('whois',[ip]);fs.writeFileSync(path.join(outDir,'whois.txt'),(who.stdout||'')+(who.stderr?'\n\nSTDERR:\n'+who.stderr:''));summary.cmds.whois={ok:who.ok,path:'whois.txt'}}catch(e){summary.cmds.whois={ok:false,err:e.message};}
  try{const nmapTxt=fs.readFileSync(path.join(outDir,'nmap.txt'),'utf8');summary.open_ports=nmapTxt.split(/\r?\n/).filter(l=>/^\d+\/tcp\s+open/.test(l)).map(l=>l.trim());}catch(e){summary.open_ports=[];}
  fs.writeFileSync(path.join(outDir,'summary.json'),JSON.stringify(summary,null,2));
  try{fs.chmodSync(outDir,0o750);}catch{}
  log('Scan written for',ip,'->',outDir);
}

// -------------------- queue optimized --------------------
class ScanQueue{
  constructor(concurrency=1){this.concurrency=concurrency;this.running=0;this.q=[];this.set=STATE.seen;this.tmpCache=new Set();}
  push(ip){
    const now=Math.floor(Date.now()/1000),next=STATE.retryAfter[ip]||0;
    if((this.set.has(ip)&&next>now)||this.tmpCache.has(ip)){log('IP already queued or running (TTL/cache):',ip);return;}
    if(this.set.has(ip)&&next<=now)log('Re-queueing after TTL:',ip),this.set.delete(ip);
    this.set.add(ip);STATE.seen=this.set;saveState(STATE);
    this.q.push(ip);this.tmpCache.add(ip);this._next();
  }
  _next(){
    if(this.running>=this.concurrency)return;
    const ip=this.q.shift();if(!ip)return;
    this.running++;
    (async()=>{
      try{log('Scanning',ip);await performScan(ip);log('Done',ip);}
      catch(e){log('Error scanning',ip,e.message||e);}
      finally{
        STATE.retryAfter[ip]=Math.floor(Date.now()/1000)+RESCAN_TTL_SEC;
        saveState(STATE);
        this.set.delete(ip);this.tmpCache.delete(ip);
        this.running--;setImmediate(()=>this._next());
      }
    })();
    setImmediate(()=>this._next());
  }
}

// -------------------- main --------------------
if(SINGLE_IP){(async()=>{const q=new ScanQueue(CORE_OVERRIDE||USER_CONCURRENCY||1);q.push(SINGLE_IP);})();return;}
const concurrency = CORE_OVERRIDE||USER_CONCURRENCY||os.cpus().length||1;
const q = new ScanQueue(concurrency);
log(`Fail2Scan started. Watching ${LOG_PATH} -> output ${OUT_ROOT}, concurrency ${concurrency}`);

const BAN_RE = /\bBan\b/i;
class FileTail{
  constructor(filePath,onLine){this.filePath=filePath;this.onLine=onLine;this.pos=0;this.inode=null;this.buf='';this.watch=null;this.start();}
  start(){try{const st=fs.statSync(this.filePath);this.inode=st.ino;this.pos=st.size;}catch{this.inode=null;this.pos=0;}this._watch();this._readNew().catch(()=>{});}
  _watch(){try{this.watch=fs.watch(this.filePath,{persistent:true},async()=>{try{const st=fs.statSync(this.filePath);if(!st){this.inode=null;this.pos=0;return;}if(this.inode!==null&&st.ino!==this.inode)this.inode=st.ino,this.pos=0;else if(this.inode===null)this.inode=st.ino,this.pos=0;await this._readNew();}catch{}});}catch(e){log('fs.watch failed:',e.message);}}
  async _readNew(){try{const st=fs.statSync(this.filePath);if(st.size<this.pos)this.pos=0;if(st.size===this.pos)return;const stream=fs.createReadStream(this.filePath,{start:this.pos,end:st.size-1,encoding:'utf8'});for await(const chunk of stream){this.buf+=chunk;let idx;while((idx=this.buf.indexOf('\n'))>=0){const line=this.buf.slice(0,idx);this.buf=this.buf.slice(idx+1);if(line.trim())this.onLine(line);}}this.pos=st.size;}catch{}}
  close(){try{this.watch?.close();}catch{}}
}
const tail=new FileTail(LOG_PATH,line=>{try{if(!BAN_RE.test(line))return;const ip=extractIpFromLine(line);if(!ip)return;q.push(ip);}catch(e){log('onLine handler error',e.message||e);}});

function shutdown(){log('Shutting down Fail2Scan...');tail.close();const start=Date.now();const wait=()=>{if(q.running===0||Date.now()-start>10000)process.exit(0);setTimeout(wait,500);};wait();}
process.on('SIGINT',shutdown);
process.on('SIGTERM',shutdown);
