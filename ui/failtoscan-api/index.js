require('dotenv').config({ quiet: true })
const express = require('express')
const helmet = require('helmet')
const path = require('path')
const fs = require('fs').promises

const app = express()
app.use(helmet())
app.set('trust proxy', true)

const EXEMPT_PATHS = new Set([
  '/',
  '/robots.txt',
  '/favicon.ico',
  '/health',
  '/.well-known/security.txt'
])

app.use((req, res, next) => {
  const q = Object.keys(req.query)
  res.setHeader('Access-Control-Allow-Origin', '*') // front
  res.setHeader('Access-Control-Allow-Methods', 'GET')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  if (!EXEMPT_PATHS.has(req.path)) return res.status(444).end()
  if (q.length > 0 && q[0] !== 'scan') return res.status(444).end()
  next()
})

const LOG_DIR = process.env.LOG_DIR || '/var/log/fail2scan'

async function readDirSafe(dir) {
  try { return await fs.readdir(dir, { withFileTypes: true }) }
  catch (err) { if (err.code === 'ENOENT' || err.code === 'EACCES') return []; throw err }
}

async function readFileUtf8Safe(fp) {
  try { return await fs.readFile(fp, 'utf8') }
  catch (err) { if (err.code === 'ENOENT' || err.code === 'EACCES') return null; throw err }
}

async function buildListingNames() {
  const out = {}
  const dateDirs = await readDirSafe(LOG_DIR)
  for (const dateDirEnt of dateDirs.filter(d => d.isDirectory())) {
    const dateName = dateDirEnt.name
    const datePath = path.join(LOG_DIR, dateName)
    const entries = await readDirSafe(datePath)
    const names = []
    for (const ent of entries) {
      if (ent.isDirectory()) names.push(ent.name)
      else if (ent.isFile()) {
        const key = ent.name.split('_')[0] + '_' + ent.name.split('_').slice(1).join('_')
        if (!names.includes(key)) names.push(key)
      }
    }
    out[dateName] = names
  }
  return out
}

async function readFullScanByName(scanName) {
  const dateDirs = await readDirSafe(LOG_DIR)
  for (const dateDirEnt of dateDirs.filter(d => d.isDirectory())) {
    const dateName = dateDirEnt.name
    const datePath = path.join(LOG_DIR, dateName)
    const dirCandidates = await readDirSafe(datePath)
    for (const ent of dirCandidates) {
      if (ent.isDirectory() && ent.name === scanName) {
        const scanPath = path.join(datePath, ent.name)
        const files = await readDirSafe(scanPath)
        const fileEntries = await Promise.all(files.filter(f => f.isFile()).map(async f => {
          const fpath = path.join(scanPath, f.name)
          const raw = await readFileUtf8Safe(fpath)
          if (raw === null) return [f.name, null]
          if (f.name.endsWith('.json')) {
            try { return [f.name, JSON.parse(raw)] } catch { return [f.name, raw] }
          }
          return [f.name, raw]
        }))
        return { date: dateName, scan: scanName, files: Object.fromEntries(fileEntries) }
      }
    }
    const flatMatches = dirCandidates.filter(e => e.isFile() && e.name.startsWith(scanName + '_'))
    if (flatMatches.length) {
      const fileEntries = await Promise.all(flatMatches.map(async f => {
        const fpath = path.join(datePath, f.name)
        const raw = await readFileUtf8Safe(fpath)
        if (raw === null) return [f.name, null]
        if (f.name.endsWith('.json')) {
          try { return [f.name, JSON.parse(raw)] } catch { return [f.name, raw] }
        }
        return [f.name, raw]
      }))
      return { date: dateName, scan: scanName, files: Object.fromEntries(fileEntries) }
    }
  }
  return null
}

app.get('/', async (req, res) => {
  try {
    const scan = req.query.scan
    if (scan) {
      const data = await readFullScanByName(scan)
      if (!data) return res.status(404).json({ error: 'scan not found' })
      return res.json(data)
    }
    const listing = await buildListingNames()
    res.json(listing)
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Internal server error' })
  }
})

app.get('/health', (req, res) => res.json({ ok: true }))
app.get('/robots.txt', (req, res) => res.type('text/plain').send('User-agent: *\nDisallow: /'))

const port = Number(process.env.APP_PORT) || 11111
app.listen(port, () => console.log(`${process.env.APP_NAME || 'unknown'} listening on ${port} as pid ${process.pid}`))
