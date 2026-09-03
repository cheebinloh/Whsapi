import makeWASocket, { useMultiFileAuthState, DisconnectReason, jidNormalizedUser, downloadMediaMessage, proto, decryptPollVote } from '@whiskeysockets/baileys'
import express from 'express'
import pino from 'pino'
import QRCode from 'qrcode'
import { DatabaseSync } from 'node:sqlite'
import crypto from 'crypto'
import http from 'node:http'
import https from 'node:https'
import fs from 'fs'
import path from 'path'
import { spawn, spawnSync } from 'node:child_process'
import zlib from 'node:zlib'
import { fileURLToPath, pathToFileURL } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
// data lives: WA_BASE_DIR override (Electron userData) > next to exe (pkg) > project dir (dev)
const BASE_DIR = process.env.WA_BASE_DIR || (process.pkg ? path.dirname(process.execPath) : __dirname)
// the dashboard ships with the code; fall back to BASE_DIR for the bare pkg exe
const UI_FILE = fs.existsSync(path.join(__dirname, 'ui.html')) ? path.join(__dirname, 'ui.html') : path.join(BASE_DIR, 'ui.html')
const AUTH_DIR = path.join(BASE_DIR, 'auth')
const DB_FILE = path.join(BASE_DIR, 'messages.db')
const ENV_FILE = path.join(BASE_DIR, '.env')
const AVATAR_DIR = path.join(BASE_DIR, 'avatars')
const MEDIA_DIR = path.join(BASE_DIR, 'media')
fs.mkdirSync(MEDIA_DIR, { recursive: true })
const MEDIA_TYPES = new Set(['imageMessage', 'videoMessage', 'audioMessage', 'documentMessage', 'stickerMessage'])
let KEEP_DAYS = Number(process.env.KEEP_DAYS) || 90
const OLDEST_MS = () => Date.now() - KEEP_DAYS * 24 * 3600e3
fs.mkdirSync(AVATAR_DIR, { recursive: true })
let API_KEY = process.env.API_KEY || ''
let WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || ''
const PORT = process.env.PORT || 3000
let WEBHOOK_URL = process.env.WEBHOOK_URL || ''
// dev-only: Host header for the webhook target, for name-based vhosts that an
// IP url can't select (e.g. WEBHOOK_URL=http://127.0.0.1/... + oc.localhost).
// Leave unset in production, where WEBHOOK_URL is a real domain.
let WEBHOOK_HOST = process.env.WEBHOOK_HOST || ''
// exposed to the internet via router port-forward: empty = allow everyone (dev),
// otherwise a comma list of exact IPs or prefixes ("203.0.113.7, 192.168.")
let ALLOW_IPS = process.env.ALLOW_IPS || ''

// ---------- pure helpers (exported for test.js) ----------

// "60123456789", "+60 12-345 6789", "60123456789@s.whatsapp.net" -> "60123456789@s.whatsapp.net"
// keeps group jids ("...@g.us") untouched
export function toJid(to) {
  if (typeof to !== 'string' || !to.trim()) throw new Error('missing "to"')
  to = to.trim()
  if (to.includes('@')) return to
  const digits = to.replace(/\D/g, '')
  if (!digits) throw new Error('invalid "to"')
  return digits + '@s.whatsapp.net'
}

// "60123456789@s.whatsapp.net" -> "60123456789"; anything else returned as-is
export function jidToNumber(jid) {
  if (!jid) return jid
  return jid.endsWith('@s.whatsapp.net') ? jid.split('@')[0].split(':')[0] : jid
}

export function extractText(message) {
  if (!message) return ''
  // polls have no plain text — render question + numbered options, matching
  // the "customer typed 2" shape poll votes already decode into
  const pollKey = Object.keys(message).find(k => k.startsWith('pollCreationMessage'))
  const poll = pollKey && message[pollKey]
  if (poll && poll.name) {
    return '📊 ' + poll.name + (poll.options || []).map((o, i) => '\n' + (i + 1) + '. ' + (o.optionName || '')).join('')
  }
  return message.conversation
    || message.extendedTextMessage?.text
    || message.imageMessage?.caption
    || message.videoMessage?.caption
    || message.documentMessage?.caption
    || message.documentMessage?.fileName
    || ''
}

export function messageType(message) {
  if (!message) return 'unknown'
  const keys = Object.keys(message).filter(k => k !== 'messageContextInfo')
  return keys[0] || 'unknown'
}

// HMAC signature the receiving server verifies (same scheme as Meta's
// X-Hub-Signature-256): sha256 over the exact raw body string
export function signBody(body, secret) {
  return 'sha256=' + crypto.createHmac('sha256', secret).update(body, 'utf8').digest('hex')
}

// "1.2.3.4, 192.168., 10.0.0.*" -> matcher list; empty string -> null (allow all)
export function parseAllowIps(str) {
  const list = String(str || '').split(',').map(s => s.trim().replace(/\*$/, '')).filter(Boolean)
  return list.length ? list : null
}

export function ipAllowed(ip, list) {
  if (!list) return true
  ip = String(ip || '').replace(/^::ffff:/, '')            // express reports v4 as ::ffff:1.2.3.4
  if (ip === '127.0.0.1' || ip === '::1') return true      // the shop PC itself is always allowed
  return list.some(entry => entry.endsWith('.') ? ip.startsWith(entry) : ip === entry)
}

// uploaded-media names: strip anything path-like; keep the extension
export function sanitizeUpName(name) {
  const base = String(name || '').split(/[\\/]/).pop().replace(/[^A-Za-z0-9._-]/g, '_')
  return base.replace(/^\.+/, '') || 'file'
}

// "media://up_123_x.jpg" -> "up_123_x.jpg", refusing anything that could
// escape the media folder; null for non-media refs
export function resolveMediaRef(ref) {
  if (typeof ref !== 'string' || !ref.startsWith('media://')) return null
  const name = ref.slice(8)
  if (!name || name.includes('/') || name.includes('\\') || name.includes('..')) return null
  return name
}

// "show typing first" seconds: 0-15 — capped so a send can never stall the
// caller's HTTP request into its timeout
export function clampTyping(s) {
  const n = Number(s) || 0
  return Math.max(0, Math.min(15, Math.round(n)))
}

/* A decrypted poll vote is a list of sha256(option name) digests. Map the first
   one back to a 1-based option number — the same thing a customer typing "2"
   produces, which is exactly what the flow engine expects. */
export function pollChoiceFromHashes(selectedHexHashes, options) {
  if (!Array.isArray(selectedHexHashes) || !selectedHexHashes.length) return null
  const byHash = {}
  options.forEach((opt, i) => {
    byHash[crypto.createHash('sha256').update(String(opt)).digest('hex')] = i + 1
  })
  for (const h of selectedHexHashes) {
    if (byHash[String(h).toLowerCase()]) return byHash[String(h).toLowerCase()]
  }
  return null
}

// ---------- message store (sqlite) ----------

const db = new DatabaseSync(DB_FILE)
db.exec('PRAGMA journal_mode = WAL')
db.exec('PRAGMA busy_timeout = 5000')
db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    id        TEXT UNIQUE,
    sender    TEXT,
    chat      TEXT,
    is_group  INTEGER,
    name      TEXT,
    type      TEXT,
    text      TEXT,
    timestamp INTEGER,
    from_me   INTEGER DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);
  CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat);
  CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
`)
try { db.exec('ALTER TABLE messages ADD COLUMN from_me INTEGER DEFAULT 0') } catch { /* column exists */ }
try { db.exec("ALTER TABLE messages ADD COLUMN media TEXT DEFAULT ''; ALTER TABLE messages ADD COLUMN raw TEXT DEFAULT ''") } catch { /* columns exist */ }
db.exec(`
  CREATE TABLE IF NOT EXISTS contacts (
    jid       TEXT PRIMARY KEY,
    name      TEXT DEFAULT '',
    avatar    TEXT DEFAULT '',
    avatar_at INTEGER DEFAULT 0
  )
`)
// polls we sent: the encryption secret is needed to read the votes back
db.exec(`
  CREATE TABLE IF NOT EXISTS polls (
    id        TEXT PRIMARY KEY,
    chat      TEXT,
    options   TEXT,
    secret    TEXT,
    created   INTEGER
  )
`)
const upsertContactStmt = db.prepare(`
  INSERT INTO contacts (jid, name) VALUES (?, ?)
  ON CONFLICT(jid) DO UPDATE SET name = excluded.name WHERE excluded.name <> ''
`)
function upsertContact(jid, name) {
  if (!jid) return
  try { upsertContactStmt.run(jid, name || '') } catch (err) { console.error('contact upsert failed:', err.message) }
}
const insertMsg = db.prepare(`
  INSERT INTO messages (id, sender, chat, is_group, name, type, text, timestamp, from_me, raw)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(id) DO UPDATE SET raw = excluded.raw WHERE messages.raw = '' AND excluded.raw <> ''
`)

// ids sent through POST /send, so the webhook can tell an engine/API send from
// a human typing on the phone — the flow engine must not auto-pause on its own
// messages. In-memory is fine: the echo event lands moments after the send.
const apiSentIds = new Set()
function rememberApiSend(id) {
  apiSentIds.add(id)
  if (apiSentIds.size > 1000) apiSentIds.delete(apiSentIds.values().next().value)
}

/* Every webhook POST is a signed envelope: { event, ts, port, data }.
   ts lets the receiver reject replays; port lets it learn this bridge's
   public address from the connection's source IP (the router forwards it).
   node:http rather than fetch: fetch strips the Host header (spec-forbidden),
   which WEBHOOK_HOST needs. */
function postWebhook(event, data) {
  if (!WEBHOOK_URL) return
  const body = JSON.stringify({ event, ts: Date.now(), port: Number(PORT), data })
  const headers = { 'Content-Type': 'application/json', 'X-WA-Signature': signBody(body, WEBHOOK_SECRET) }
  if (WEBHOOK_HOST) headers.Host = WEBHOOK_HOST
  const url = new URL(WEBHOOK_URL)
  const req = (url.protocol === 'https:' ? https : http).request(url, { method: 'POST', headers, timeout: 15000 },
    res => res.resume())
  req.on('timeout', () => req.destroy(new Error('timeout')))
  req.on('error', err => console.error('webhook failed:', err.message))
  req.end(body)
}

function saveMessage(msg, { webhook = true } = {}) {
  try {
    insertMsg.run(msg.id, msg.from, msg.chat, msg.isGroup ? 1 : 0, msg.name, msg.type, msg.text, msg.timestamp, msg.fromMe ? 1 : 0, msg.raw || '')
  } catch (err) {
    console.error('db insert failed:', err.message)
    return
  }
  // fromMe events go too: the receiver uses them to pause automation for a
  // contact when a human replies. viaApi separates engine sends from human ones.
  if (webhook) {
    const { raw, ...payload } = msg // keep media download keys internal
    payload.hasMedia = !!raw
    payload.viaApi = apiSentIds.has(msg.id)
    postWebhook('message', payload)
  }
}

// retention: drop anything older than KEEP_DAYS at startup
db.prepare('DELETE FROM messages WHERE timestamp < ?').run(OLDEST_MS())

function rowToMsg(r) {
  return {
    seq: r.seq, id: r.id, from: r.sender, chat: r.chat, isGroup: !!r.is_group, fromMe: !!r.from_me,
    name: r.name, type: r.type, text: r.text, timestamp: r.timestamp,
    hasMedia: !!(r.media || r.raw)
  }
}

// ---------- whatsapp connection ----------

let sock = null
let lastQR = null
let connectionState = 'connecting'
let groupNames = {} // jid -> subject, refreshed on connect

// resolve a possibly-LID jid to a plain phone number using the alt field or the lid mapping store
async function resolveNumber(jid, altJid) {
  if (!jid) return null
  if (jid.endsWith('@lid')) {
    if (altJid) return jidToNumber(altJid)
    try {
      const pn = await sock.signalRepository.lidMapping.getPNForLID(jid)
      if (pn) return jidToNumber(pn)
    } catch { /* mapping unknown */ }
    return jid // couldn't resolve, return raw lid
  }
  return jidToNumber(jid)
}

// converts a raw Baileys WAMessage into our stored record shape (null if not storable)
async function waMessageToRecord(m) {
  if (!m.message || !m.key.remoteJid || m.key.remoteJid === 'status@broadcast') return null
  const chatJid = m.key.remoteJid
  const isGroup = chatJid.endsWith('@g.us')
  const senderJid = isGroup ? (m.key.participant || chatJid) : chatJid
  const senderAlt = isGroup ? (m.key.participantAlt || m.key.participantPn) : (m.key.remoteJidAlt || m.key.senderPn)
  const senderNumber = await resolveNumber(senderJid, senderAlt)
  const chat = isGroup ? chatJid : await resolveNumber(chatJid, m.key.remoteJidAlt || m.key.senderPn)
  const type = messageType(m.message)
  return {
    id: m.key.id,
    from: m.key.fromMe ? 'me' : senderNumber,
    chat,
    isGroup,
    fromMe: !!m.key.fromMe,
    name: m.pushName || '',
    type,
    text: extractText(m.message),
    timestamp: Number(m.messageTimestamp) * 1000,
    // keep download keys for media so the file can be fetched on demand later
    raw: MEDIA_TYPES.has(type) ? JSON.stringify({ key: m.key, message: m.message }) : ''
  }
}

async function startWhatsApp() {
  const { state, saveCreds } = await useMultiFileAuthState(AUTH_DIR)
  sock = makeWASocket({ auth: state, logger: pino({ level: 'warn' }), syncFullHistory: true })

  sock.ev.on('creds.update', saveCreds)

  sock.ev.on('connection.update', (update) => {
    const { connection, lastDisconnect, qr } = update
    if (qr) { lastQR = qr; connectionState = 'waiting_for_qr_scan' }
    if (connection === 'open') {
      lastQR = null; connectionState = 'connected'; console.log('WhatsApp connected')
      sock.groupFetchAllParticipating()
        .then(groups => {
          for (const [jid, g] of Object.entries(groups)) { groupNames[jid] = g.subject; upsertContact(jid, g.subject) }
        })
        .catch(() => {})
      setTimeout(warmAvatars, 15000) // let history/app-state sync settle first
      setTimeout(warmMedia, 60000)
    }
    if (connection === 'close') {
      const code = lastDisconnect?.error?.output?.statusCode
      if (code === DisconnectReason.loggedOut) {
        // session invalidated -> wipe auth so a fresh QR appears
        connectionState = 'logged_out'
        fs.rmSync(AUTH_DIR, { recursive: true, force: true })
        console.log('Logged out. Restarting for new QR...')
      } else {
        connectionState = 'reconnecting'
        console.log('Connection closed (code ' + code + '), reconnecting...')
      }
      setTimeout(startWhatsApp, 3000)
    }
  })

  sock.ev.on('messages.upsert', async ({ messages: msgs, type }) => {
    if (type !== 'notify' && type !== 'append') return // notify = incoming, append = own sends
    for (const m of msgs) {
      // poll votes are encrypted updates, not text — decode them into the same
      // "customer typed 2" shape everything downstream already understands
      if (m.message?.pollUpdateMessage) {
        console.log('poll update received:', JSON.stringify({ from: m.key.remoteJid, fromMe: !!m.key.fromMe,
          pollId: m.message.pollUpdateMessage.pollCreationMessageKey?.id }))
        if (!m.key.fromMe) await handlePollVote(m).catch(err => console.error('poll vote failed:', err.message))
        continue
      }
      const rec = await waMessageToRecord(m)
      // own sends webhook too (append/fromMe): the flow engine needs to see a
      // human reply to pause automation for that contact
      if (rec) saveMessage(rec)
    }
  })

  // address-book names arrive via history sync (at pairing) and app-state updates afterwards
  const storeContacts = async (contacts) => {
    for (const c of contacts || []) {
      const jid = await resolveNumber(c.id, c.phoneNumber)
      upsertContact(jid, c.name || c.notify || c.verifiedName || '')
    }
  }
  sock.ev.on('contacts.upsert', storeContacts)
  sock.ev.on('contacts.update', storeContacts)

  // chat history pushed by WhatsApp when the device is (re)linked
  sock.ev.on('messaging-history.set', async ({ messages: msgs, contacts, progress }) => {
    await storeContacts(contacts)
    let stored = 0
    const oldest = OLDEST_MS()
    for (const m of msgs) {
      const rec = await waMessageToRecord(m)
      if (rec && rec.timestamp >= oldest) { saveMessage(rec, { webhook: false }); stored++ }
    }
    console.log(`History sync: stored ${stored} messages, ${(contacts || []).length} contacts` + (progress != null ? ` (${progress}%)` : ''))
  })
}

/* An incoming vote on a poll we sent: decrypt with the stored secret, map the
   selected option back to its 1-based number, and store/webhook it exactly as
   if the customer had typed that number. Vote *changes* come through the same
   way; retractions (nothing selected) are ignored. */
async function handlePollVote(m) {
  const pu = m.message.pollUpdateMessage
  const pollId = pu.pollCreationMessageKey && pu.pollCreationMessageKey.id
  const row = pollId ? db.prepare('SELECT * FROM polls WHERE id = ?').get(pollId) : null
  if (!row || !row.secret) return
  const options = JSON.parse(row.options)
  /* The vote is AES-keyed on (secret, poll id, creator jid, voter jid) — and
     with Baileys 7's LID addressing either side may be known to WhatsApp by
     its LID rather than its phone jid. Try every combination we hold. */
  const creators = [jidNormalizedUser(sock.user.id), sock.user.lid && jidNormalizedUser(sock.user.lid)].filter(Boolean)
  const voters = [m.key.remoteJid, m.key.remoteJidAlt, m.key.participant, m.key.participantAlt, m.key.senderPn]
    .filter(Boolean)
  let choice = null
  const tried = []
  outer:
  for (const pollCreatorJid of creators) {
    for (const voterJid of voters) {
      try {
        const dec = decryptPollVote(pu.vote, {
          pollCreatorJid,
          pollMsgId: pollId,
          pollEncKey: Buffer.from(row.secret, 'base64'),
          voterJid
        })
        const hashes = (dec.selectedOptions || []).map(b => Buffer.from(b).toString('hex'))
        choice = pollChoiceFromHashes(hashes, options)
        if (choice) {
          console.log('poll vote decrypted: option', choice, 'creator', pollCreatorJid, 'voter', voterJid)
          break outer
        }
        tried.push(pollCreatorJid + '/' + voterJid + ': decrypted but no option matched')
      } catch (err) {
        tried.push(pollCreatorJid + '/' + voterJid + ': ' + err.message)
      }
    }
  }
  if (!choice) {
    console.error('poll vote NOT decoded for ' + pollId + ' | ' + tried.join(' | '))
    return
  }
  saveMessage({
    id: m.key.id,
    pollId,                 // which poll was answered — lets the engine drop late re-taps
    from: row.chat, chat: row.chat, isGroup: false, fromMe: false,
    name: m.pushName || '',
    type: 'poll_vote',
    text: String(choice),   // downstream sees "1"/"2"… — identical to a typed pick
    timestamp: Number(m.messageTimestamp) * 1000,
    raw: ''
  })
}

// ---------- http api ----------

const app = express()
app.use(express.json({ limit: '80mb' }))   // uploads arrive base64-in-JSON (50MB file ≈ 67MB base64)

const isLocalReq = (req) => {
  const ip = String(req.ip || '').replace(/^::ffff:/, '')
  return ip === '127.0.0.1' || ip === '::1'
}

// with the router port-forwarding this process to the internet, unknown IPs get
// a bare 403 on every route — a port scanner sees a dead door, not a login page
app.use((req, res, next) => {
  if (!ipAllowed(req.ip, parseAllowIps(ALLOW_IPS))) return res.status(403).end()
  next()
})

// The dashboard shell itself contains no data, but the API key is only embedded
// for the shop PC's own browser (localhost / the Electron shell). A remote
// visitor gets the page without the key and enters it once (kept in their
// browser's localStorage) — before this, anyone finding the forwarded port got
// the key handed to them in the HTML.
app.get('/', (req, res) => {
  let html = fs.readFileSync(UI_FILE, 'utf8')
  if (isLocalReq(req)) {
    html = html.replace('</head>', `<script>window.__WA_KEY__=${JSON.stringify(API_KEY)}</script></head>`)
  }
  res.type('html').send(html)
})
app.get('/favicon.ico', (req, res) => res.status(204).end())

app.use((req, res, next) => {
  const key = req.headers['x-api-key'] || req.query.key
  if (!API_KEY || key !== API_KEY) return res.status(401).json({ error: 'invalid or missing api key (X-API-Key header or ?key=)' })
  next()
})

// GET /upload/:name — hand back a file stored by POST /upload (the name part of a media:// ref),
// so the web app can keep its own viewable copy of pictures attached to flows
app.get('/upload/:name', (req, res) => {
  const name = resolveMediaRef('media://' + req.params.name)
  if (!name || !name.startsWith('up_')) return res.status(400).json({ error: 'bad name' })
  const full = path.join(MEDIA_DIR, name)
  if (!fs.existsSync(full)) return res.status(404).json({ error: 'not found' })
  res.sendFile(full)
})

app.get('/status', (req, res) => {
  res.json({
    state: connectionState,
    user: sock?.user ? { number: jidToNumber(jidNormalizedUser(sock.user.id)), name: sock.user.name } : null,
    syncing: { avatars: warmingAvatars, media: warmingMedia },
    stats: {
      messages: db.prepare('SELECT COUNT(*) c FROM messages').get().c,
      contacts: db.prepare("SELECT COUNT(*) c FROM contacts WHERE name <> ''").get().c,
      mediaFiles: fs.readdirSync(MEDIA_DIR).length,
      avatarFiles: fs.readdirSync(AVATAR_DIR).length
    }
  })
})

app.get('/qr', async (req, res) => {
  if (connectionState === 'connected') {
    return res.send('<h2>Connected as ' + (sock?.user?.name || '') + '</h2>')
  }
  if (!lastQR) return res.send('<h2>No QR yet (' + connectionState + ')</h2><script>setTimeout(()=>location.reload(),2000)</script>')
  const dataUrl = await QRCode.toDataURL(lastQR, { width: 300 })
  res.send('<h2>Scan with WhatsApp &gt; Linked Devices</h2><img src="' + dataUrl + '"><script>setTimeout(()=>location.reload(),15000)</script>')
})

app.get('/qr.json', async (req, res) => {
  res.json({
    state: connectionState,
    user: sock?.user ? { number: jidToNumber(jidNormalizedUser(sock.user.id)), name: sock.user.name } : null,
    qr: lastQR ? await QRCode.toDataURL(lastQR, { width: 300 }) : null
  })
})

// graceful exit for updates: reply, then quit between credential writes — a
// force-kill mid-write has already cost one linked session, never again
app.post('/shutdown', (req, res) => {
  res.json({ ok: true, bye: true })
  console.log('Shutdown requested via API')
  setTimeout(() => process.exit(0), 300)
})

app.post('/logout', async (req, res) => {
  if (req.body?.clearData) {
    db.exec('DELETE FROM messages; DELETE FROM contacts')
    for (const f of fs.readdirSync(AVATAR_DIR)) fs.unlinkSync(path.join(AVATAR_DIR, f))
    for (const f of fs.readdirSync(MEDIA_DIR)) fs.unlinkSync(path.join(MEDIA_DIR, f))
    groupNames = {}
    console.log('Local database cleared on unlink')
  }
  try { await sock.logout() } catch { /* already dead; close handler still fires */ }
  res.json({ ok: true })
})

function setEnv(name, value) {
  let env = ''
  try { env = fs.readFileSync(ENV_FILE, 'utf8') } catch { /* no .env */ }
  env = env.replace(/\r\n?/g, '\n') // normalize any stray \r-only endings
  const line = name + '=' + value
  const re = new RegExp('^#?\\s*' + name + '=.*$', 'm')
  env = re.test(env) ? env.replace(re, line) : env.trimEnd() + '\n' + line + '\n'
  fs.writeFileSync(ENV_FILE, env)
}

// webhookSecret rides along so the receiving server can self-sync it over the
// API-key-authenticated channel instead of a human re-typing it on both sides
const currentSettings = () => ({ webhookUrl: WEBHOOK_URL, webhookHost: WEBHOOK_HOST, webhookSecret: WEBHOOK_SECRET, keepDays: KEEP_DAYS, mediaSyncDays: MEDIA_SYNC_DAYS, port: Number(PORT), allowIps: ALLOW_IPS })

app.get('/settings', (req, res) => res.json(currentSettings()))

app.post('/settings', (req, res) => {
  const b = req.body || {}
  if ('webhookUrl' in b) { WEBHOOK_URL = String(b.webhookUrl || '').trim(); setEnv('WEBHOOK_URL', WEBHOOK_URL) }
  if ('webhookHost' in b) { WEBHOOK_HOST = String(b.webhookHost || '').trim(); setEnv('WEBHOOK_HOST', WEBHOOK_HOST) }
  if ('allowIps' in b) { ALLOW_IPS = String(b.allowIps || '').trim(); setEnv('ALLOW_IPS', ALLOW_IPS) }
  if ('keepDays' in b) {
    KEEP_DAYS = Math.max(1, Number(b.keepDays) || 90)
    setEnv('KEEP_DAYS', KEEP_DAYS)
    db.prepare('DELETE FROM messages WHERE timestamp < ?').run(OLDEST_MS()) // apply retention now
  }
  if ('mediaSyncDays' in b) { MEDIA_SYNC_DAYS = Math.max(1, Number(b.mediaSyncDays) || 30); setEnv('MEDIA_SYNC_DAYS', MEDIA_SYNC_DAYS) }
  if ('port' in b) setEnv('PORT', Math.max(1, Number(b.port) || 3000)) // takes effect after restart
  res.json(currentSettings())
})

// re-run group names + avatar + media warm-ups on demand
app.post('/sync', (req, res) => {
  if (connectionState !== 'connected') return res.status(503).json({ error: 'whatsapp not connected' })
  sock.groupFetchAllParticipating()
    .then(groups => { for (const [jid, g] of Object.entries(groups)) { groupNames[jid] = g.subject; upsertContact(jid, g.subject) } })
    .catch(() => {})
  warmAvatars()
  warmMedia()
  res.json({ ok: true, started: true })
})

// one row per conversation, newest first; name = address book > group subject > pushName > number
app.get('/chats', (req, res) => {
  const rows = db.prepare(`
    SELECT x.chat, x.is_group, x.text, x.type, x.timestamp, x.from_me, x.cnt,
      ct.name saved_name,
      (SELECT name FROM messages WHERE chat = x.chat AND name <> '' AND from_me = 0 ORDER BY seq DESC LIMIT 1) push_name
    FROM (
      SELECT chat, is_group, text, type, timestamp, from_me,
        ROW_NUMBER() OVER (PARTITION BY chat ORDER BY timestamp DESC, seq DESC) rn,
        COUNT(*) OVER (PARTITION BY chat) cnt
      FROM messages
    ) x
    LEFT JOIN contacts ct ON ct.jid = x.chat
    WHERE x.rn = 1
    ORDER BY x.timestamp DESC
  `).all()
  res.json({
    chats: rows.map(r => ({
      chat: r.chat,
      isGroup: !!r.is_group,
      name: r.saved_name || (r.is_group ? (groupNames[r.chat] || 'Group') : (r.push_name || r.chat)),
      lastText: r.text,
      lastType: r.type,
      lastFromMe: !!r.from_me,
      timestamp: r.timestamp,
      count: r.cnt
    }))
  })
})

// profile picture, fetched once from WhatsApp then cached on disk for 7 days
const AVATAR_TTL = 7 * 24 * 3600e3
const avatarInflight = new Map()

function fetchAvatar(id) {
  if (!avatarInflight.has(id)) {
    avatarInflight.set(id, (async () => {
      let file = 'none'
      try {
        const jid = id.includes('@') ? id : id + '@s.whatsapp.net'
        const url = await sock.profilePictureUrl(jid, 'image')
        const buf = Buffer.from(await (await fetch(url)).arrayBuffer())
        file = id.replace(/[^A-Za-z0-9]/g, '_') + '.jpg'
        fs.writeFileSync(path.join(AVATAR_DIR, file), buf)
      } catch { /* no picture or privacy-restricted */ }
      upsertContact(id, '')
      db.prepare('UPDATE contacts SET avatar = ?, avatar_at = ? WHERE jid = ?').run(file, Date.now(), id)
      return file
    })().finally(() => avatarInflight.delete(id)))
  }
  return avatarInflight.get(id)
}

// slowly pre-download every chat's picture so the whole list has images without waiting for scroll
// ponytail: 1.5s spacing to stay well under WhatsApp's radar; a full pass over ~700 chats takes ~20 min once a week
let warmingAvatars = false
async function warmAvatars() {
  if (warmingAvatars) return
  warmingAvatars = true
  const ids = db.prepare('SELECT DISTINCT chat FROM messages').all().map(r => r.chat)
  for (const id of ids) {
    if (connectionState !== 'connected') break
    const row = db.prepare('SELECT avatar, avatar_at FROM contacts WHERE jid = ?').get(id)
    if (row && row.avatar && Date.now() - row.avatar_at < AVATAR_TTL) continue
    await fetchAvatar(id).catch(() => {})
    await new Promise(r => setTimeout(r, 1500))
  }
  warmingAvatars = false
  console.log('Avatar warm-up pass finished')
}
const placeholderSvg = (label) => `<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96">
  <rect width="96" height="96" rx="48" fill="#263830"/>
  <text x="48" y="62" font-family="sans-serif" font-size="40" fill="#8BA398" text-anchor="middle">${label}</text></svg>`

app.get('/avatar/:id', async (req, res) => {
  const id = req.params.id
  const initial = [...(String(req.query.n || '#'))][0].toUpperCase().replace(/[<>&"]/g, '#')
  const fallback = () => res.type('svg').send(placeholderSvg(initial))
  const row = db.prepare('SELECT avatar, avatar_at FROM contacts WHERE jid = ?').get(id)
  const fresh = row && Date.now() - row.avatar_at < AVATAR_TTL
  if (fresh && row.avatar === 'none') return fallback()
  if (fresh && row.avatar) return res.sendFile(path.join(AVATAR_DIR, row.avatar))
  if (connectionState !== 'connected') return fallback()
  const file = await fetchAvatar(id)
  file === 'none' ? fallback() : res.sendFile(path.join(AVATAR_DIR, file))
})

// media file for a message: served from cache, downloaded from WhatsApp on first request
const EXT = {
  'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif',
  'video/mp4': 'mp4', 'audio/ogg': 'ogg', 'audio/mpeg': 'mp3', 'audio/mp4': 'm4a', 'audio/wav': 'wav',
  'application/pdf': 'pdf'
}
const mediaInflight = new Map()

function downloadMediaFor(row) { // row: {id, raw, type}
  if (!mediaInflight.has(row.id)) {
    mediaInflight.set(row.id, (async () => {
      const parsed = JSON.parse(row.raw)
      let waMsg = proto.WebMessageInfo.fromObject(parsed)
      const ctx = { logger: pino({ level: 'warn' }), reuploadRequest: sock.updateMediaMessage }
      let buf
      try {
        buf = await downloadMediaMessage(waMsg, 'buffer', {}, ctx)
      } catch {
        // expired CDN link: ask the phone to re-upload, then retry with the fresh keys
        waMsg = await sock.updateMediaMessage(waMsg)
        db.prepare('UPDATE messages SET raw = ? WHERE id = ?')
          .run(JSON.stringify({ key: waMsg.key, message: waMsg.message }), row.id)
        buf = await downloadMediaMessage(waMsg, 'buffer', {}, ctx)
      }
      const inner = parsed.message[row.type] || {}
      const mime = String(inner.mimetype || '').split(';')[0]
      const ext = EXT[mime] || (inner.fileName ? String(inner.fileName).split('.').pop().toLowerCase() : 'bin')
      const file = row.id.replace(/[^A-Za-z0-9]/g, '_') + '.' + ext
      fs.writeFileSync(path.join(MEDIA_DIR, file), buf)
      db.prepare('UPDATE messages SET media = ? WHERE id = ?').run(file, row.id)
      return file
    })().finally(() => mediaInflight.delete(row.id)))
  }
  return mediaInflight.get(row.id)
}

// background download of recent media so files are on disk without opening each chat
// ponytail: 30-day window and 15MB cap keep disk use sane; older/larger media still loads on view
let MEDIA_SYNC_DAYS = Number(process.env.MEDIA_SYNC_DAYS) || 30
let warmingMedia = false
async function warmMedia() {
  if (warmingMedia) return
  warmingMedia = true
  const rows = db.prepare(
    "SELECT id, raw, type FROM messages WHERE raw <> '' AND media = '' AND timestamp > ? ORDER BY timestamp DESC"
  ).all(Date.now() - MEDIA_SYNC_DAYS * 24 * 3600e3)
  let ok = 0, fail = 0
  for (const row of rows) {
    if (connectionState !== 'connected') break
    try {
      const size = Number(JSON.parse(row.raw).message?.[row.type]?.fileLength || 0)
      if (size > 15e6) continue
      await downloadMediaFor(row)
      ok++
    } catch { fail++ }
    await new Promise(r => setTimeout(r, 2000))
  }
  console.log(`Media warm-up finished: ${ok} downloaded, ${fail} failed of ${rows.length}`)
  warmingMedia = false
}

app.get('/media/:id', async (req, res) => {
  const row = db.prepare('SELECT id, media, raw, type FROM messages WHERE id = ?').get(req.params.id)
  if (!row) return res.status(404).json({ error: 'message not found' })
  if (row.media && fs.existsSync(path.join(MEDIA_DIR, row.media))) {
    return res.sendFile(path.join(MEDIA_DIR, row.media))
  }
  if (!row.raw) return res.status(404).json({ error: 'no media stored for this message' })
  if (connectionState !== 'connected') return res.status(503).json({ error: 'whatsapp not connected' })
  try {
    const file = await downloadMediaFor(row)
    res.sendFile(path.join(MEDIA_DIR, file))
  } catch (err) {
    res.status(502).json({ error: 'media download failed: ' + err.message })
  }
})

/* Media uploaded from the flow builder (via oc), stored beside the session
   that will send it. base64-in-JSON keeps the bridge dependency-free. */
const UPLOAD_EXT = {
  jpg: 'image', jpeg: 'image', png: 'image', webp: 'image', gif: 'image', mp4: 'video',
  ogg: 'audio', webm: 'audio', opus: 'audio', m4a: 'audio', mp3: 'audio', aac: 'audio',
  pdf: 'document', doc: 'document', docx: 'document', xls: 'document', xlsx: 'document',
  ppt: 'document', pptx: 'document', txt: 'document', csv: 'document', zip: 'document'
}
const AUDIO_MIME = {
  ogg: 'audio/ogg; codecs=opus', webm: 'audio/webm', opus: 'audio/ogg; codecs=opus',
  m4a: 'audio/mp4', mp3: 'audio/mpeg', aac: 'audio/aac'
}
// documents are sent with their mime type, or WhatsApp shows them as a blank file
const DOC_MIME = {
  pdf: 'application/pdf', doc: 'application/msword',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt: 'application/vnd.ms-powerpoint',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  txt: 'text/plain', csv: 'text/csv', zip: 'application/zip'
}
app.post('/upload', (req, res) => {
  const { name, data } = req.body || {}
  const clean = sanitizeUpName(name)
  const ext = clean.split('.').pop().toLowerCase()
  const kind = UPLOAD_EXT[ext]
  if (!kind) return res.status(400).json({ error: 'allowed: ' + Object.keys(UPLOAD_EXT).join(', ') })
  let buf
  try { buf = Buffer.from(String(data || ''), 'base64') } catch { buf = null }
  if (!buf || !buf.length) return res.status(400).json({ error: 'empty file' })
  if (buf.length > 15e6) return res.status(400).json({ error: 'file too large (max 15MB)' })
  const file = 'up_' + Date.now() + '_' + clean
  fs.writeFileSync(path.join(MEDIA_DIR, file), buf)
  res.json({ ok: true, media: 'media://' + file, kind, bytes: buf.length })
})

// media:// refs resolve to local files; anything else is a URL Baileys fetches
function mediaSource(ref) {
  const name = resolveMediaRef(ref)
  if (!name) return { url: ref }
  const full = path.join(MEDIA_DIR, name)
  if (!fs.existsSync(full)) throw new Error('media not found: ' + name)
  return fs.readFileSync(full)
}

app.post('/send', async (req, res) => {
  if (connectionState !== 'connected') return res.status(503).json({ error: 'whatsapp not connected', state: connectionState })
  try {
    const { to, text, imageUrl, videoUrl, documentUrl, audioUrl, ptt, fileName, caption, poll, typingSeconds } = req.body || {}
    const jid = toJid(to)
    let content, pollValues = null
    if (poll) {
      const name = String(poll.name || '').trim()
      pollValues = (Array.isArray(poll.values) ? poll.values : []).map(v => String(v).trim()).filter(Boolean)
      if (!name || pollValues.length < 2 || pollValues.length > 12) {
        return res.status(400).json({ error: 'poll needs a name and 2-12 options' })
      }
      content = { poll: { name, values: pollValues, selectableCount: 1 } }
    } else if (videoUrl) content = { video: mediaSource(videoUrl), caption: caption || text || '' }
    else if (audioUrl) {
      /* ptt=1 marks it a voice note. Browser recordings are webm/opus - declared
         as ogg/opus so WhatsApp treats them as playable voice messages (same
         opus payload; iOS can be picky about exotic containers). */
      const isPtt = String(ptt) === '1' || ptt === true
      const ext = String(resolveMediaRef(audioUrl) || audioUrl).split('.').pop().toLowerCase()
      content = {
        audio: mediaSource(audioUrl),
        ptt: isPtt,
        mimetype: isPtt ? 'audio/ogg; codecs=opus' : (AUDIO_MIME[ext] || 'audio/mpeg')
      }
    }
    else if (imageUrl) content = { image: mediaSource(imageUrl), caption: caption || text || '' }
    else if (documentUrl) {
      const named = sanitizeUpName(fileName || resolveMediaRef(documentUrl) || 'file')
      content = {
        document: mediaSource(documentUrl),
        mimetype: DOC_MIME[named.split('.').pop().toLowerCase()] || 'application/octet-stream',
        fileName: named,
        caption: caption || text || ''
      }
    }
    else if (text) content = { text }
    else return res.status(400).json({ error: 'provide "text", "imageUrl", "videoUrl", "documentUrl" or "poll"' })
    // "typing..." for a moment before the message lands, like a human would
    const typing = clampTyping(typingSeconds)
    if (typing > 0) {
      try {
        await sock.sendPresenceUpdate('composing', jid)
        await new Promise(r => setTimeout(r, typing * 1000))
        await sock.sendPresenceUpdate('paused', jid)
      } catch { /* presence is cosmetic — never block the send on it */ }
    }
    const result = await sock.sendMessage(jid, content)
    rememberApiSend(result.key.id)   // so the webhook flags this send as viaApi, not a human reply
    if (pollValues) {
      // keep the poll's encryption secret, or the votes can never be read back
      const secret = result.message && result.message.messageContextInfo && result.message.messageContextInfo.messageSecret
      db.prepare('INSERT OR REPLACE INTO polls (id, chat, options, secret, created) VALUES (?, ?, ?, ?, ?)')
        .run(result.key.id, jidToNumber(jid), JSON.stringify(pollValues),
             secret ? Buffer.from(secret).toString('base64') : '', Date.now())
      if (!secret) console.error('poll sent without messageSecret — votes will not decrypt')
    }
    res.json({ ok: true, id: result.key.id, to: jidToNumber(jid), poll: !!pollValues })
  } catch (err) {
    res.status(err.message.includes('"to"') ? 400 : 500).json({ error: err.message })
  }
})

/* POST /youtube {to, url, caption?} - downloads the YouTube video, compresses
   it to WhatsApp size (480p-ish, x264 crf28) and sends it as a playable video
   message. The work takes a while, so the request is answered immediately and
   the send happens in the background - watch the console for failures. */
/* Each send is a tracked job: GET /youtube/status?id=... follows it through
   downloading (with %) -> compressing -> sending -> sent | failed(error). */
const ytJobs = new Map()

function ytJobSet(id, patch) {
  const j = ytJobs.get(id)
  if (j) Object.assign(j, patch, { updated: Date.now() })
}

app.get('/youtube/status', (req, res) => {
  const j = ytJobs.get(String(req.query.id || ''))
  if (!j) return res.status(404).json({ error: 'unknown job' })
  res.json({ ok: true, job: j })
})

app.post('/youtube', (req, res) => {
  const { to, url, caption } = req.body || {}
  let jid
  try { jid = toJid(to) } catch (e) { return res.status(400).json({ error: e.message }) }
  if (!/^(https?:\/\/)?(www\.|m\.)?(youtube\.com|youtu\.be)\//i.test(String(url || ''))) {
    return res.status(400).json({ error: 'not a youtube link' })
  }
  if (connectionState !== 'connected') return res.status(503).json({ error: 'whatsapp not connected', state: connectionState })
  const id = crypto.randomUUID()
  ytJobs.set(id, { id, url: String(url), status: 'queued', percent: 0, error: '', created: Date.now(), updated: Date.now() })
  // old jobs age out - the map must not grow forever
  for (const [k, j] of ytJobs) { if (Date.now() - j.created > 3600000) ytJobs.delete(k) }
  res.json({ ok: true, queued: true, job: id })
  sendYoutubeVideo(id, jid, String(url), String(caption || ''))
    .catch(err => {
      ytJobSet(id, { status: 'failed', error: err.message })
      console.error('youtube send failed:', url, '-', err.message)
    })
})

// POST /youtube/prepare { url } -> { job }; poll /youtube/status?id= until status 'ready' (media, bytes) or 'failed'
app.post('/youtube/prepare', (req, res) => {
  const { url } = req.body || {}
  if (!/^(https?:\/\/)?(www\.|m\.)?(youtube\.com|youtu\.be)\//i.test(String(url || ''))) {
    return res.status(400).json({ error: 'not a youtube link' })
  }
  const id = crypto.randomUUID()
  ytJobs.set(id, { id, url: String(url), status: 'queued', percent: 0, error: '', created: Date.now(), updated: Date.now() })
  for (const [k, j] of ytJobs) { if (Date.now() - j.created > 3600000) ytJobs.delete(k) }
  res.json({ ok: true, queued: true, job: id })
  prepareYoutubeVideo(id, String(url))
    .catch(err => {
      ytJobSet(id, { status: 'failed', error: err.message })
      console.error('youtube prepare failed:', url, '-', err.message)
    })
})

// POST /video/prepare { name, data(base64) } -> { job }; same status polling as /youtube/prepare
app.post('/video/prepare', (req, res) => {
  const { name, data } = req.body || {}
  const clean = sanitizeUpName(name)
  const ext = clean.split('.').pop().toLowerCase()
  if (!['mp4', 'mov', 'm4v', 'webm', 'mkv', 'avi', '3gp'].includes(ext)) return res.status(400).json({ error: 'allowed: mp4, mov, m4v, webm, mkv, avi, 3gp' })
  let buf
  try { buf = Buffer.from(String(data || ''), 'base64') } catch { buf = null }
  if (!buf || !buf.length) return res.status(400).json({ error: 'empty file' })
  if (buf.length > 200e6) return res.status(400).json({ error: 'file too large (max 200MB before compression)' })
  const raw = path.join(MEDIA_DIR, 'vid-' + Date.now() + '-raw.' + ext)
  fs.writeFileSync(raw, buf)
  const id = crypto.randomUUID()
  ytJobs.set(id, { id, url: clean, status: 'queued', percent: 100, error: '', created: Date.now(), updated: Date.now() })
  for (const [k, j] of ytJobs) { if (Date.now() - j.created > 3600000) ytJobs.delete(k) }
  res.json({ ok: true, queued: true, job: id })
  prepareUploadedVideo(id, raw)
    .catch(err => {
      ytJobSet(id, { status: 'failed', error: err.message })
      console.error('video prepare failed:', clean, '-', err.message)
    })
})

/* The extractor is yt-dlp, fetched on first use and self-updated weekly - the
   pure-JS libraries (ytdl-core & friends) all break whenever YouTube changes
   its player, yt-dlp is the one that keeps recovering. */
const YTDLP_URL = {
  darwin: 'https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp_macos',
  win32: 'https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp.exe',
  linux: 'https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp'
}

async function ensureYtDlp() {
  const bin = path.join(BASE_DIR, process.platform === 'win32' ? 'yt-dlp.exe' : 'yt-dlp')
  if (!fs.existsSync(bin)) {
    console.log('downloading yt-dlp...')
    const res = await fetch(YTDLP_URL[process.platform] || YTDLP_URL.linux)
    if (!res.ok) throw new Error('yt-dlp download failed: http ' + res.status)
    fs.writeFileSync(bin, Buffer.from(await res.arrayBuffer()))
    if (process.platform !== 'win32') fs.chmodSync(bin, 0o755)
  } else if (Date.now() - fs.statSync(bin).mtimeMs > 7 * 86400000) {
    // the standalone binary updates itself; stale extractors are the #1 failure
    await new Promise(resolve => {
      const p = spawn(bin, ['-U'])
      p.on('close', () => { try { fs.utimesSync(bin, new Date(), new Date()) } catch {} resolve() })
      p.on('error', resolve)   // update is best-effort, never blocks a send
    })
  }
  return bin
}

/* Inside the packaged Electron app the ffmpeg binary lives in app.asar.unpacked
   (spawning from within the asar archive is impossible - ENOTDIR), but the
   module still reports the in-archive path. Point past the archive. */
/* ...and the bundled binary must match this CPU: a build packed on the wrong
   runner arch dies with spawn error -86. So the binary is TESTED before use,
   and if it will not run here the matching build for process.arch is fetched
   once into the data dir (the same release ffmpeg-static itself installs from). */
let ffmpegResolved = null
async function ffmpegBin() {
  if (ffmpegResolved) return ffmpegResolved
  const works = p => { try { return !!p && spawnSync(p, ['-version']).status === 0 } catch { return false } }
  const bundled = ((await import('ffmpeg-static')).default || '').replace(/app\.asar([\\/])/, 'app.asar.unpacked$1')
  if (works(bundled)) return (ffmpegResolved = bundled)
  const local = path.join(BASE_DIR, process.platform === 'win32' ? 'ffmpeg.exe' : 'ffmpeg')
  if (works(local)) return (ffmpegResolved = local)
  console.log('bundled ffmpeg unusable on ' + process.platform + '/' + process.arch + ' - downloading a matching build')
  const url = 'https://github.com/eugeneware/ffmpeg-static/releases/download/b6.1.1/ffmpeg-' + process.platform + '-' + process.arch + '.gz'
  const res = await fetch(url)
  if (!res.ok) throw new Error('ffmpeg download failed: http ' + res.status + ' (' + process.platform + '/' + process.arch + ')')
  fs.writeFileSync(local, zlib.gunzipSync(Buffer.from(await res.arrayBuffer())))
  if (process.platform !== 'win32') fs.chmodSync(local, 0o755)
  if (!works(local)) throw new Error('downloaded ffmpeg for ' + process.arch + ' will not run either')
  return (ffmpegResolved = local)
}

/* WhatsApp-friendly re-encode: 640px wide, H.264 crf 28, AAC 96k, faststart. Returns the size. */
async function compressVideo(jobId, ffmpegPath, raw, out) {
  ytJobSet(jobId, { status: 'compressing', percent: 100 })
  await new Promise((resolve, reject) => {
    const p = spawn(ffmpegPath, ['-y', '-i', raw,
      '-vf', "scale='min(640,iw)':-2", '-c:v', 'libx264', '-crf', '28', '-preset', 'veryfast',
      '-c:a', 'aac', '-b:a', '96k', '-movflags', '+faststart', out])
    p.on('close', c => c === 0 ? resolve() : reject(new Error('ffmpeg exited ' + c)))
    p.on('error', e => reject(new Error('ffmpeg spawn failed on ' + process.arch + ' (' + ffmpegPath + '): ' + e.message)))
  })
  const size = fs.statSync(out).size
  if (size > 50 * 1024 * 1024) throw new Error('still over 50MB after compression (' + Math.round(size / 1e6) + 'MB) - video too long')
  return size
}

/* An uploaded video file: compress the same way and keep it as an upload (media://up_...). */
async function prepareUploadedVideo(jobId, rawPath) {
  const ffmpegPath = await ffmpegBin()
  const out = path.join(MEDIA_DIR, 'vid-' + Date.now() + '.mp4')
  try {
    const size = await compressVideo(jobId, ffmpegPath, rawPath, out)
    const file = 'up_' + Date.now() + '_video.mp4'
    fs.renameSync(out, path.join(MEDIA_DIR, file))
    ytJobSet(jobId, { status: 'ready', media: 'media://' + file, bytes: size })
    console.log('uploaded video prepared:', Math.round(size / 1e6) + 'MB ->', file)
  } finally {
    fs.rmSync(rawPath, { force: true })
    fs.rmSync(out, { force: true })
  }
}

/* Download (yt-dlp, <=720p) and compress (ffmpeg, 640px, crf 28) a YouTube link.
   Returns the paths; the caller decides whether to send it now or keep it. */
async function ytPrepareFile(jobId, url) {
  const ffmpegPath = await ffmpegBin()
  ytJobSet(jobId, { status: 'preparing' })
  const bin = await ensureYtDlp()
  const stamp = Date.now()
  const raw = path.join(MEDIA_DIR, 'yt-' + stamp + '-raw.mp4')
  const out = path.join(MEDIA_DIR, 'yt-' + stamp + '.mp4')
  try {
    ytJobSet(jobId, { status: 'downloading' })
    let errOut = ''
    await new Promise((resolve, reject) => {
      const p = spawn(bin, ['-f', 'bv*[ext=mp4][height<=720]+ba[ext=m4a]/b[ext=mp4]/b',
        '--merge-output-format', 'mp4', '--ffmpeg-location', ffmpegPath,
        '--no-playlist', '--newline', '-o', raw, url])
      p.stdout.on('data', d => {
        const m = String(d).match(/\[download\]\s+([\d.]+)%/)
        if (m) ytJobSet(jobId, { percent: Math.round(parseFloat(m[1])) })
      })
      p.stderr.on('data', d => { errOut += d })
      p.on('close', c => c === 0 ? resolve() : reject(new Error('yt-dlp exited ' + c + ': ' + errOut.slice(-300))))
      p.on('error', reject)
    })
    const size = await compressVideo(jobId, ffmpegPath, raw, out)
    return { raw, out, size }
  } catch (e) {
    fs.rmSync(raw, { force: true })
    fs.rmSync(out, { force: true })
    throw e
  }
}

async function sendYoutubeVideo(jobId, jid, url, caption) {
  const { raw, out, size } = await ytPrepareFile(jobId, url)
  try {
    ytJobSet(jobId, { status: 'sending' })
    const result = await sock.sendMessage(jid, { video: { url: out }, caption: caption || '' })
    rememberApiSend(result.key.id)
    ytJobSet(jobId, { status: 'sent' })
    console.log('youtube video sent:', url, Math.round(size / 1e6) + 'MB')
  } finally {
    fs.rmSync(raw, { force: true })
    fs.rmSync(out, { force: true })
  }
}

/* Prepare once, send many: the compressed clip is kept as an upload (media://up_...)
   so a flow node can send it instantly without downloading again. */
async function prepareYoutubeVideo(jobId, url) {
  const { raw, out, size } = await ytPrepareFile(jobId, url)
  fs.rmSync(raw, { force: true })
  const file = 'up_' + Date.now() + '_youtube.mp4'
  fs.renameSync(out, path.join(MEDIA_DIR, file))
  ytJobSet(jobId, { status: 'ready', media: 'media://' + file, bytes: size })
  console.log('youtube video prepared:', url, Math.round(size / 1e6) + 'MB ->', file)
}

// GET /messages?after=<seq>&from=<number>&chat=<number|groupjid>&q=<text search>&limit=100
app.get('/messages', (req, res) => {
  const after = Number(req.query.after) || 0
  const limit = Math.min(Number(req.query.limit) || 100, 500)
  const where = ['seq > ?']
  const params = [after]
  if (req.query.from) { where.push('sender = ?'); params.push(String(req.query.from)) }
  if (req.query.chat) { where.push('chat = ?'); params.push(String(req.query.chat)) }
  if (req.query.q) { where.push("text LIKE '%' || ? || '%'"); params.push(String(req.query.q)) }
  const order = req.query.order === 'desc' ? 'DESC' : 'ASC'
  const rows = db.prepare(
    `SELECT m.*, COALESCE(NULLIF(ct.name, ''), NULLIF(m.name, ''), '') AS name
     FROM messages m LEFT JOIN contacts ct ON ct.jid = m.sender
     WHERE ` + where.join(' AND ') + ` ORDER BY timestamp ${order}, seq ${order} LIMIT ?`
  ).all(...params, limit)
  const list = rows.map(rowToMsg)
  res.json({ messages: list, cursor: list.length ? list[list.length - 1].seq : after })
})

// ---------- start ----------

// secrets are generated, not invented: first boot writes them to .env and
// prints them once so they can be pasted into the gkjewels flow settings page
function ensureSecret(name, current) {
  if (current) return current
  const value = crypto.randomBytes(32).toString('hex')
  setEnv(name, value)
  console.log(`Generated ${name} (saved to .env): ${value}`)
  return value
}

export function startServer() {
  API_KEY = ensureSecret('API_KEY', API_KEY)
  WEBHOOK_SECRET = ensureSecret('WEBHOOK_SECRET', WEBHOOK_SECRET)
  app.listen(PORT, () => console.log('API on http://localhost:' + PORT + '  (open /qr?key=... to link)'))
  startWhatsApp()
  // heartbeat: lets the receiver run timed flow steps (waits/timeouts) and keep
  // its learned bridge address fresh, without any cron on the PHP side
  setInterval(() => postWebhook('tick', { state: connectionState }), 30000)
}

// start when run directly or packaged with pkg; under Electron, main.cjs calls startServer() itself
if (process.pkg || (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)) startServer()
