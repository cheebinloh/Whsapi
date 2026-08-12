const { app, BrowserWindow, Tray, Menu, nativeImage } = require('electron')
const path = require('path')
const fs = require('fs')
const crypto = require('crypto')
const { pathToFileURL } = require('url')

// single instance: if already running, tell the running copy to show its window, then exit
if (!app.requestSingleInstanceLock()) {
  app.quit()
} else {
  startApp()
}

function startApp() {
  // all data (session, db, media, .env) lives in the per-user app data folder
  const dataDir = app.getPath('userData')
  process.env.WA_BASE_DIR = dataDir
  const envFile = path.join(dataDir, '.env')
  fs.mkdirSync(dataDir, { recursive: true })
  // one-time migration from the old "WhatsApp API" app name
  const oldDir = path.join(dataDir, '..', 'WhatsApp API')
  if (!fs.existsSync(envFile) && fs.existsSync(path.join(oldDir, '.env'))) {
    for (const item of ['auth', 'avatars', 'media', 'messages.db', 'messages.db-wal', 'messages.db-shm', '.env']) {
      const src = path.join(oldDir, item)
      if (fs.existsSync(src)) fs.cpSync(src, path.join(dataDir, item), { recursive: true })
    }
  }
  if (!fs.existsSync(envFile)) {
    // seed from the installer's setup page if present, else sensible defaults
    const cfg = { PORT: '3210', KEEP_DAYS: '90', MEDIA_SYNC_DAYS: '30' }
    const cfgFile = path.join(dataDir, 'install.cfg')
    try {
      for (const line of fs.readFileSync(cfgFile, 'utf8').split(/\r\n|\r|\n/)) {
        const m = /^([A-Z_]+)=(.*)$/.exec(line.trim())
        if (m && m[2]) cfg[m[1]] = m[2]
      }
      fs.rmSync(cfgFile, { force: true })
    } catch { /* no installer config */ }
    fs.writeFileSync(envFile,
      'API_KEY=' + crypto.randomBytes(16).toString('hex') + '\n' +
      'PORT=' + cfg.PORT + '\n' +
      'KEEP_DAYS=' + cfg.KEEP_DAYS + '\n' +
      'MEDIA_SYNC_DAYS=' + cfg.MEDIA_SYNC_DAYS + '\n')
  }
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r\n|\r|\n/)) {
    const m = /^([A-Z_]+)=(.*)$/.exec(line.trim())
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2]
  }
  const KEY = process.env.API_KEY
  const PORT = process.env.PORT || 3210
  const ICON = path.join(__dirname, '..', 'build', 'icon.png')

  let win = null
  let tray = null

  function showWindow(hash = '') {
    if (win && !win.isDestroyed()) {
      if (hash) win.loadURL(`http://localhost:${PORT}/?key=${KEY}${hash}`)
      if (win.isMinimized()) win.restore()
      win.show(); win.focus()
      return
    }
    win = new BrowserWindow({
      width: 1240, height: 840, minWidth: 700, minHeight: 500,
      title: 'WhatsApp Server', icon: ICON, autoHideMenuBar: true, show: false
    })
    win.loadURL(`http://localhost:${PORT}/?key=${KEY}${hash}`)
    win.once('ready-to-show', () => win.show())
    win.on('close', (e) => { // closing hides to tray; Quit lives in the tray menu
      if (!app.isQuiting) { e.preventDefault(); win.hide() }
    })
    win.on('closed', () => { win = null })
  }

  function apiPost(p) {
    return fetch(`http://localhost:${PORT}${p}`, { method: 'POST', headers: { 'X-API-Key': KEY } }).catch(() => {})
  }

  function buildTray() {
    tray = new Tray(nativeImage.createFromPath(ICON).resize({ width: 16, height: 16 }))
    tray.setToolTip('WhatsApp Server — click to open')
    const menu = Menu.buildFromTemplate([
      { label: 'Open WhatsApp Server', click: () => showWindow() },
      { type: 'separator' },
      { label: 'Settings', click: () => showWindow('#settings') },
      { label: 'Link device', click: () => showWindow('#link') },
      { label: 'API docs', click: () => showWindow('#docs') },
      { label: 'Sync data again', click: () => apiPost('/sync') },
      { type: 'separator' },
      {
        label: process.platform === 'darwin' ? 'Start at login' : 'Start with Windows', type: 'checkbox',
        checked: app.getLoginItemSettings().openAtLogin,
        click: (item) => app.setLoginItemSettings({ openAtLogin: item.checked })
      },
      { type: 'separator' },
      { label: 'Quit WhatsApp Server', click: () => { app.isQuiting = true; app.quit() } }
    ])
    tray.setContextMenu(menu)
    tray.on('click', () => showWindow())        // single left-click
    tray.on('double-click', () => showWindow())  // some Windows setups only fire double-click
  }

  // a second launch (double-clicking the shortcut) reopens the running window
  app.on('second-instance', () => showWindow())
  app.on('window-all-closed', (e) => e.preventDefault()) // keep running in the tray
  app.on('activate', () => showWindow())

  app.whenReady().then(async () => {
    try {
      const server = await import(pathToFileURL(path.join(__dirname, '..', 'server.js')).href)
      server.startServer()
    } catch (err) {
      require('electron').dialog.showErrorBox('WhatsApp Server failed to start', String(err.stack || err))
    }
    buildTray()
    showWindow()
  })
}
