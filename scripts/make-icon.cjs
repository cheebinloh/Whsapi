// generates build/icon.png (512x512, macOS icns needs >=512): green rounded square with a white thunder bolt — zero dependencies
const zlib = require('zlib')
const fs = require('fs')
const S = 512

// rounded-square test
const R = 108, PAD = 16
function inRoundedRect(x, y) {
  if (x < PAD || x > S - PAD || y < PAD || y > S - PAD) return false
  const cx = Math.min(Math.max(x, PAD + R), S - PAD - R)
  const cy = Math.min(Math.max(y, PAD + R), S - PAD - R)
  const dx = x - cx, dy = y - cy
  return dx * dx + dy * dy <= R * R
}

// thunder bolt polygon (classic zig-zag), ray casting test
const BOLT = [[300, 52], [132, 296], [240, 296], [216, 460], [388, 216], [272, 216]]
function inBolt(x, y) {
  let inside = false
  for (let i = 0, j = BOLT.length - 1; i < BOLT.length; j = i++) {
    const [xi, yi] = BOLT[i], [xj, yj] = BOLT[j]
    if ((yi > y) !== (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi) + xi) inside = !inside
  }
  return inside
}

const rows = []
for (let y = 0; y < S; y++) {
  const row = Buffer.alloc(1 + S * 4)
  for (let x = 0; x < S; x++) {
    const o = 1 + x * 4
    if (inBolt(x, y)) { row[o] = 0xFF; row[o + 1] = 0xFF; row[o + 2] = 0xFF; row[o + 3] = 255 }
    else if (inRoundedRect(x, y)) { row[o] = 0x00; row[o + 1] = 0xA8; row[o + 2] = 0x84; row[o + 3] = 255 }
  }
  rows.push(row)
}

function crc32(buf) {
  let table = crc32.t
  if (!table) {
    table = crc32.t = []
    for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; table[n] = c }
  }
  let crc = 0xFFFFFFFF
  for (const b of buf) crc = table[(crc ^ b) & 0xFF] ^ (crc >>> 8)
  return (crc ^ 0xFFFFFFFF) >>> 0
}
function chunk(type, data) {
  const t = Buffer.from(type)
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length)
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(Buffer.concat([t, data])))
  return Buffer.concat([len, t, data, crc])
}

const ihdr = Buffer.alloc(13)
ihdr.writeUInt32BE(S, 0); ihdr.writeUInt32BE(S, 4)
ihdr[8] = 8; ihdr[9] = 6

fs.mkdirSync('build', { recursive: true })
fs.writeFileSync('build/icon.png', Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
  chunk('IHDR', ihdr),
  chunk('IDAT', zlib.deflateSync(Buffer.concat(rows))),
  chunk('IEND', Buffer.alloc(0))
]))
console.log('build/icon.png written')
