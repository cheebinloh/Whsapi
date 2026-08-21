import assert from 'assert'
import crypto from 'crypto'
import { toJid, jidToNumber, extractText, messageType, signBody, parseAllowIps, ipAllowed, pollChoiceFromHashes, clampTyping, sanitizeUpName, resolveMediaRef } from './server.js'

assert.equal(toJid('60123456789'), '60123456789@s.whatsapp.net')
assert.equal(toJid('+60 12-345 6789'), '60123456789@s.whatsapp.net')
assert.equal(toJid('120363012345@g.us'), '120363012345@g.us')
assert.throws(() => toJid(''), /missing/)
assert.throws(() => toJid('abc'), /invalid/)

assert.equal(jidToNumber('60123456789@s.whatsapp.net'), '60123456789')
assert.equal(jidToNumber('60123456789:12@s.whatsapp.net'), '60123456789')
assert.equal(jidToNumber('12345@g.us'), '12345@g.us')

assert.equal(extractText({ conversation: 'hi' }), 'hi')
assert.equal(extractText({ extendedTextMessage: { text: 'yo' } }), 'yo')
assert.equal(extractText({ imageMessage: { caption: 'pic' } }), 'pic')
assert.equal(extractText(null), '')
assert.equal(
  extractText({ pollCreationMessageV3: { name: 'Which color?', options: [{ optionName: 'Gold' }, { optionName: 'Silver' }] } }),
  '📊 Which color?\n1. Gold\n2. Silver')
assert.equal(extractText({ pollCreationMessage: { name: 'Q', options: [] } }), '📊 Q')

assert.equal(messageType({ imageMessage: {} }), 'imageMessage')
assert.equal(messageType({ messageContextInfo: {}, conversation: 'x' }), 'conversation')

// webhook signature: standard HMAC-sha256 over the exact raw body, hex, prefixed
const body = JSON.stringify({ event: 'message', ts: 1754900000000, port: 3000, data: { text: '你好' } })
const expect = 'sha256=' + crypto.createHmac('sha256', 'secret1').update(body, 'utf8').digest('hex')
assert.equal(signBody(body, 'secret1'), expect)
assert.notEqual(signBody(body, 'secret2'), expect)               // different secret, different sig
assert.notEqual(signBody(body + ' ', 'secret1'), expect)         // any body change breaks the sig

// allowlist: empty = allow everyone (dev); localhost always passes;
// exact IPs and dot-terminated prefixes; express's ::ffff: v4 wrapper stripped
assert.equal(parseAllowIps(''), null)
assert.equal(ipAllowed('8.8.8.8', null), true)
const list = parseAllowIps('203.0.113.7, 192.168., 10.0.0.*')
assert.equal(ipAllowed('203.0.113.7', list), true)
assert.equal(ipAllowed('::ffff:203.0.113.7', list), true)
assert.equal(ipAllowed('203.0.113.8', list), false)
assert.equal(ipAllowed('192.168.1.55', list), true)
assert.equal(ipAllowed('10.0.0.9', list), true)
assert.equal(ipAllowed('10.0.1.9', list), false)
assert.equal(ipAllowed('127.0.0.1', list), true)                 // shop PC itself
assert.equal(ipAllowed('::1', list), true)
assert.equal(ipAllowed('', list), false)                         // unknown source is not "local"
// a prefix must not match mid-octet: "192.168." !=> "192.1688..."
assert.equal(ipAllowed('192.1688.0.1', parseAllowIps('192.168.')), false)

// poll votes decrypt to sha256(option) digests; map back to the 1-based number
const sha = t => crypto.createHash('sha256').update(t).digest('hex')
assert.equal(pollChoiceFromHashes([sha('View cart 查看购物车')], ['Ask price', 'View cart 查看购物车']), 2)
assert.equal(pollChoiceFromHashes([sha('Ask price')], ['Ask price', 'View cart']), 1)
assert.equal(pollChoiceFromHashes([sha('Ask price').toUpperCase()], ['Ask price', 'View cart']), 1) // case-proof
assert.equal(pollChoiceFromHashes([sha('not an option')], ['A', 'B']), null)
assert.equal(pollChoiceFromHashes([], ['A', 'B']), null)          // vote retracted
assert.equal(pollChoiceFromHashes(null, ['A', 'B']), null)

// typing indicator duration: whole seconds, 0-15, junk = off
assert.equal(clampTyping(3), 3)
assert.equal(clampTyping(99), 15)
assert.equal(clampTyping(-2), 0)
assert.equal(clampTyping('abc'), 0)
assert.equal(clampTyping(2.6), 3)

// upload names lose their path; media refs cannot escape the media folder
assert.equal(sanitizeUpName('promo video.MP4'), 'promo_video.MP4')
assert.equal(sanitizeUpName('..' + String.fromCharCode(92) + 'evil/..' + String.fromCharCode(92) + 'x.jpg'), 'x.jpg')
assert.equal(sanitizeUpName('...jpg'), 'jpg')
assert.equal(resolveMediaRef('media://up_1_x.jpg'), 'up_1_x.jpg')
assert.equal(resolveMediaRef('media://../auth/creds.json'), null)
assert.equal(resolveMediaRef('media://a/b.jpg'), null)
assert.equal(resolveMediaRef('https://x.com/a.jpg'), null)

console.log('all tests passed')
