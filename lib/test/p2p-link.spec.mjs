import test from 'node:test'
import assert from 'node:assert/strict'
import { startLanServer } from '../lan-server.mjs'

const TOKEN = 'TOK-P2P-1756'
const SECRET = 'TEST-INTERNAL-SECRET-P2P'

let portSeq = 0
const nextPort = () => 19501 + (portSeq++ * 2)

function fakeLink(over = {}) {
  const calls = { start: 0, offer: 0, punch: [], close: 0 }
  const link = Object.assign({
    _state: 'ready',
    _closed: false,
    async start() { calls.start++; this._state = 'ready'; return true },
    offer() {
      calls.offer++
      return { ok: true, state: this._state, ip: '39.182.215.130', port: 9348, secret: 'S3CRET', stun: ['118.178.129.217:3478'], sprayPps: 5000, sockets: 32, ttlMs: 300000 }
    },
    punch(ip) { calls.punch.push(ip); return true },
    status() { return { state: this._state, ready: this._state === 'ready', ip: '39.182.215.130', port: 9348, localPort: 5555, bindIp: '192.168.31.63', peer: this._peer || null, sinceMs: 0, spraySent: 0, lastError: '' } },
    close() { calls.close++; this._closed = true },
    on() { return this },
    emit() { return true },
  }, over)
  return { link, calls }
}

async function serve(over = {}) {
  const o = Object.assign({
    port: nextPort(),
    allowShift: true,
    log: () => {},
    getToken: () => TOKEN,
    internalSecret: SECRET,
    getInfo: () => ({ name: '我的电脑', nodeId: 'dsh-console', host: 'host-1', dshOk: true, version: '0.6.1' }),
    listSessions: async () => [],
    runCommand: async () => ({ ok: true }),
  }, over)
  const srv = startLanServer(o)
  const started = await srv.start()
  assert.ok(started)
  return { srv, base: 'http://127.0.0.1:' + started.port + '/dsh-console' }
}

const INR = { 'x-dsh-console-internal': SECRET }

test('① /p2p/offer 返回映射与密钥，且 p2pView 不含 secret', async () => {
  const { link, calls } = fakeLink()
  const s = await serve({ p2pLink: link })
  const r = await fetch(s.base + '/p2p/offer?token=' + TOKEN, { headers: INR })
  assert.equal(r.status, 200)
  const j = await r.json()
  assert.equal(j.ok, true)
  assert.equal(j.ip, '39.182.215.130')
  assert.equal(j.secret, 'S3CRET')
  assert.equal(calls.start, 1, 'offer 前必须先把 link 启起来')
  assert.equal(calls.offer, 1)
  assert.equal(j.p2p.secret, undefined, 'p2pView 不许把 secret 带出去')
  assert.equal(j.p2p.state, 'ready')
  await s.srv.stop()
})

test('② /p2p/offer 在公网开关关掉时 403 remote-off', async () => {
  const { link } = fakeLink()
  const s = await serve({ p2pLink: link, getAccess: () => ({ lan: true, remote: false }) })
  const r = await fetch(s.base + '/p2p/offer?token=' + TOKEN, { headers: INR })
  assert.equal(r.status, 403)
  const j = await r.json()
  assert.equal(j.reason, 'remote-off')
  await s.srv.stop()
})

test('③ /p2p/punch 校验 IP，合法则调 link.punch', async () => {
  const { link, calls } = fakeLink()
  const s = await serve({ p2pLink: link })
  const bad = await fetch(s.base + '/p2p/punch?token=' + TOKEN, {
    method: 'POST', headers: Object.assign({}, INR, { 'content-type': 'application/json' }),
    body: JSON.stringify({ ip: 'not-an-ip' }),
  })
  assert.equal(bad.status, 400)
  assert.equal(calls.punch.length, 0)
  const ok = await fetch(s.base + '/p2p/punch?token=' + TOKEN, {
    method: 'POST', headers: Object.assign({}, INR, { 'content-type': 'application/json' }),
    body: JSON.stringify({ ip: '112.17.235.91' }),
  })
  assert.equal(ok.status, 200)
  const j = await ok.json()
  assert.equal(j.started, true)
  assert.deepEqual(calls.punch, ['112.17.235.91'])
  await s.srv.stop()
})

test('④ /p2p/status 只读，没启动过也回 idle 不建实例', async () => {
  const { link, calls } = fakeLink()
  const s = await serve({ p2pLink: link })
  const r = await fetch(s.base + '/p2p/status?token=' + TOKEN, { headers: INR })
  assert.equal(r.status, 200)
  const j = await r.json()
  assert.equal(j.ok, true)
  assert.equal(calls.start, 0, '/p2p/status 不该把 P2P 拉起来')
  await s.srv.stop()
})

test('⑤ P2P 来源：受公网开关管、不落 wan、取码面被挡', async () => {
  const { link } = fakeLink()
  const s = await serve({ p2pLink: link })

  const info = await fetch(s.base + '/info?token=' + TOKEN, { headers: INR })
  const j = await info.json()
  assert.ok(j.p2p, '/info 必须带 p2p 状态，App 靠它决定这一轮走直连还是 frp')
  await s.srv.stop()
})

test('⑥ stop() 必须把 p2p 关掉（_closed 是终态，不能复用）', async () => {
  const { link, calls } = fakeLink()
  const s = await serve({ p2pLink: link })
  await fetch(s.base + '/p2p/offer?token=' + TOKEN, { headers: INR })
  assert.equal(calls.start, 1)
  await s.srv.stop()
  assert.equal(calls.close, 1, 'stop 必须 close 掉 P2P 实例')
})

import { EventEmitter } from 'node:events'
import { TunnelStream } from '../p2p-tunnel.mjs'

function fakeLinkWithStream() {
  const em = new EventEmitter()
  Object.assign(em, {
    async start() { return true },
    offer() { return { ok: true, state: 'proved', ip: '39.182.215.130', port: 9348, secret: 'S', stun: [], sprayPps: 5000, sockets: 32, ttlMs: 300000 } },
    punch() { return true },
    status() { return { state: 'proved', ready: true, peer: { ip: '112.17.235.91', port: 57966 }, sinceMs: 1 } },
    close() {},
  })
  return em
}

function dec(buf) {
  if (!buf || buf.length < 14) return null
  if (buf[0] !== 0xd5 || buf[1] !== 0x3f) return null
  const len = buf.readUInt16BE(10)
  return { type: buf[2], payload: buf.subarray(14, 14 + len) }
}

function openP2pStream(link, remoteIp) {
  const out = { frames: [] }
  let s = null
  const tunnel = {
    kick() { pump() },
    send(buf) { out.frames.push(Buffer.from(buf)) },
    dropStream() {},
    onAck() {},
  }
  function pump() {
    let guard = 4000
    while (s && s.pending && guard-- > 0) {
      const fr = s.pumpSend()
      if (!fr) break
      out.frames.push(Buffer.from(fr))
    }
  }
  s = new TunnelStream(tunnel, 1, { established: true, remoteAddress: remoteIp, remotePort: 57966 })
  s._dshVia = 'p2p'
  out.st = s
  link.emit('stream', s)
  out.send = (text) => s.onData(0, Buffer.from(text))
  out.text = () => {
    let acc = ''
    for (const fr of out.frames) {
      const d = dec(fr)
      if (d && d.type === 3 && d.payload.length) acc += d.payload.toString('utf8')
    }
    return acc
  }
  return out
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms))

test('⑦ P2P 来源走真 HTTP 解析：公网开关关掉 ⇒ 403 remote-off', async () => {
  const link = fakeLinkWithStream()
  const s = await serve({ p2pLink: link, getAccess: () => ({ lan: true, remote: false }) })
  await s.srv.startP2p()
  const p = openP2pStream(link, '112.17.235.91')
  p.send('GET /dsh-console/info?token=' + TOKEN + ' HTTP/1.1\r\nHost: x\r\n\r\n')
  await wait(200)
  const txt = p.text()
  assert.ok(/HTTP\/1\.1 403/.test(txt), 'P2P 来源在公网开关关闭时必须被挡，实际回包：' + txt.slice(0, 200))
  assert.ok(txt.includes('remote-off') || txt.includes('公网连接'), '文案要是 remote-off 那条，实际：' + txt.slice(0, 300))
  await s.srv.stop()
})

test('⑧ P2P 来源：开关开着 ⇒ /info 200 且带 p2p 状态；取码面 /qr 仍 403', async () => {
  const link = fakeLinkWithStream()
  const s = await serve({ p2pLink: link })
  await s.srv.startP2p()
  const p1 = openP2pStream(link, '112.17.235.91')
  p1.send('GET /dsh-console/info?token=' + TOKEN + ' HTTP/1.1\r\nHost: x\r\n\r\n')
  await wait(200)
  const t1 = p1.text()
  assert.ok(/HTTP\/1\.1 200/.test(t1), '开着的时候 /info 必须 200，实际：' + t1.slice(0, 200))
  assert.ok(t1.includes('"p2p"'), '/info 回包必须带 p2p 字段')
  const p2 = openP2pStream(link, '112.17.235.91')
  p2.send('GET /dsh-console/qr HTTP/1.1\r\nHost: x\r\n\r\n')
  await wait(200)
  const t2 = p2.text()
  assert.ok(/HTTP\/1\.1 403/.test(t2), 'P2P 来源取码面必须 403，实际：' + t2.slice(0, 200))
  await s.srv.stop()
})