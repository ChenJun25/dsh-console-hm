
import dgram from 'node:dgram'
import crypto from 'node:crypto'
import { EventEmitter } from 'node:events'
import {
  buildStun, parseStun, verifyStunIntegrity, pickBindIp, resolveHost,
  surveySocket, Tunnel
} from './p2p-tunnel.mjs'

const DEFAULT_STUN = [
  '118.178.129.217:3478',
  'stun.miwifi.com:3478',
  'stun.chat.bilibili.com:3478',
  'stun.cloudflare.com:3478'
]

const SPRAY_PPS = 5000
const SPRAY_MAX_MS = 25000
const PROVE_TTL_MS = 5 * 60 * 1000

export class P2pLink extends EventEmitter {
  constructor(opts = {}) {
    super()
    this.log = typeof opts.log === 'function' ? opts.log : () => {}
    this.stunList = Array.isArray(opts.stunList) && opts.stunList.length ? opts.stunList.slice() : DEFAULT_STUN.slice()
    this.secret = opts.secret || crypto.randomBytes(32).toString('hex')
    this.sock = null
    this.mapped = null
    this.localPort = 0
    this.bindIp = ''
    this.state = 'idle'
    this.peer = null
    this.tunnel = null
    this.provedAt = 0
    this.lastError = ''
    this.sprayTimer = null
    this.sprayStats = { sent: 0, hitAt: 0 }
    this._closed = false
    this.stats = { punchIn: 0, punchOut: 0, offerCount: 0 }
  }

  async start() {
    if (this.sock || this._closed) return this
    this.state = 'surveying'
    this.bindIp = pickBindIp()
    const sock = dgram.createSocket('udp4')
    this.sock = sock
    sock.on('message', (msg, rinfo) => this.onPacket(msg, rinfo))
    sock.on('error', (e) => {
      this.lastError = 'socket: ' + ((e && e.message) || e)
      this.log('[p2p] socket 错误: ' + this.lastError)
    })
    await new Promise((resolve) => sock.bind({ address: this.bindIp, port: 0 }, resolve))
    this.localPort = sock.address().port
    const s = await surveySocket(sock, this.stunList, { timeoutMs: 1200, totalMs: 4000 })
    const good = (s.obs || []).filter((o) => o.port)
    if (!good.length) {
      this.state = 'failed'
      this.lastError = 'STUN 无应答'
      this.log('[p2p] STUN 观测失败（' + this.stunList.join(',') + '）')
      return this
    }

    const tally = new Map()
    for (const o of good) {
      const k = o.ip + ':' + o.port
      tally.set(k, (tally.get(k) || 0) + 1)
    }
    let best = null
    for (const [k, n] of tally) if (!best || n > best.n) best = { k, n }
    const [ip, port] = best.k.split(':')
    this.mapped = { ip, port: Number(port) }
    this.state = 'ready'
    this.log('[p2p] 就绪 bind=' + this.bindIp + ':' + this.localPort +
      ' mapped=' + this.mapped.ip + ':' + this.mapped.port +
      ' obs=' + good.map((o) => o.port).join('/'))
    return this
  }

  offer() {
    this.stats.offerCount++
    if (!this.mapped) {
      return { ok: false, error: this.state === 'surveying' ? '还没观测完，稍后再试' : (this.lastError || 'P2P 未就绪'), state: this.state }
    }
    return {
      ok: true,
      state: this.state,
      ip: this.mapped.ip,
      port: this.mapped.port,
      secret: this.secret,
      stun: this.stunList,
      sprayPps: SPRAY_PPS,
      sockets: 32,
      ttlMs: PROVE_TTL_MS
    }
  }

  punch(phoneIp) {
    if (!this.sock || !this.mapped) return false
    if (!phoneIp || phoneIp === '0.0.0.0') return false
    if (this.state === 'proved' && this.peer) return true
    this.stopSpray()
    this.state = 'punching'
    this.sprayStats = { sent: 0, hitAt: 0 }
    const started = Date.now()

    const ports = []
    for (let p = 1024; p <= 65535; p++) ports.push(p)
    for (let i = ports.length - 1; i > 0; i--) {
      const j = (Math.random() * (i + 1)) | 0
      const t = ports[i]; ports[i] = ports[j]; ports[j] = t
    }
    let idx = 0
    const batch = Math.max(8, Math.round(SPRAY_PPS / 100))
    const msg = buildStun(0x0001, [], { integrityKey: this.secret, fingerprint: true })
    const tick = () => {
      if (this._closed || this.state === 'proved') { this.stopSpray(); return }
      if (Date.now() - started > SPRAY_MAX_MS) {
        this.state = this.state === 'proved' ? 'proved' : 'failed'
        this.lastError = this.lastError || '扫射超时未命中'
        this.log('[p2p] 扫射超时 sent=' + this.sprayStats.sent + ' 未命中')
        this.stopSpray()
        this.emit('punch-failed')
        return
      }
      for (let i = 0; i < batch && idx < ports.length; i++, idx++) {
        try {
          this.sock.send(msg.buf, ports[idx], phoneIp)
          this.sprayStats.sent++
          this.stats.punchOut++
        } catch (e) { }
      }
      if (idx >= ports.length) { idx = 0; }
      this.sprayTimer = setTimeout(tick, 10)
    }
    this.log('[p2p] 开始扫射 ' + phoneIp + ' 端口 1024-65535 @' + SPRAY_PPS + 'pps')
    tick()
    return true
  }

  stopSpray() {
    if (this.sprayTimer) { clearTimeout(this.sprayTimer); this.sprayTimer = null }
  }

  onPacket(msg, rinfo) {
    if (this._closed) return
    let p = null
    try { p = parseStun(msg) } catch (e) { p = null }
    if (!p) return

    if (p.type === 0x0001) {
      if (!p.hasIntegrity) return
      let ok = false
      try { ok = verifyStunIntegrity(p, this.secret) } catch (e) { ok = false }
      if (!ok) return
      this.stats.punchIn++
      const resp = buildStun(0x0101, [
        stunAttr(0x0020, xorAddrBuf(rinfo.address, rinfo.port))
      ], { integrityKey: this.secret, fingerprint: true, txid: p.txid })
      try { this.sock.send(resp.buf, rinfo.port, rinfo.address) } catch (e) { }
      this.prove(rinfo.address, rinfo.port, 'peer-request')
      return
    }

    if (p.type === 0x0101) {
      if (!p.hasIntegrity) return
      let ok = false
      try { ok = verifyStunIntegrity(p, this.secret) } catch (e) { ok = false }
      if (!ok) return
      this.prove(rinfo.address, rinfo.port, 'spray-reply')
      return
    }
  }

  prove(ip, port, by) {
    if (this.state === 'proved' && this.peer && this.peer.ip === ip && this.peer.port === port) return
    this.stopSpray()
    this.peer = { ip, port }
    this.provedAt = Date.now()
    this.state = 'proved'
    this.sprayStats.hitAt = this.sprayStats.sent
    this.log('[p2p] ★ 打通 by=' + by + ' peer=' + ip + ':' + port + ' 扫射包=' + this.sprayStats.sent)

    if (this.tunnel) { try { this.tunnel.close() } catch (e) { } }
    const t = new Tunnel({
      secret: this.secret,
      isClient: false,
      log: (m) => this.log('[p2p-tunnel] ' + m)
    })
    t.onStream = (st) => {
      st._dshVia = 'p2p'
      this.emit('stream', st)
    }
    t.attach(this.sock, this.peer)
    this.tunnel = t
    this.emit('proved', { ip, port, by })
  }

  status() {
    const now = Date.now()
    const fresh = this.state === 'proved' && this.peer && (now - this.provedAt) < PROVE_TTL_MS
    return {
      state: fresh ? 'proved' : this.state,
      ready: this.state === 'ready' || this.state === 'proved',
      ip: this.mapped ? this.mapped.ip : '',
      port: this.mapped ? this.mapped.port : 0,
      localPort: this.localPort,
      bindIp: this.bindIp,
      peer: fresh ? this.peer : null,
      sinceMs: fresh ? now - this.provedAt : 0,
      spraySent: this.sprayStats.sent,
      lastError: this.lastError,
      stats: this.tunnel ? this.tunnel.stats : null
    }
  }

  close() {
    this._closed = true
    this.stopSpray()
    if (this.tunnel) { try { this.tunnel.close() } catch (e) { } this.tunnel = null }
    if (this.sock) { try { this.sock.close() } catch (e) { } this.sock = null }
    this.state = 'closed'
    this.emit('close')
  }
}

function xorAddrBuf(ip, port) {
  const MAGIC = 0x2112A442
  const MAGIC_BUF = Buffer.from([0x21, 0x12, 0xA4, 0x42])
  const b = Buffer.alloc(8)
  b.writeUInt16BE(0, 0)
  b.writeUInt16BE(port ^ (MAGIC >>> 16), 2)
  const ipb = Buffer.from(ip.split('.').map(Number))
  for (let i = 0; i < 4; i++) ipb[i] ^= MAGIC_BUF[i]
  ipb.copy(b, 4)
  return b
}

function stunAttr(type, value) {
  const pad = (4 - (value.length % 4)) % 4
  const head = Buffer.alloc(4)
  head.writeUInt16BE(type, 0)
  head.writeUInt16BE(value.length, 2)
  return Buffer.concat([head, value, Buffer.alloc(pad)])
}
