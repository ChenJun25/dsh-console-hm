
import dgram from 'node:dgram'
import os from 'node:os'
import dns from 'node:dns/promises'
import net from 'node:net'
import crypto from 'node:crypto'
import { Duplex } from 'node:stream'
import { EventEmitter } from 'node:events'

const MAGIC = 0x2112A442
const MAGIC_BUF = Buffer.from([0x21, 0x12, 0xA4, 0x42])
const FP_XOR = 0x5354554e

function pad4(n) { return (4 - (n % 4)) % 4 }

function stunAttr(type, value) {
  const head = Buffer.alloc(4)
  head.writeUInt16BE(type, 0)
  head.writeUInt16BE(value.length, 2)
  return Buffer.concat([head, value, Buffer.alloc(pad4(value.length))])
}

function xorAddr(ip, port) {
  const b = Buffer.alloc(8)
  b.writeUInt16BE(0, 0)
  b.writeUInt16BE(port ^ (MAGIC >>> 16), 2)
  const ipb = Buffer.from(ip.split('.').map(Number))
  for (let i = 0; i < 4; i++) ipb[i] ^= MAGIC_BUF[i]
  ipb.copy(b, 4)
  return b
}

const CRC_TABLE = (() => {
  const t = new Uint32Array(256)
  for (let i = 0; i < 256; i++) {
    let c = i
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1)
    t[i] = c >>> 0
  }
  return t
})()

function crc32(buf) {
  let c = 0xFFFFFFFF
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8)
  return (c ^ 0xFFFFFFFF) >>> 0
}

export function buildStun(type, attrs, opts = {}) {
  const txid = opts.txid || crypto.randomBytes(12)
  const body = Buffer.concat(attrs)
  const hasIntegrity = opts.integrityKey != null
  const hdr = Buffer.alloc(20)
  hdr.writeUInt16BE(type, 0)
  hdr.writeUInt16BE(body.length + (hasIntegrity ? 24 : 0), 2)
  MAGIC_BUF.copy(hdr, 4)
  txid.copy(hdr, 8)
  let msg = Buffer.concat([hdr, body])
  if (hasIntegrity) {
    const key = Buffer.isBuffer(opts.integrityKey) ? opts.integrityKey : Buffer.from(opts.integrityKey, 'utf8')
    const hmac = crypto.createHmac('sha1', key).update(msg).digest()
    msg = Buffer.concat([msg, stunAttr(0x0008, hmac)])
  }
  if (opts.fingerprint) {
    const total = msg.length + 8 - 20
    const withLen = Buffer.from(msg)
    withLen.writeUInt16BE(total, 2)
    const fb = Buffer.alloc(4)
    fb.writeUInt32BE((crc32(withLen) ^ FP_XOR) >>> 0, 0)
    msg = Buffer.concat([withLen, stunAttr(0x8028, fb)])
  }
  return { buf: msg, txid }
}

export function parseStun(buf) {
  if (buf.length < 20) return null
  const type = buf.readUInt16BE(0)
  const len = buf.readUInt16BE(2)
  if (buf.readUInt32BE(4) !== MAGIC) return null
  const txid = buf.subarray(8, 20)
  const end = Math.min(buf.length, 20 + len)
  const attrs = []
  let off = 20
  while (off + 4 <= end) {
    const t = buf.readUInt16BE(off)
    const l = buf.readUInt16BE(off + 2)
    const vStart = off + 4
    const vEnd = vStart + l
    if (vEnd > end) break
    attrs.push({ type: t, value: buf.subarray(vStart, vEnd), offset: off })
    off = vEnd + pad4(l)
  }
  const get = (t) => attrs.find((a) => a.type === t)
  const out = { type, txid, attrs, raw: buf, hasIntegrity: !!get(0x0008) }
  const xma = get(0x0020)
  if (xma && xma.value.length >= 8) {
    const v = xma.value
    const port = v.readUInt16BE(2) ^ (MAGIC >>> 16)
    const ipb = Buffer.from(v.subarray(4, 8))
    for (let i = 0; i < 4; i++) ipb[i] ^= MAGIC_BUF[i]
    out.xorMapped = { ip: Array.from(ipb).join('.'), port }
  }
  const ma = get(0x0001)
  if (ma && ma.value.length >= 8) {
    out.mapped = { ip: Array.from(ma.value.subarray(4, 8)).join('.'), port: ma.value.readUInt16BE(2) }
  }
  return out
}

export function verifyStunIntegrity(parsed, key) {
  const a = parsed.attrs.find((x) => x.type === 0x0008)
  if (!a) return false
  const k = Buffer.isBuffer(key) ? key : Buffer.from(key, 'utf8')
  const head = Buffer.from(parsed.raw.subarray(0, a.offset))
  head.writeUInt16BE(a.offset - 20 + 24, 2)
  const hmac = crypto.createHmac('sha1', k).update(head).digest()
  return crypto.timingSafeEqual(hmac, Buffer.from(a.value))
}

export function pickBindIp() {
  const env = process.env.DSH_BIND_IP
  if (env) return env
  const cands = []
  for (const [name, list] of Object.entries(os.networkInterfaces())) {
    if (/^(tun|tap|utun|wg|vEthernet|Loopback|sing)/i.test(name)) continue
    for (const a of list || []) {
      if (a.family !== 'IPv4' && a.family !== 4) continue
      if (a.internal) continue
      cands.push({ name, address: a.address })
    }
  }
  const score = (o) => (/^192\.168\./.test(o.address) ? 0 : /^10\./.test(o.address) ? 1 : /^172\.(1[6-9]|2\d|3[01])\./.test(o.address) ? 2 : 3)
  cands.sort((x, y) => score(x) - score(y))
  return cands.length ? cands[0].address : '0.0.0.0'
}

export async function resolveHost(hostPort, timeoutMs = 1500) {
  const idx = hostPort.lastIndexOf(':')
  const host = hostPort.slice(0, idx)
  const port = Number(hostPort.slice(idx + 1))
  if (net.isIP(host)) return { ip: host, port }
  try {
    const ips = await dns.resolve4(host)
    if (!ips.length) return null
    return { ip: ips[0], port }
  } catch (e) {
    return null
  }
}

function bindingQuery(sock, ip, port, timeoutMs = 1200) {
  const { buf, txid } = buildStun(0x0001, [])
  return new Promise((resolve) => {
    let done = false
    const finish = (r) => {
      if (done) return
      done = true
      clearTimeout(timer)
      sock.off('message', onMsg)
      resolve(r)
    }
    const onMsg = (msg, rinfo) => {
      if (rinfo.address !== ip || rinfo.port !== port) return
      if (!msg.subarray(8, 20).equals(txid)) return
      const p = parseStun(msg)
      if (!p) return
      finish({ ok: true, xorMapped: p.xorMapped, mapped: p.mapped })
    }
    const timer = setTimeout(() => finish({ ok: false, err: 'timeout' }), timeoutMs)
    sock.on('message', onMsg)
    try {
      sock.send(buf, port, ip, (e) => { if (e) finish({ ok: false, err: e.message }) })
    } catch (e) {
      finish({ ok: false, err: e.message })
    }
  })
}

export async function surveySocket(sock, stunList, { timeoutMs = 1200, totalMs = 3000 } = {}) {
  const obs = []
  const started = Date.now()
  for (const hp of stunList) {
    if (Date.now() - started > totalMs) break
    const r = await resolveHost(hp)
    if (!r) { obs.push({ server: hp, err: 'resolve' }); continue }
    const q = await bindingQuery(sock, r.ip, r.port, timeoutMs)
    if (!q.ok) { obs.push({ server: hp, err: q.err }); continue }
    const m = q.xorMapped || q.mapped
    if (!m) { obs.push({ server: hp, err: 'no-mapped' }); continue }
    obs.push({ server: hp, ip: m.ip, port: m.port })
  }
  const good = obs.filter((o) => o.port)
  let step = null
  let stable = false
  let predicted = null
  if (good.length >= 3) {
    const sameIp = good.every((o) => o.ip === good[0].ip)
    const ports = good.slice(0, 3).map((o) => o.port)
    const d1 = ports[1] - ports[0]
    const d2 = ports[2] - ports[1]
    if (sameIp && d1 > 0 && d1 === d2 && d1 <= 16) {
      step = d1
      predicted = { address: good[2].ip, port: ports[2], step }
    } else if (sameIp && d1 === 0 && d2 === 0) {
      stable = true
      predicted = { address: good[2].ip, port: ports[2], step: 0 }
    }
  }
  return { obs, step, stable, predicted }
}

export const T = { SYN: 1, SYNACK: 2, DATA: 3, ACK: 4, FIN: 5, PING: 6, PONG: 7, RST: 8 }

const MAGIC0 = 0xd5
const MAGIC1 = 0x3f
const HDR = 14
const MAX_PAYLOAD = 1100
const RCV_WINDOW = 512

const CRYPT_FLAG = 0x01
const CRYPT_LABEL_C2S = 'dsh.p2p.data.v1.c2s'
const CRYPT_LABEL_S2C = 'dsh.p2p.data.v1.s2c'
const GCM_TAG = 16
const GCM_NONCE = 12
const DIR_C2S = 1
const DIR_S2C = 2

function secretBytes(secret) {
  const s = String(secret || '')
  if (/^[0-9a-fA-F]{64}$/.test(s)) return Buffer.from(s, 'hex')
  return Buffer.from(s, 'utf8')
}

function deriveDataKey(secret, label) {
  return crypto.createHmac('sha256', secretBytes(secret)).update(label).digest()
}

function dataNonce(sid, seq, dir) {
  const n = Buffer.alloc(GCM_NONCE)
  n.writeUInt16BE(sid & 0xffff, 0)
  n.writeUInt32BE(seq >>> 0, 2)
  n.writeUInt8(dir, 6)
  return n
}

function sealData(key, sid, seq, dir, plain) {
  const c = crypto.createCipheriv('aes-256-gcm', key, dataNonce(sid, seq, dir))
  const ct = Buffer.concat([c.update(plain), c.final()])
  return Buffer.concat([ct, c.getAuthTag()])
}

function openData(key, sid, seq, dir, sealed) {
  if (!sealed || sealed.length < GCM_TAG) return null
  const ct = sealed.subarray(0, sealed.length - GCM_TAG)
  const tag = sealed.subarray(sealed.length - GCM_TAG)
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', key, dataNonce(sid, seq, dir))
    d.setAuthTag(tag)
    return Buffer.concat([d.update(ct), d.final()])
  } catch (e) {
    return null
  }
}

function encFrame(type, sid, seq, payload, flags) {
  const body = payload || Buffer.alloc(0)
  const buf = Buffer.alloc(HDR + body.length)
  buf.writeUInt8(MAGIC0, 0)
  buf.writeUInt8(MAGIC1, 1)
  buf.writeUInt8(type, 2)
  buf.writeUInt8(flags || 0, 3)
  buf.writeUInt16BE(sid, 4)
  buf.writeUInt32BE(seq >>> 0, 6)
  buf.writeUInt16BE(body.length, 10)
  body.copy(buf, HDR)
  return buf
}

function decFrame(buf) {
  if (buf.length < HDR) return null
  if (buf.readUInt8(0) !== MAGIC0 || buf.readUInt8(1) !== MAGIC1) return null
  const type = buf.readUInt8(2)
  const sid = buf.readUInt16BE(4)
  const seq = buf.readUInt32BE(6)
  const flags = buf.readUInt8(3)
  const len = buf.readUInt16BE(10)
  if (HDR + len > buf.length) return null
  return { type, sid, seq, flags, payload: buf.subarray(HDR, HDR + len) }
}

export class TunnelStream extends Duplex {
  constructor(tunnel, sid, opts = {}) {
    super({ allowHalfOpen: true, highWaterMark: 256 * 1024 })
    this.tunnel = tunnel
    this.sid = sid
    this.sndNext = 0
    this.sndUna = 0
    this.sndBuf = new Map()
    this.rcvNext = 0
    this.rcvOoo = new Map()
    this.wq = []
    this.wqBytes = 0
    this.finQueued = false
    this.finSeq = -1
    this.gotFin = false
    this.closedByPeer = false
    this.lastAckAt = 0
    this.rcvSinceAck = 0
    this.established = !!opts.established
    this._closed = false

    this.remoteAddress = opts.remoteAddress || '0.0.0.0'
    this.remotePort = opts.remotePort || 0
    this.remoteFamily = 'IPv4'

    this.sendKey = opts.sendKey || null
    this.sendDir = opts.sendDir || 0
    this.recvKey = opts.recvKey || null
    this.recvDir = opts.recvDir || 0
    this.encrypted = !!this.sendKey
  }

  _read() {

  }

  _write(chunk, encoding, cb) {
    if (this._closed) return cb()
    this.wq.push(Buffer.from(chunk))
    this.wqBytes += chunk.length
    this.tunnel.kick()
    cb()
  }

  _final(cb) {
    this.finQueued = true
    this.tunnel.kick()
    cb()
  }

  setTimeout() { return this }
  setNoDelay() { return this }
  setKeepAlive() { return this }
  ref() { return this }
  unref() { return this }
  address() { return { address: '127.0.0.1', family: 'IPv4', port: 0 } }
  get bytesRead() { return 0 }
  get bytesWritten() { return 0 }

  destroySoon() { this.end() }

  _destroy(err, cb) {
    this._closed = true
    this.tunnel.dropStream(this.sid)
    cb(err)
  }

  onData(seq, payload) {
    if (seq === this.rcvNext) {
      this.rcvNext++
      if (payload.length) this.push(Buffer.from(payload))
      this.rcvSinceAck++
      while (this.rcvOoo.has(this.rcvNext)) {
        const p = this.rcvOoo.get(this.rcvNext)
        this.rcvOoo.delete(this.rcvNext)
        this.rcvNext++
        if (p.length) this.push(Buffer.from(p))
        this.rcvSinceAck++
      }
      this.maybeFinish()
    } else if (seq > this.rcvNext && seq < this.rcvNext + RCV_WINDOW) {
      this.rcvOoo.set(seq, payload)
    }
    this.maybeAck(true)
  }

  onFin(seq) {
    this.finSeq = seq
    this.maybeFinish()
    this.maybeAck(true)
  }

  maybeFinish() {
    if (this.finSeq < 0 || this.gotFin) return
    if (this.rcvNext > this.finSeq) {
      this.gotFin = true
      this.push(null)
    }
  }

  maybeAck(force) {
    const now = Date.now()
    if (!force && this.rcvSinceAck < 4 && now - this.lastAckAt < 6) return
    this.rcvSinceAck = 0
    this.lastAckAt = now
    const sack = Buffer.alloc(4)
    for (let i = 0; i < 32; i++) {
      if (this.rcvOoo.has(this.rcvNext + i)) sack[Math.floor(i / 8)] |= 1 << (i % 8)
    }
    this.tunnel.send(encFrame(T.ACK, this.sid, this.rcvNext, sack))
  }

  onAck(ack, sack) {
    let advanced = 0
    for (const [seq, rec] of this.sndBuf) {
      if (seq < ack) {
        this.sndBuf.delete(seq)
        advanced++
      }
    }
    if (sack && sack.length >= 4) {
      for (let i = 0; i < 32; i++) {
        if (sack[Math.floor(i / 8)] & (1 << (i % 8))) {
          const seq = ack + i
          if (this.sndBuf.has(seq)) {
            this.sndBuf.delete(seq)
            advanced++
          }
        }
      }
    }
    if (ack > this.sndUna) this.sndUna = ack
    this.tunnel.onAck(advanced)
  }

  pumpSend() {
    if (this._closed) return null
    if (this.wq.length) {
      const head = this.wq[0]
      const take = Math.min(MAX_PAYLOAD, head.length)
      const chunk = take === head.length ? this.wq.shift() : head.subarray(0, take)
      if (take !== head.length) this.wq[0] = head.subarray(take)
      this.wqBytes -= take
      const seq = this.sndNext++
      let buf
      if (this.sendKey) {
        buf = encFrame(T.DATA, this.sid, seq, sealData(this.sendKey, this.sid, seq, this.sendDir, chunk), CRYPT_FLAG)
      } else {
        buf = encFrame(T.DATA, this.sid, seq, chunk)
      }
      this.sndBuf.set(seq, { buf, at: Date.now(), tries: 0 })
      return buf
    }
    if (this.finQueued && this.finSeq < 0) {
      this.finSeq = this.sndNext++
      const buf = encFrame(T.FIN, this.sid, this.finSeq, null)
      this.sndBuf.set(this.finSeq, { buf, at: Date.now(), tries: 0 })
      return buf
    }
    return null
  }

  get pending() { return this.wq.length > 0 || (this.finQueued && this.finSeq < 0) }
  get unacked() { return this.sndBuf.size }
}

export class Tunnel extends EventEmitter {
  constructor(opts = {}) {
    super()
    this.secret = opts.secret || ''
    this.isClient = !!opts.isClient

    if (this.secret) {
      const c2s = deriveDataKey(this.secret, CRYPT_LABEL_C2S)
      const s2c = deriveDataKey(this.secret, CRYPT_LABEL_S2C)
      this.sendKey = this.isClient ? c2s : s2c
      this.recvKey = this.isClient ? s2c : c2s
      this.sendDir = this.isClient ? DIR_C2S : DIR_S2C
      this.recvDir = this.isClient ? DIR_S2C : DIR_C2S
    } else {
      this.sendKey = null
      this.recvKey = null
      this.sendDir = 0
      this.recvDir = 0
    }
    this.log = typeof opts.log === 'function' ? opts.log : () => {}
    this.onStream = typeof opts.onStream === 'function' ? opts.onStream : null
    this.sock = null
    this.peer = null
    this.streams = new Map()
    this.nextSid = this.isClient ? 1 : 2
    this.cwnd = 32
    this.minCwnd = 8
    this.maxCwnd = 384
    this.rto = 200
    this.inflight = 0
    this.closed = false
    this.lastRecvAt = 0
    this.stats = { sent: 0, recv: 0, retx: 0, framesOut: 0, framesIn: 0 }
    this._timers = []
  }

  attach(sock, peer) {
    this.sock = sock
    this.peer = peer

    if (this._onMsg && this._sockRef) {
      try { this._sockRef.removeListener('message', this._onMsg) } catch (e) { }
    }
    this._onMsg = (msg, rinfo) => this.onPacket(msg, rinfo)
    this._sockRef = sock
    sock.on('message', this._onMsg)
    const tick = setInterval(() => this.tick(), 4)
    const rtoTick = setInterval(() => this.checkRto(), 20)
    const pingTick = setInterval(() => this.sendPing(), 5000)
    this._timers.push(tick, rtoTick, pingTick)
    this.log('p2p tunnel attached peer=' + peer.ip + ':' + peer.port)
    return this
  }

  send(buf) {
    if (!this.sock || !this.peer) return
    try {
      this.sock.send(buf, this.peer.port, this.peer.ip)
      this.stats.sent += buf.length
      this.stats.framesOut++
    } catch (e) {              }
  }

  sendPing() {
    if (this.closed) return
    this.send(encFrame(T.PING, 0, 0, null))
  }

  kick() {

    this.tick()
  }

  tick() {
    if (this.closed || !this.sock) return
    let budget = 96
    while (this.inflight < this.cwnd && budget-- > 0) {
      let sentAny = false
      for (const st of this.streams.values()) {
        if (this.inflight >= this.cwnd) break
        if (!st.pending) continue
        const frame = st.pumpSend()
        if (!frame) continue
        this.send(frame)
        this.inflight++
        sentAny = true
      }
      if (!sentAny) break
    }
  }

  checkRto() {
    if (this.closed) return
    const now = Date.now()
    let lost = 0
    for (const st of this.streams.values()) {
      for (const [seq, rec] of st.sndBuf) {
        if (now - rec.at < this.rto) continue
        if (rec.tries >= 6) continue
        rec.tries++
        rec.at = now
        this.send(rec.buf)
        this.stats.retx++
        lost++
      }
    }
    if (lost > 0) {
      this.cwnd = Math.max(this.minCwnd, Math.floor(this.cwnd * 0.7))
      this.rto = Math.min(800, Math.floor(this.rto * 1.4))
    } else {
      this.rto = Math.max(120, Math.floor(this.rto * 0.98))
    }
  }

  onAck(n) {
    this.inflight = Math.max(0, this.inflight - n)
    if (n > 0) this.cwnd = Math.min(this.maxCwnd, this.cwnd + Math.max(1, Math.floor(n / 2)))
    this.tick()
  }

  onPacket(msg, rinfo) {
    if (this.closed) return
    const f = decFrame(msg)
    if (!f) return
    this.lastRecvAt = Date.now()
    this.stats.recv += msg.length
    this.stats.framesIn++
    if (f.type === T.PING) {
      this.send(encFrame(T.PONG, 0, 0, null))
      return
    }
    if (f.type === T.PONG) return
    if (f.type === T.ACK) {
      const st = this.streams.get(f.sid)
      if (st) st.onAck(f.seq, f.payload)
      return
    }
    if (f.type === T.DATA) {
      const st = this.streams.get(f.sid)
      if (!st) {

        return
      }
      let payload = f.payload
      if (st.recvKey) {

        if (!(f.flags & CRYPT_FLAG)) return
        payload = openData(st.recvKey, f.sid, f.seq, st.recvDir, f.payload)
        if (payload === null) return
      }
      st.onData(f.seq, payload)
      return
    }
    if (f.type === T.FIN) {
      const st = this.streams.get(f.sid)
      if (st) st.onFin(f.seq)
      return
    }
    if (f.type === T.SYN) {
      const sid = f.sid
      if (this.streams.has(sid)) {
        const st = this.streams.get(sid)
        this.send(encFrame(T.SYNACK, sid, 0, null))
        return
      }
      const st = this.newStream(sid, { established: true, remoteAddress: rinfo.address, remotePort: rinfo.port })
      this.send(encFrame(T.SYNACK, sid, 0, null))
      if (this.onStream) this.onStream(st)
      return
    }
    if (f.type === T.SYNACK) {
      const st = this.streams.get(f.sid)
      if (st && !st.established) {
        st.established = true
        this.emit('stream-open', st)
      }
      return
    }
    if (f.type === T.RST) {
      const st = this.streams.get(f.sid)
      if (st) st.destroy()
      return
    }
  }

  newStream(sid, opts) {
    const st = new TunnelStream(this, sid, {
      ...opts,
      sendKey: this.sendKey,
      sendDir: this.sendDir,
      recvKey: this.recvKey,
      recvDir: this.recvDir
    })
    this.streams.set(sid, st)
    st.on('close', () => { this.streams.delete(sid) })
    return st
  }

  openStream() {
    const sid = this.nextSid
    this.nextSid += 2
    const st = this.newStream(sid, { established: false })
    this.send(encFrame(T.SYN, sid, 0, null))
    return st
  }

  dropStream(sid) {
    this.streams.delete(sid)
  }

  close() {
    this.closed = true
    if (this._onMsg && this._sockRef) {
      try { this._sockRef.removeListener('message', this._onMsg) } catch (e) { }
    }
    this._onMsg = null
    this._sockRef = null
    for (const t of this._timers) clearInterval(t)
    this._timers = []
    for (const st of this.streams.values()) {
      try { st.destroy() } catch (e) { }
    }
    this.streams.clear()
    this.emit('close')
  }
}
