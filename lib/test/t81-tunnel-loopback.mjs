
import dgram from 'node:dgram'
import http from 'node:http'
import { Tunnel } from '../p2p-tunnel.mjs'

const LOSS = Number(process.env.LOSS || 0)

function mkSock() {
  return new Promise((res) => {
    const s = dgram.createSocket('udp4')
    s.bind(0, '127.0.0.1', () => res(s))
  })
}

const sa = await mkSock()
const sb = await mkSock()
const A = { ip: '127.0.0.1', port: sa.address().port }
const B = { ip: '127.0.0.1', port: sb.address().port }

function wrap(sock, drop) {
  const orig = sock.send.bind(sock)
  sock.send = (buf, port, ip, cb) => {
    if (drop > 0 && Math.random() < drop) { if (cb) cb(); return }
    return orig(buf, port, ip, cb)
  }
  return sock
}
wrap(sa, LOSS); wrap(sb, LOSS)

const server = http.createServer((req, res) => {
  let n = 0
  req.on('data', (c) => { n += c.length })
  req.on('end', () => {
    const body = JSON.stringify({ ok: true, path: req.url, method: req.method, bytes: n, ra: req.socket.remoteAddress })
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) })
    res.end(body)
  })
})

const srvTunnel = new Tunnel({ secret: 'k', isClient: false, onStream: (st) => { server.emit('connection', st) } })
srvTunnel.attach(sb, A)

const cliTunnel = new Tunnel({ secret: 'k', isClient: true })
cliTunnel.attach(sa, B)

function call(path, payload, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const st = cliTunnel.openStream()
    const req = http.request({ createConnection: () => st, method: payload ? 'POST' : 'GET', path, headers: { Host: '127.0.0.1:8899' } }, (res) => {
      let d = ''
      res.on('data', (c) => { d += c })
      res.on('end', () => resolve({ status: res.statusCode, body: d }))
    })
    req.on('error', reject)
    const t = setTimeout(() => { req.destroy(); reject(new Error('timeout')) }, timeoutMs)
    req.on('close', () => clearTimeout(t))
    if (payload) req.write(payload)
    req.end()
  })
}

const t0 = Date.now()
const r1 = await call('/info')
console.log('R1', JSON.stringify(r1), 'ms=' + (Date.now() - t0))
const big = JSON.stringify({ op: 'sessions', payload: { x: 'y'.repeat(200000) } })
const t1 = Date.now()
const r2 = await call('/cmd', big)
console.log('R2', JSON.stringify(r2).slice(0, 200), 'ms=' + (Date.now() - t1))
const r3 = await call('/info')
console.log('R3', JSON.stringify(r3), 'ms=' + (Date.now() - t1))
console.log('STATS cli=', JSON.stringify(cliTunnel.stats), 'srv=', JSON.stringify(srvTunnel.stats))
process.exit(0)
