import test, { after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createHash } from 'node:crypto'

let seq = 0
const TMP_DIRS = []
function tmpDir() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-ffm-' + (seq++) + '-'))
  TMP_DIRS.push(d)
  return d
}
const GATE_FILE = path.join(tmpDir(), 'dl-gate.json')
process.env.DSH_DL_GATE_FILE = GATE_FILE

const ff = await import('../ffmpeg-bootstrap.mjs')
const dg = await import('../dl-gate.mjs')

after(() => {
  for (const d of TMP_DIRS) { try { fs.rmSync(d, { recursive: true, force: true }) } catch (_) { } }
})

const PAD = Buffer.from('FAKE-FFMPEG-ZIP-BODY-'.repeat(32), 'utf8')
const BODY = PAD
const SHA = createHash('sha256').update(BODY).digest('hex')
const KEYS = ['win32-x64', 'darwin-x64', 'darwin-arm64', 'linux-x64', 'linux-arm64']

function manifest() {
  const files = {}
  for (const k of KEYS) files[k] = { file: 'ffmpeg-test.zip', sha256: SHA, size: BODY.length }
  return { version: 'test-1', files }
}

function fakeFetch(rule = {}) {
  const calls = []
  const fn = async (url) => {
    const u = String(url)
    calls.push(u)
    const kind = u.indexOf('manifest.json') >= 0 ? 'manifest' : 'file'
    const srcId = u.indexOf('github.com') >= 0 ? 'github' : (u.indexOf('aliyuncs.com') >= 0 ? 'oss' : 'self')
    const conf = rule[srcId] || {}
    const status = conf[kind]
    if (typeof status === 'number' && status !== 200) {
      return { ok: false, status: status, text: async () => (conf.body || '{"ok":false,"reason":"ip-gap"}') }
    }
    if (kind === 'manifest') return { ok: true, status: 200, json: async () => (conf.manifest || manifest()) }
    return { ok: true, status: 200, arrayBuffer: async () => BODY }
  }
  fn.calls = calls
  return fn
}

function resetGate() {
  try { fs.writeFileSync(GATE_FILE, '{}') } catch (_) { }
}

test('源顺序常量：github → oss → self（本服必须最后，否则 GitHub 永远到不了）', () => {
  assert.deepEqual(ff.FFMPEG_MIRROR_BASES.map((b) => b.id), ['github', 'oss', 'self'])
})

test('manualSourcePlan：手动点按钮一律全量回退，不再「第 1 次只锁 GitHub」', () => {
  const p1 = dg.manualSourcePlan(1)
  assert.equal(p1.ids, null)
  assert.equal(p1.skipOss, false, '第一次就必须允许 OSS（国内直连 GitHub 必挂）')
  const p2 = dg.manualSourcePlan(2, { ossBase: 'https://dsh-bin.oss-cn-hangzhou.aliyuncs.com/ffmpeg' })
  assert.equal(p2.skipOss, false)
  const p3 = dg.manualSourcePlan(9, { ossBase: '' })
  assert.equal(p3.skipOss, true, '排障时显式传 ossBase:\'\' 才剔除 OSS')
})

test('🔴 回归：GitHub 清单 500 必须继续落到 OSS（旧代码在这里 return 整条失败）', async () => {
  resetGate()
  const dir = tmpDir()
  const f = fakeFetch({ github: { manifest: 500 } })
  const r = await ff.ensureFfmpeg({ dir: dir, forceDownload: true, auto: false, fetch: f, log: () => { } })
  assert.equal(f.calls.length > 2, true, '不许只打 GitHub 两条就收工：' + f.calls.join(','))
  assert.equal(f.calls.some((u) => u.indexOf('aliyuncs.com') >= 0), true, '必须试过 OSS：' + f.calls.join(','))

  assert.equal(r.ok, false)
  assert.equal(r.reason, 'unzip')
})

test('🔴 回归：GitHub 文件 500 必须继续落到 OSS 并下载成功', async () => {
  resetGate()
  const dir = tmpDir()
  const f = fakeFetch({ github: { file: 500 } })
  const r = await ff.ensureFfmpeg({ dir: dir, forceDownload: true, auto: false, fetch: f, log: () => { } })
  assert.equal(f.calls.some((u) => u.indexOf('aliyuncs.com') >= 0 && u.indexOf('manifest.json') < 0), true,
    '必须真的从 OSS 下过包：' + f.calls.join(','))
  assert.equal(r.reason, 'unzip')
})

test('三档全挂：返回最后一档的 lastFail，且三档都试过', async () => {
  resetGate()
  const dir = tmpDir()
  const f = fakeFetch({ github: { file: 500 }, oss: { file: 503 }, self: { file: 502 } })
  const r = await ff.ensureFfmpeg({ dir: dir, forceDownload: true, auto: false, fetch: f, log: () => { } })
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'download-http')
  assert.match(String(r.error), /HTTP 502/)
  assert.equal(f.calls.length, 6, '三档各一次清单 + 一次文件：' + f.calls.join(','))
  assert.equal(fs.existsSync(path.join(dir, 'download.zip')), false, '失败必须把半截包删掉')
})

test('429 限流：原样照搬服务端 error 文案，不再只甩状态码', async () => {
  resetGate()
  const dir = tmpDir()

  const body = '{"ok": false, "error": "下载太频繁，请 20 秒后再试", "reason": "ip-gap"}'
  const f = fakeFetch({ github: { file: 429, body: body }, oss: { file: 429, body: body }, self: { file: 429, body: body } })
  const r = await ff.ensureFfmpeg({ dir: dir, forceDownload: true, auto: false, fetch: f, log: () => { } })
  assert.equal(r.reason, 'download-http')
  assert.match(String(r.error), /请 20 秒后再试/)
  assert.equal(String(r.error).indexOf('ip-gap'), -1, '不许把内部 reason 漏给用户')
})

test('429 但 body 不是 JSON：按 reason 关键词兜底翻人话', async () => {
  resetGate()
  const dir = tmpDir()
  const body = '<html>429 ip-day too many</html>'
  const f = fakeFetch({ github: { file: 429, body: body }, oss: { file: 429, body: body }, self: { file: 429, body: body } })
  const r = await ff.ensureFfmpeg({ dir: dir, forceDownload: true, auto: false, fetch: f, log: () => { } })
  assert.equal(r.reason, 'download-http')
  assert.match(String(r.error), /下载次数已用完/)
})

test('OSS 闸门用尽时静默跳过 OSS，直接落本服（不把省钱逻辑漏给用户）', async () => {
  fs.writeFileSync(GATE_FILE, JSON.stringify({
    day: (() => { const d = new Date(); const p = (n) => String(n).padStart(2, '0'); return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) })(),
    oss: { count: dg.OSS_MAX_PER_DAY, bytes: 0, lastMs: 0 }
  }))
  const dir = tmpDir()
  const logs = []
  const f = fakeFetch({ github: { file: 500 }, self: { file: 500 } })
  const r = await ff.ensureFfmpeg({ dir: dir, forceDownload: true, auto: false, fetch: f, log: (m) => logs.push(String(m)) })
  assert.equal(f.calls.some((u) => u.indexOf('aliyuncs.com') >= 0), false, '闸门用尽不该再打 OSS：' + f.calls.join(','))
  assert.equal(logs.some((m) => m.indexOf('跳过 OSS') >= 0), true)
  assert.equal(r.reason, 'download-http')
  resetGate()
})
