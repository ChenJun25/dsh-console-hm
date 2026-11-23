import test from 'node:test'
import assert from 'node:assert/strict'

const MSG_TYPES = new Set(['user/message', 'assistant/message'])

function paginate(events, maxMessages) {
  const evs = events
  let count = 0
  let cut = 0
  for (let i = evs.length - 1; i >= 0; i--) {
    if (!MSG_TYPES.has(evs[i].type)) continue
    count++
    if (count >= maxMessages) { cut = i; break }
  }
  return evs.slice(cut)
}

function makeTurn(turn, opts) {
  const o = opts || {}
  const evs = []
  let seq = 0
  const push = (type, data) => evs.push({ type, seq: seq++, time: 1790000000000 + seq, data })
  push('turn/start', { turn })
  push('user/message', { turn, content: [{ type: 'text', text: '第 ' + turn + ' 轮提问' }] })
  push('assistant/message', { turn, step: 1, stream: [
    { type: 'text-chunks', texts: ['第 ' + turn + ' 轮回答'] }
  ], message: { content: [{ type: 'text', text: '第 ' + turn + ' 轮回答' }] } })
  if (!o.open) { push('turn/end', { turn }) }
  return evs
}

function makeEvents(turns, opts) {
  const out = []
  for (let i = 1; i <= turns; i++) {
    out.push(...makeTurn(i, (opts && opts.open && i === turns) ? { open: true } : null))
  }

  let s = 1
  for (const e of out) { e.seq = s++ }
  return out
}

const CLOSED = makeEvents(8, null)
const OPEN = makeEvents(8, { open: true })

let seqNo = 0
async function detailWith(payload, events) {
  const evs = events || CLOSED
  const asOfSeq = evs.reduce((m, e) => Math.max(m, e.seq), 0)
  let cmdFetch = null
  const conn = { fetch: { register: (r) => { if (r.path === '/api/dsh-console/cmd') cmdFetch = r.fetch; return () => {} } } }
  const ctl = {
    projections: async () => ({ asOfSeq, values: { title: 't', turnOutline: [] } }),
    page: async (req) => ({ records: paginate(evs, Number((req && req.maxMessages) || 3200)).map((e) => ({ type: 'event', event: e })) }),
    list: async () => ({ items: [] })
  }
  const ctx = { get: (n) => (n === 'connection' ? conn : n === 'sessionController' ? ctl : null), on: () => () => {}, effect: () => () => {} }
  const mod = await import('../index.js?t=' + (++seqNo) + '-' + Math.random())
  mod.apply(ctx, { port: 0 })
  assert.ok(cmdFetch, 'cmd 路由没注册上')
  const r = await cmdFetch(new Request('http://x', { method: 'POST', body: JSON.stringify({ op: 'detail', payload }) }))
  const txt = await r.text()
  return { bytes: Buffer.byteLength(txt), text: txt, detail: (JSON.parse(txt).result) || {} }
}

test('① 不传 sinceTurn：整份全量，incremental=false、baseTurn=0、turnCount=轮数', async () => {
  const r = await detailWith({ sessionId: 's' })
  assert.equal(r.detail.turns.length, 8, '全量应 8 轮，实际 ' + r.detail.turns.length)
  assert.equal(r.detail.incremental, false, '非增量必须显式 false')
  assert.equal(Number(r.detail.baseTurn), 0, 'baseTurn 应为 0')
  assert.equal(Number(r.detail.turnCount), 8, 'turnCount 应为 8')
})

test('② sinceTurn=6：只回 turn 7、8，且带 incremental/baseTurn，turnCount 仍是全量 8', async () => {
  const r = await detailWith({ sessionId: 's', sinceTurn: 6 })
  assert.equal(r.detail.incremental, true, '必须标 incremental')
  assert.equal(Number(r.detail.baseTurn), 6, 'baseTurn 应为 6')
  assert.equal(Number(r.detail.turnCount), 8, 'turnCount 恒为全量轮数，不能因增量变小')
  const nos = (r.detail.turns || []).map((t) => Number(t.turn))
  assert.deepEqual(nos, [7, 8], '增量应只含 turn>6 的轮，实际 ' + JSON.stringify(nos))
})

test('③ sinceTurn 已是最新轮：turns 为空（全结束的末轮不重传），但 turnCount 仍报全量', async () => {
  const r = await detailWith({ sessionId: 's', sinceTurn: 8 })
  assert.equal(r.detail.incremental, true, '仍是增量回包')
  assert.equal((r.detail.turns || []).length, 0, '已结束的轮不再重传，turns 应为空')
  assert.equal(Number(r.detail.turnCount), 8, 'turnCount 仍为 8（App 靠它判有没有新轮）')
})

test('④ 末轮未结束（endedMs=0）时必须补进增量里，哪怕它的轮号 <= sinceTurn', async () => {

  const r = await detailWith({ sessionId: 's', sinceTurn: 8 }, OPEN)
  const nos = (r.detail.turns || []).map((t) => Number(t.turn))
  assert.deepEqual(nos, [8], '未结束的末轮必须被补进增量，实际 ' + JSON.stringify(nos))
  assert.equal(Number(r.detail.turnCount), 8, 'turnCount 应为 8')
})

test('⑤ 增量回包不带 hasMore / earliestSeq（分页口径与 App 手里那份拼不起来）', async () => {
  const r = await detailWith({ sessionId: 's', sinceTurn: 4 })
  assert.equal(r.detail.hasMore, undefined, '增量回包不该带 hasMore')
  assert.equal(r.detail.earliestSeq, undefined, '增量回包不该带 earliestSeq')
})

test('⑥ 增量真的省字节：同样一份会话，增量回包必须显著小于全量', async () => {
  const full = await detailWith({ sessionId: 's' })
  const inc = await detailWith({ sessionId: 's', sinceTurn: 6 })
  assert.ok(inc.bytes < full.bytes, '增量应小于全量：inc=' + inc.bytes + ' full=' + full.bytes)
  assert.ok(inc.bytes * 2 < full.bytes, '8 轮会话只取 2 轮，增量应不到全量一半：inc=' + inc.bytes + ' full=' + full.bytes)
})

test('⑦ sinceTurn 传非法值（负数/小数/字符串）：按 0 或整数处理，不炸', async () => {
  const a = await detailWith({ sessionId: 's', sinceTurn: -3 })
  assert.equal(a.detail.incremental, false, '负数应归 0 ⇒ 走全量')
  assert.equal(a.detail.turns.length, 8, '负数应回全量 8 轮')
  const b = await detailWith({ sessionId: 's', sinceTurn: '6' })
  assert.equal(Number(b.detail.baseTurn), 6, '字符串数字应被 Number 化')
  const c = await detailWith({ sessionId: 's', sinceTurn: 3.9 })
  assert.equal(Number(c.detail.baseTurn), 3, '小数应截断为整数')
})
