import test from 'node:test'
import assert from 'node:assert/strict'

const MSG_TYPES = new Set(['user/message', 'assistant/message'])

function paginate(events, req) {
  const maxMessages = Number((req && req.maxMessages) || 3200)
  const beforeSeq = Number((req && req.beforeSeq) || 0)
  const win = req && req.turnWindow
  const end = beforeSeq > 0
    ? events.findIndex((e) => Number(e.seq) >= beforeSeq)
    : events.length
  const stop = end < 0 ? events.length : end
  let count = 0
  let turns = 0
  let cut = 0
  for (let i = stop - 1; i >= 0; i--) {
    if (win && events[i].type === 'turn/start') {
      turns++
      if (count >= Number(win.minMessages || 1) && turns >= Number(win.minTurns || 1)) { cut = i; break }
    }
    if (!MSG_TYPES.has(events[i].type)) continue
    count++
    if (count >= maxMessages) { cut = i; break }
  }
  return { events: events.slice(cut, stop), hasMore: cut > 0 }
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
  if (!o.open) push('turn/end', { turn })
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

const TOTAL = 8
const CLOSED = makeEvents(TOTAL, null)

let seqNo = 0

async function detailWith(payload, events, opts) {
  const evs = events || CLOSED
  const asOfSeq = evs.reduce((m, e) => Math.max(m, e.seq), 0)

  const statsTurns = evs.filter((e) => e.type === 'turn/start').length
  const values = { title: 't', turnOutline: [] }
  if (!(opts && opts.noStats)) values.sessionStats = { turns: statsTurns }
  let cmdFetch = null
  const conn = { fetch: { register: (r) => { if (r.path === '/api/dsh-console/cmd') cmdFetch = r.fetch; return () => {} } } }
  const ctl = {
    projections: async () => ({ asOfSeq, values: values }),
    page: async (req) => {
      const p = paginate(evs, req)
      return { records: p.events.map((e) => ({ type: 'event', event: e })), hasMore: p.hasMore }
    },
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

const nosOf = (d) => (d.turns || []).map((t) => Number(t.turn))

test('① 不传 limitTurns/beforeSeq：整份全量，轮号 1..N，turnCount=N，不带 hasMore', async () => {
  const r = await detailWith({ sessionId: 's' })
  assert.deepEqual(nosOf(r.detail), [1, 2, 3, 4, 5, 6, 7, 8], '全量轮号应为 1..8，实际 ' + JSON.stringify(nosOf(r.detail)))
  assert.equal(Number(r.detail.turnCount), TOTAL, 'turnCount 应为 8')
  assert.equal(r.detail.hasMore, undefined, '不分页时不该带 hasMore（保持旧回包形状）')
  assert.equal(r.detail.earliestSeq, undefined, '不分页时不该带 earliestSeq')
})

test('② limitTurns=3：只回最近 3 轮，轮号必须是真实轮号 6,7,8（不能重编成 1..3）', async () => {
  const r = await detailWith({ sessionId: 's', limitTurns: 3 })
  assert.deepEqual(nosOf(r.detail), [6, 7, 8], '最近 3 轮应是真实轮号 6,7,8，实际 ' + JSON.stringify(nosOf(r.detail)))
  assert.equal(Number(r.detail.turnCount), TOTAL, 'turnCount 必须仍是全量 8，否则 App 判新轮会错')
  assert.equal(r.detail.hasMore, true, '还有更早的轮 ⇒ hasMore=true')
  assert.ok(Number(r.detail.earliestSeq) > 0, 'earliestSeq 必须给出来，App 靠它往上翻页')
})

test('③ 往上翻页：beforeSeq=earliestSeq 必须回到更早的轮，且轮号连续、可与上一页按号合并', async () => {
  const first = await detailWith({ sessionId: 's', limitTurns: 3 })
  const firstNos = nosOf(first.detail)
  const back = await detailWith({ sessionId: 's', limitTurns: 3, beforeSeq: Number(first.detail.earliestSeq) })
  const backNos = nosOf(back.detail)
  assert.ok(backNos.length > 0, '翻页必须回出轮，实际为空')
  assert.ok(backNos[backNos.length - 1] <= firstNos[0],
    '翻页轮的末轮应 <= 首页首轮（允许 1 轮重叠去重），back=' + JSON.stringify(backNos) + ' first=' + JSON.stringify(firstNos))
  assert.ok(backNos.every((v, i) => i === 0 || v === backNos[i - 1] + 1), '翻页轮号必须连续：' + JSON.stringify(backNos))
  assert.equal(Number(back.detail.turnCount), TOTAL, '翻页回包 turnCount 也必须是全量 8')
})

test('④ 连续翻页到底：beforeSeq 一直往前推，最终能拿到第 1 轮，且 hasMore 归 false', async () => {
  let beforeSeq = 0
  let seen = []
  let guard = 0
  for (;;) {
    const p = { sessionId: 's', limitTurns: 3 }
    if (beforeSeq > 0) p.beforeSeq = beforeSeq
    const r = await detailWith(p)
    const nos = nosOf(r.detail)
    for (const n of nos) if (!seen.includes(n)) seen.push(n)
    if (r.detail.hasMore !== true) break
    const es = Number(r.detail.earliestSeq)
    assert.ok(es > 0, 'hasMore=true 时必须给 earliestSeq')
    assert.ok(!(beforeSeq > 0 && es >= beforeSeq), '翻页后 earliestSeq 必须真的变小：' + beforeSeq + ' -> ' + es)
    beforeSeq = es
    if (++guard > 20) throw new Error('翻页死循环')
  }
  seen.sort((a, b) => a - b)
  assert.deepEqual(seen, [1, 2, 3, 4, 5, 6, 7, 8], '一路翻到底必须补齐全部轮，实际 ' + JSON.stringify(seen))
})

test('⑤ 分页 + 增量组合：sinceTurn 仍只回更新的轮，turnCount 仍是全量，且不带 hasMore', async () => {
  const r = await detailWith({ sessionId: 's', limitTurns: 3, sinceTurn: 6 })
  assert.equal(r.detail.incremental, true, '必须标 incremental')
  assert.deepEqual(nosOf(r.detail), [7, 8], '增量应只含 turn>6 的轮，实际 ' + JSON.stringify(nosOf(r.detail)))
  assert.equal(Number(r.detail.turnCount), TOTAL, 'turnCount 必须仍是全量 8')
  assert.equal(r.detail.hasMore, undefined, '增量回包不带 hasMore（与 App 手里那份拼不起来）')
  assert.equal(r.detail.earliestSeq, undefined, '增量回包不带 earliestSeq')
})

test('⑥ limitTurns 非法值（0/负数/小数/字符串）：按整数处理，0 与负数退回全量', async () => {
  const a = await detailWith({ sessionId: 's', limitTurns: -3 })
  assert.deepEqual(nosOf(a.detail), [1, 2, 3, 4, 5, 6, 7, 8], '负数应退回全量')
  assert.equal(a.detail.hasMore, undefined, '退回全量不该带 hasMore')
  const b = await detailWith({ sessionId: 's', limitTurns: '2' })
  assert.deepEqual(nosOf(b.detail), [7, 8], '字符串数字应被 Number 化，取最近 2 轮')
  const c = await detailWith({ sessionId: 's', limitTurns: 2.9 })
  assert.deepEqual(nosOf(c.detail), [7, 8], '小数应截断为 2 轮')
})

test('⑦ 分页真的省字节：limitTurns=3 的回包必须显著小于全量', async () => {
  const full = await detailWith({ sessionId: 's' })
  const page = await detailWith({ sessionId: 's', limitTurns: 3 })
  assert.ok(page.bytes * 2 < full.bytes,
    '8 轮只取 3 轮应不到全量一半：page=' + page.bytes + ' full=' + full.bytes)
})

test('⑧ 宿主没给 sessionStats.turns：翻页时 turnCount 不能小于本页轮数，也不能崩', async () => {
  const back = await detailWith({ sessionId: 's', limitTurns: 3, beforeSeq: Number((await detailWith({ sessionId: 's', limitTurns: 3 })).detail.earliestSeq) }, null, { noStats: true })
  const n = nosOf(back.detail).length
  assert.ok(n > 0, '翻页必须回出轮')
  assert.ok(Number(back.detail.turnCount) >= n,
    'turnCount 至少要不小于本页轮数（兜底不能把全量轮数改小）：turnCount=' + back.detail.turnCount + ' 本页=' + n)
})
