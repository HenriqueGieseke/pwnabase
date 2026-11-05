import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, rename, unlink, symlink, rm, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createStore, SHEETS } from '../server/utils/sheets.mjs'
import { readBatchStatus, readBatchConfigurations, readBatchHistory } from '../server/utils/batch-status.mjs'
import { readBatchEvents } from '../server/utils/batch-events.mjs'
import { createEventQueue } from '../app/utils/event-queue.mjs'
import './privacy.test.mjs'
import { createDemoRoot, demoEnvironment } from '../demo.mjs'

test('fictional demo uses a separate temporary root with each sheet populated', async t => {
  const root = await createDemoRoot()
  t.after(() => rm(root, { recursive: true, force: true }))
  assert.notEqual(root, process.env.PWNA_DATA_ROOT)
  const env = demoEnvironment({ NUXT_DATA_ROOT: '/real', NITRO_DATA_ROOT: '/real',
    NUXT_PUBLIC_DEMO: 'false', NITRO_PUBLIC_DEMO: 'false', PWNA_DATA_ROOT: '/real' }, root)
  assert.equal(env.NUXT_DATA_ROOT, root)
  assert.equal(env.NITRO_DATA_ROOT, root)
  assert.equal(env.PWNA_DATA_ROOT, root)
  assert.equal(env.NUXT_PUBLIC_DEMO, 'true')
  assert.equal(env.NITRO_PUBLIC_DEMO, 'true')
  const store = createStore(root)
  for (const tab of SHEETS) assert.ok((await store.sheet(tab)).rows.length, `${tab} has fictional rows`)
  const row = (await store.sheet('complete')).rows[0]
  assert.ok(row.password.startsWith('fictional-demo-'))
  const status = await readBatchStatus(root)
  assert.equal(status.source_label, 'fictional-words')
  assert.equal((await readBatchEvents(root, status.run_id)).events.length, 3)
})

test('batch status is read-only, filtered and detects stale runs', async t => {
  const { root, put } = await fixture(t)
  assert.equal(await readBatchStatus(root), null)
  const file = await put('.pwnabase/batch-status.json', {
    schema_version: 1, run_id: 'a'.repeat(32), state: 'running',
    started_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:10Z',
    capture_index: 2, capture_total: 4, ssid: 'Synthetic network', bssid: '02:00:00:00:00:01',
    generated_candidates: 100, hashcat_confirmed_candidates: 75, checkpointed_candidates: 50,
    hashcat: { done: 5, total: 10, speed: 2, eta_seconds: 3, password: 'synthetic-secret' },
    password: 'synthetic-secret',
  })
  const before = await readFile(file, 'utf8')
  const status = await readBatchStatus(root, Date.parse('2026-01-01T00:01:00Z'))
  assert.equal(status.state, 'unknown')
  assert.equal(status.generated_candidates, 100)
  assert.equal(status.hashcat_confirmed_candidates, 75)
  assert.equal(status.checkpointed_candidates, 50)
  assert.deepEqual(status.hashcat, { done: 5, total: 10, speed: 2, eta_seconds: 3 })
  assert.equal((await readBatchStatus(root, Date.parse('2026-01-01T00:00:20Z'))).state, 'running')
  assert.equal((await readBatchStatus(root, Date.parse('2026-01-01T00:00:40Z'))).state, 'running')
  assert.ok(!JSON.stringify(status).includes('synthetic-secret'))
  assert.equal(await readFile(file, 'utf8'), before)
  await writeFile(file, JSON.stringify({ schema_version: 1, run_id: 'a'.repeat(32), state: 'completed',
    started_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:10Z' }))
  assert.equal((await readBatchStatus(root, Date.parse('2026-02-01T00:00:00Z'))).state, 'completed')
  await writeFile(file, '{bad')
  assert.equal(await readBatchStatus(root), null)
  await unlink(file)
  await symlink(join(root, 'complete'), file)
  assert.equal(await readBatchStatus(root), null)
})

test('batch configurations group identical identities and number changed contents', async t => {
  const { root, put } = await fixture(t)
  const record = (run, config, label, time) => ({ schema_version: 1, run_id: run.repeat(32),
    configuration_id: config.repeat(64), source_label: label, mode: 'wordlist', rule_label: null,
    state: 'completed', started_at: time, updated_at: time })
  await put(`.pwnabase/batch-runs/${'a'.repeat(32)}.json`, record('a', 'a', 'words', '2026-01-01T00:00:00Z'))
  await put(`.pwnabase/batch-runs/${'b'.repeat(32)}.json`, record('b', 'a', 'renamed', '2026-01-02T00:00:00Z'))
  await put(`.pwnabase/batch-runs/${'d'.repeat(32)}.json`, record('d', 'c', 'words 2', '2026-01-03T00:00:00Z'))
  await put(`.pwnabase/batch-runs/${'c'.repeat(32)}.json`, record('c', 'b', 'words', '2026-01-04T00:00:00Z'))
  const groups = await readBatchConfigurations(root)
  assert.equal(groups.length, 3)
  assert.equal(groups[0].label, 'words')
  assert.equal(groups[0].latest.run_id, 'b'.repeat(32))
  assert.equal(groups[1].label, 'words 2')
  assert.equal(groups[2].label, 'words 3')
})

test('run history pages remain stable when new runs arrive', async t => {
  const { root, put } = await fixture(t)
  const config = 'a'.repeat(64)
  const record = i => ({ schema_version: 1, run_id: i.toString(16).padStart(32, '0'),
    configuration_id: config, source_label: 'words', mode: 'wordlist', rule_label: null,
    state: 'completed', started_at: new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString(),
    ended_at: new Date(Date.UTC(2026, 0, 1, 0, 0, i + 1)).toISOString(),
    updated_at: new Date(Date.UTC(2026, 0, 1, 0, 0, i + 1)).toISOString(), password: 'synthetic-secret' })
  for (let i = 0; i < 25; i++) {
    const item = record(i)
    await put(`.pwnabase/batch-runs/${item.run_id}.json`, item)
  }
  const first = await readBatchHistory(root, config)
  assert.equal(first.runs.length, 20)
  assert.ok(first.storage_bytes > 0)
  const extra = record(25)
  await put(`.pwnabase/batch-runs/${extra.run_id}.json`, extra)
  const older = await readBatchHistory(root, config, first.before)
  assert.equal(older.runs.length, 5)
  assert.equal(older.before, null)
  assert.equal(older.runs[0].run_id, record(4).run_id)
  assert.ok(!JSON.stringify(first).includes('synthetic-secret'))
  assert.deepEqual((await readBatchHistory(root, '../private')).runs, [])
})

test('indexed run history reads bounded pages and keeps cursors stable', async t => {
  const { root, put } = await fixture(t)
  const config = 'f'.repeat(64)
  const runId = i => i.toString(16).padStart(32, '0')
  const index = join(root, '.pwnabase', 'batch-index')
  await mkdir(index, { recursive: true })
  await put(`.pwnabase/batch-index/${config}.json`, { configuration_id: config, source_label: 'words',
    mode: 'wordlist', rule_label: null, started_at: '2026-01-01T00:00:00Z' })
  const record = i => ({ schema_version: 1, run_id: runId(i), configuration_id: config,
    source_label: 'words', mode: 'wordlist', rule_label: null, state: 'completed',
    started_at: new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString(),
    updated_at: new Date(Date.UTC(2026, 0, 1, 0, 0, i + 1)).toISOString() })
  for (let i = 0; i < 45; i++) await put(`.pwnabase/batch-runs/${runId(i)}.json`, record(i))
  const indexPath = join(index, `${config}.idx`)
  await writeFile(indexPath, Array.from({ length: 45 }, (_, i) => runId(i) + '\n').join(''))
  const first = await readBatchHistory(root, config)
  assert.equal(first.runs.length, 20)
  assert.equal(first.runs[0].run_id, runId(44))
  assert.match(first.before, /^\d{1,15}:[a-f0-9]{32}$/)
  await put(`.pwnabase/batch-runs/${runId(45)}.json`, record(45))
  await writeFile(indexPath, runId(45) + '\n', { flag: 'a' })
  const older = await readBatchHistory(root, config, first.before)
  assert.equal(older.runs[0].run_id, runId(24))
  assert.equal(older.runs.length, 20)
  assert.ok(first.storage_bytes > 0)
  assert.equal((await readBatchConfigurations(root))[0].latest.run_id, runId(45))
  await put(`.pwnabase/batch-runs/${runId(46)}.json`, record(46))
  await put('.pwnabase/batch-index-dirty', { needs_rebuild: true })
  assert.equal((await readBatchHistory(root, config, first.before)).reset, true)
  assert.equal((await readBatchHistory(root, config)).runs[0].run_id, runId(46))
  assert.equal((await readBatchConfigurations(root))[0].latest.run_id, runId(46))
  const legacyCursor = (await readBatchHistory(root, config)).before
  await unlink(join(root, '.pwnabase', 'batch-index-dirty'))
  assert.equal((await readBatchHistory(root, config, legacyCursor)).reset, true)
  await writeFile(indexPath, Array.from({ length: 46 }, (_, i) => runId(i + 1) + '\n').join(''))
  assert.equal((await readBatchHistory(root, config, first.before)).reset, true)
})

test('batch events page backwards without leaking fields or duplicating newer writes', async t => {
  const { root } = await fixture(t)
  const directory = join(root, '.pwnabase', 'batch-events')
  await mkdir(directory, { recursive: true })
  const run = 'a'.repeat(32)
  const file = join(directory, `${run}.jsonl`)
  const line = index => JSON.stringify({ kind: 'capture_started', at: '2026-01-01T00:00:00Z',
    capture_name: `capture-${index}`, password: 'synthetic-secret' }) + '\n'
  await writeFile(file, Array.from({ length: 250 }, (_, i) => line(i)).join(''))
  const latest = await readBatchEvents(root, run)
  assert.equal(latest.events.length, 200)
  assert.equal(latest.events[0].capture_name, 'capture-50')
  await writeFile(file, line(250), { flag: 'a' })
  const older = await readBatchEvents(root, run, latest.before)
  assert.equal(older.events.length, 50)
  assert.equal(older.events.at(-1).capture_name, 'capture-49')
  assert.equal(older.before, null)
  assert.ok(!JSON.stringify(latest).includes('synthetic-secret'))
  assert.equal((await readBatchEvents(root, '../private')).events.length, 0)
  await writeFile(file, Array.from({ length: 450 }, (_, i) => line(i + 251)).join(''), { flag: 'a' })
  const newest = await readBatchEvents(root, run)
  const middle = await readBatchEvents(root, run, newest.before)
  const bridge = await readBatchEvents(root, run, middle.before)
  assert.equal(newest.events[0].capture_name, 'capture-501')
  assert.equal(middle.events[0].capture_name, 'capture-301')
  assert.equal(bridge.events.at(-1).capture_name, 'capture-300')
})

test('event refresh finishes before a simultaneous older-page request', async () => {
  const queue = createEventQueue()
  const order = []
  let unblock
  const barrier = new Promise(resolve => { unblock = resolve })
  const latest = queue.refresh(async () => { order.push('latest-start'); await barrier; order.push('latest-end') })
  const older = queue.older(async () => { order.push('older') })
  await Promise.resolve()
  assert.deepEqual(order, ['latest-start'])
  unblock()
  await Promise.all([latest, older])
  assert.deepEqual(order, ['latest-start', 'latest-end', 'older'])
})

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'pwnabase-viewer-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  for (const tab of SHEETS) await mkdir(join(root, tab))
  return { root, store: createStore(root), async put(name, data) {
    const file = join(root, name)
    await mkdir(join(file, '..'), { recursive: true })
    await writeFile(file, JSON.stringify(data))
    return file
  } }
}

test('old results, visible passwords, non-UTF8 hex, catalogs and details', async t => {
  const { store, put } = await fixture(t)
  const file = await put('complete/one.json', { status: 'recovered', password: 'synthetic!123', record: { ssid: 'Study fixture', bssid: '02:00:00:00:00:01' }, updated_at: '2026-01-01T00:00:00Z' })
  const before = await readFile(file, 'utf8')
  const sheet = await store.sheet('complete')
  assert.equal(sheet.rows[0].password, 'synthetic!123')
  assert.equal(sheet.rows[0].ruleSet, '')
  assert.equal((await store.detail('complete', sheet.rows[0].id)).data.password, 'synthetic!123')
  await put('complete/two.json', { password: null, password_hex: 'ff80', rules: null })
  assert.ok((await store.sheet('complete')).rows.some(row => row.passwordHex === 'ff80'))
  assert.equal(await readFile(file, 'utf8'), before)
  await put('rules/basic.json', { id: 'basic', rules: [{ id: 'original', expression: ':' }, { id: 'capital', expression: 'c' }] })
  const rules = await store.sheet('rules')
  assert.equal(rules.rows.length, 1)
  assert.equal(rules.rows[0].ruleCount, 2)
})

test('all wordlist directories, separate attempts, search, sort and pagination', async t => {
  const { store, put } = await fixture(t)
  for (let i = 0; i < 56; i++) await put(`exhausted/${i % 2 ? 'beta' : 'alpha'}/${i}.json`, {
    status: 'wordlist_exhausted', record: { ssid: `Network ${i}` },
    updated_at: new Date(1700000000000 + i * 1000).toISOString(),
  })
  const first = await store.sheet('exhausted')
  assert.equal(first.total, 56)
  assert.equal(first.rows.length, 50)
  assert.equal(first.rows[0].name, 'Network 55')
  assert.deepEqual(first.wordlists, ['alpha', 'beta'])
  assert.equal((await store.sheet('exhausted', { page: 2 })).rows.length, 6)
  assert.equal((await store.sheet('exhausted', { page: 900 })).page, 2)
  assert.equal((await store.sheet('exhausted', { wordlist: 'alpha' })).filtered, 28)
  assert.equal((await store.sheet('exhausted', { search: 'Network 55' })).filtered, 1)
  assert.equal((await store.sheet('exhausted', { sort: 'name', direction: 'asc' })).rows[0].name, 'Network 0')
})

test('atomic replacements, deleted files, malformed files and missing directories', async t => {
  const { root, store, put } = await fixture(t)
  const path = await put('complete/a.json', { record: { ssid: 'Before' } })
  assert.equal((await store.sheet('complete')).rows[0].name, 'Before')
  await writeFile(join(root, 'complete/.pending-x'), JSON.stringify({ record: { ssid: 'After' } }))
  await rename(join(root, 'complete/.pending-x'), path)
  assert.equal((await store.sheet('complete')).rows[0].name, 'After')
  const id = (await store.sheet('complete')).rows[0].id
  await unlink(path)
  assert.equal(await store.detail('complete', id), null)
  await writeFile(path, 'broken json')
  assert.equal((await store.sheet('complete')).rows[0].status, 'invalid_json')
  await put('tool-error/capture.json', { status: 'tool_error', error: 'Synthetic extractor error', sources: [{ path: '/fixtures/capture.pcap' }] })
  assert.equal((await store.sheet('tool-error')).rows[0].name, 'capture.pcap')
  await rm(join(root, 'rules'), { recursive: true })
  assert.equal((await store.sheet('rules')).total, 0)
})

test('rejects arbitrary directories and ignores symlinks and internal state', async t => {
  const { root, store, put } = await fixture(t)
  await put('.aws/secret.json', { hidden: true })
  await put('.pwnabase/captures/internal.json', { hidden: true })
  await symlink(join(root, '.aws/secret.json'), join(root, 'complete/link.json'))
  await symlink(join(root, '.aws'), join(root, 'exhausted/linked'))
  assert.equal((await store.sheet('complete')).total, 0)
  assert.equal((await store.sheet('exhausted')).total, 0)
  await assert.rejects(store.sheet('../.aws'), /Unknown sheet/)
  await assert.rejects(store.sheet('.pwnabase'), /Unknown sheet/)
  assert.equal(await store.detail('complete', '../.aws/secret.json'), null)
})

test('duplicate filter uses the complete network/password tuple before pagination', async t => {
  const { store, put } = await fixture(t)
  const base = { status: 'recovered', password: 'fixture123', record: { ssid: 'Fixture', bssid: '02:00:00:00:00:01' } }
  for (let i = 0; i < 52; i++) await put(`complete/${i}.json`, { ...base, updated_at: new Date(1700000000000 + i * 1000).toISOString() })
  await put('complete/different-password.json', { ...base, password: 'other123' })
  await put('complete/different-ssid.json', { ...base, record: { ...base.record, ssid: 'Other' } })
  await put('complete/different-bssid.json', { ...base, record: { ...base.record, bssid: '02:00:00:00:00:02' } })
  await put('complete/hex-one.json', { ...base, password: null, password_hex: 'ff80' })
  await put('complete/hex-two.json', { ...base, password: null, password_hex: 'ff81' })
  await put('complete/no-identifiers-one.json', {})
  await put('complete/no-identifiers-two.json', {})
  assert.equal((await store.sheet('complete')).total, 59)
  assert.equal((await store.sheet('complete', { hideDuplicates: 'false' })).filtered, 59)
  const unique = await store.sheet('complete', { hideDuplicates: 'true', page: 2 })
  assert.equal(unique.filtered, 8)
  assert.equal(unique.duplicatesHidden, 51)
  assert.equal(unique.page, 1)
  assert.equal(unique.pages, 1)
  assert.ok(unique.rows.some(row => row.filename === '51.json'))
  assert.equal((await store.sheet('complete', { hideDuplicates: true, search: 'Other' })).filtered, 2)
  assert.equal((await store.sheet('complete')).filtered, 59)
})

test('SSID-derived results expose a source label and preserve generation details', async t => {
  const { store, put } = await fixture(t)
  await put('exhausted/ssid/attempt.json', {
    status: 'no_eligible_candidates', wordlist: null,
    candidate_source: { type: 'ssid', label: 'SSID', ssid_hex: '616263' },
    candidate_generation: { eligible: 0 }, rules: { id: 'ssid-portuguese' },
    record: { ssid: 'abc', bssid: '02:00:00:00:00:01' },
  })
  const sheet = await store.sheet('exhausted', { wordlist: 'SSID' })
  assert.equal(sheet.filtered, 1)
  assert.equal(sheet.rows[0].wordlist, 'SSID')
  assert.equal(sheet.rows[0].candidateSource, 'ssid')
  assert.equal(sheet.rows[0].status, 'no_eligible_candidates')
  assert.equal((await store.detail('exhausted', sheet.rows[0].id)).data.candidate_generation.eligible, 0)
  await put('rules/ssid.json', { id: 'ssid-portuguese', type: 'ssid_profile', rules: [{ id: 'case', operation: 'case', values: ['upper'] }] })
  assert.equal((await store.sheet('rules')).rows[0].ruleCount, 1)
})
