import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, rename, unlink, symlink, rm, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createStore, SHEETS } from '../server/utils/sheets.mjs'
import { readBatchStatus } from '../server/utils/batch-status.mjs'

test('batch status is read-only, filtered and detects stale runs', async t => {
  const { root, put } = await fixture(t)
  assert.equal(await readBatchStatus(root), null)
  const file = await put('.pwnabase/batch-status.json', {
    schema_version: 1, run_id: 'a'.repeat(32), state: 'running',
    started_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:10Z',
    password: 'synthetic-secret',
  })
  const before = await readFile(file, 'utf8')
  const status = await readBatchStatus(root, Date.parse('2026-01-01T00:01:00Z'))
  assert.equal(status.state, 'unknown')
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
