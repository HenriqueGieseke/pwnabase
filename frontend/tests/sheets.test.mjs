import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, rename, unlink, symlink, rm, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createStore, SHEETS } from '../server/utils/sheets.mjs'

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
