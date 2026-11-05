import test from 'node:test'
import assert from 'node:assert/strict'
import { HIDDEN, PREFERENCES_KEY, loadPreferences, redactDetails, redactPasswords, savePreferences } from '../app/utils/privacy.mjs'

test('password masking covers nested text and hex without changing the original', () => {
  const input = { password: 'fictional-secret', password_hex: '1234', nested: [{ passwordHex: 'abcd' }] }
  assert.deepEqual(redactPasswords(input), { password: HIDDEN, password_hex: HIDDEN, nested: [{ passwordHex: HIDDEN }] })
  assert.equal(input.password, 'fictional-secret')
})

test('preferences default privately, persist only settings, and retain per-sheet duplicates', () => {
  const tabs = ['complete', 'exhausted']
  const saved = new Map()
  const storage = { getItem: key => saved.get(key), setItem: (key, value) => saved.set(key, value) }
  assert.deepEqual(loadPreferences(storage, tabs), { hidePasswords: true, hideSsids: true, duplicates: { complete: false, exhausted: false } })
  savePreferences(storage, false, { complete: { hideDuplicates: true, password: 'never-store' }, exhausted: { hideDuplicates: false } }, tabs)
  assert.deepEqual(loadPreferences(storage, tabs), { hidePasswords: false, hideSsids: true, duplicates: { complete: true, exhausted: false } })
  assert.ok(!saved.get(PREFERENCES_KEY).includes('never-store'))
  saved.set(PREFERENCES_KEY, '{bad json')
  assert.equal(loadPreferences(storage, tabs).hidePasswords, true)
  const unavailable = { getItem() { throw new Error() }, setItem() { throw new Error() } }
  assert.equal(loadPreferences(unavailable, tabs).hidePasswords, true)
  assert.doesNotThrow(() => savePreferences(unavailable, true, { complete: {}, exhausted: {} }, tabs))
})

test('SSID hiding covers network bytes, authentication records, paths and diagnostics independently', () => {
  const input = { record: { ssid: 'Fictional Network', ssid_hex: '4649', hashcat_record: 'WPA*4649' },
    sources: [{ path: '/captures/Fictional Network.pcap' }], error: 'Fictional Network failure', password: 'secret' }
  const result = redactDetails(input, false, true)
  assert.deepEqual(result.record, { ssid: HIDDEN, ssid_hex: HIDDEN, hashcat_record: HIDDEN })
  assert.equal(result.sources[0].path, HIDDEN)
  assert.equal(result.error, HIDDEN)
  assert.equal(result.password, 'secret')
  assert.deepEqual(redactDetails(input, false, false), input)
  const saved = new Map()
  const storage = { getItem: key => saved.get(key), setItem: (key, value) => saved.set(key, value) }
  savePreferences(storage, true, { complete: { hideDuplicates: false } }, ['complete'], false)
  assert.equal(loadPreferences(storage, ['complete']).hideSsids, false)
})
