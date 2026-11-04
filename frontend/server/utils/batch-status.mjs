import { lstat, open, readdir } from 'node:fs/promises'
import { constants } from 'node:fs'
import { join, resolve } from 'node:path'

async function safeDirectory(directory) {
  try { const info = await lstat(directory); return info.isDirectory() && !info.isSymbolicLink() }
  catch (error) { if (error.code === 'ENOENT') return false; throw error }
}

async function readStatusFile(path, now) {
  let file
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    const info = await file.stat()
    if (!info.isFile() || info.size > 65536) return null
    const data = JSON.parse(await file.readFile('utf8'))
    if (!data || data.schema_version !== 1 || !/^[a-f0-9]{32}$/.test(data.run_id) ||
        !['starting', 'running', 'completed', 'interrupted', 'failed'].includes(data.state) ||
        typeof data.started_at !== 'string' || typeof data.updated_at !== 'string' ||
        !Number.isFinite(Date.parse(data.started_at)) || !Number.isFinite(Date.parse(data.updated_at))) return null
    const stale = ['starting', 'running'].includes(data.state) && now - Date.parse(data.updated_at) > 30000
    const result = { run_id: data.run_id, state: stale ? 'unknown' : data.state,
      started_at: data.started_at, updated_at: data.updated_at }
    if (/^[a-f0-9]{64}$/.test(data.configuration_id) &&
        ['ssid', 'wordlist', 'native-rules', 'wordlist-profile'].includes(data.mode) &&
        typeof data.source_label === 'string' && data.source_label.length <= 128 &&
        (data.rule_label === null || (typeof data.rule_label === 'string' && data.rule_label.length <= 128))) {
      Object.assign(result, { configuration_id: data.configuration_id, mode: data.mode,
        source_label: data.source_label, rule_label: data.rule_label })
    }
    for (const key of ['capture_index', 'capture_total', 'source_words', 'wordlist_position', 'wordlist_size',
      'generated_candidates', 'hashcat_confirmed_candidates', 'checkpointed_candidates']) {
      if (Number.isSafeInteger(data[key]) && data[key] >= 0) result[key] = data[key]
    }
    for (const key of ['capture_name', 'ssid', 'bssid']) {
      if (typeof data[key] === 'string' && data[key].length <= 512) result[key] = data[key]
    }
    if (typeof data.resumed === 'boolean') result.resumed = data.resumed
    if (data.outcomes && typeof data.outcomes === 'object') {
      const outcomes = {}
      for (const key of ['recovered', 'exhausted', 'skipped', 'unusable', 'failed']) {
        if (Number.isSafeInteger(data.outcomes[key]) && data.outcomes[key] >= 0) outcomes[key] = data.outcomes[key]
      }
      result.outcomes = outcomes
    }
    if (data.hashcat && typeof data.hashcat === 'object') {
      const report = {}
      for (const key of ['done', 'total', 'speed', 'eta_seconds']) {
        if (typeof data.hashcat[key] === 'number' && Number.isFinite(data.hashcat[key]) && data.hashcat[key] >= 0) report[key] = data.hashcat[key]
      }
      result.hashcat = report
    }
    return result
  } catch (error) {
    if (['ENOENT', 'ELOOP', 'ENOTDIR'].includes(error.code) || error instanceof SyntaxError) return null
    throw error
  } finally {
    await file?.close()
  }
}

export async function readBatchStatus(root, now = Date.now()) {
  const directory = join(resolve(root), '.pwnabase')
  return await safeDirectory(directory) ? readStatusFile(join(directory, 'batch-status.json'), now) : null
}

export async function readBatchConfigurations(root, now = Date.now()) {
  const runtime = join(resolve(root), '.pwnabase')
  const directory = join(runtime, 'batch-runs')
  if (!await safeDirectory(runtime) || !await safeDirectory(directory)) return []
  const entries = await readdir(directory, { withFileTypes: true })
  const runs = []
  for (const entry of entries) {
    if (!entry.isFile() || !/^[a-f0-9]{32}\.json$/.test(entry.name)) continue
    const status = await readStatusFile(join(directory, entry.name), now)
    if (status?.configuration_id && entry.name === status.run_id + '.json') runs.push(status)
  }
  runs.sort((a, b) => a.started_at.localeCompare(b.started_at) || a.run_id.localeCompare(b.run_id))
  const byIdentity = new Map()
  const nameCounts = new Map()
  const usedNames = new Set()
  for (const run of runs) {
    let group = byIdentity.get(run.configuration_id)
    if (!group) {
      const base = run.rule_label ? `${run.source_label} · ${run.rule_label}` : run.source_label
      let count = (nameCounts.get(base) || 0) + 1
      let label = count === 1 ? base : `${base} ${count}`
      while (usedNames.has(label)) { count++; label = `${base} ${count}` }
      nameCounts.set(base, count)
      usedNames.add(label)
      group = { id: run.configuration_id, label, latest: run }
      byIdentity.set(run.configuration_id, group)
    }
    group.latest = run
  }
  return [...byIdentity.values()]
}
