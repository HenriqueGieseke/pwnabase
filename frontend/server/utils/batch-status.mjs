import { lstat, open, readdir } from 'node:fs/promises'
import { constants } from 'node:fs'
import { join, resolve } from 'node:path'

async function safeDirectory(directory) {
  try { const info = await lstat(directory); return info.isDirectory() && !info.isSymbolicLink() }
  catch (error) { if (['ENOENT', 'ENOTDIR'].includes(error.code)) return false; throw error }
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
    if (typeof data.resumed_any === 'boolean') result.resumed_any = data.resumed_any
    if (typeof data.ended_at === 'string' && Number.isFinite(Date.parse(data.ended_at))) result.ended_at = data.ended_at
    if (data.execution_candidates && typeof data.execution_candidates === 'object') {
      const totals = {}
      for (const key of ['generated', 'confirmed', 'checkpointed']) {
        if (Number.isSafeInteger(data.execution_candidates[key]) && data.execution_candidates[key] >= 0) totals[key] = data.execution_candidates[key]
      }
      result.execution_candidates = totals
    }
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

async function readRuns(root, now) {
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
  return runs
}

async function readIndexPage(root, configuration, before, now, limit = 20) {
  const runtime = join(resolve(root), '.pwnabase')
  const directory = join(runtime, 'batch-index')
  const empty = { runs: [], before: null }
  if (!await safeDirectory(runtime) || !await safeDirectory(directory)) return before === null ? empty : { ...empty, reset: true }
  let file
  try {
    file = await open(join(directory, `${configuration}.idx`), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    const info = await file.stat()
    if (!info.isFile()) return empty
    const size = Math.floor(info.size / 33) * 33
    const [offset, anchor] = before === null ? [null, null] : before.split(':')
    const end = before === null ? size : Number(offset)
    if (!Number.isSafeInteger(end) || end < 0 || end > size || end % 33) return { ...empty, reset: true }
    if (anchor) {
      const check = Buffer.alloc(32)
      const { bytesRead } = await file.read(check, 0, 32, end)
      if (bytesRead !== 32 || check.toString('ascii') !== anchor) return { ...empty, reset: true }
    }
    const start = Math.max(0, end - limit * 33)
    const bytes = Buffer.alloc(end - start)
    const { bytesRead } = await file.read(bytes, 0, bytes.length, start)
    if (bytesRead !== bytes.length) return empty
    const runs = []
    const runsDirectory = join(runtime, 'batch-runs')
    if (!await safeDirectory(runsDirectory)) return empty
    for (let offset = bytes.length - 33; offset >= 0; offset -= 33) {
      const id = bytes.subarray(offset, offset + 32).toString('ascii')
      if (!/^[a-f0-9]{32}$/.test(id)) continue
      const run = await readStatusFile(join(runsDirectory, `${id}.json`), now)
      if (run?.run_id === id && run.configuration_id === configuration) runs.push({ ...run, index_position: start + offset })
    }
    const firstId = bytes.subarray(0, 32).toString('ascii')
    return { runs, before: start > 0 && /^[a-f0-9]{32}$/.test(firstId) ? `${start}:${firstId}` : null }
  } catch (error) {
    if (['ENOENT', 'ELOOP', 'ENOTDIR'].includes(error.code)) return before === null ? empty : { ...empty, reset: true }
    throw error
  } finally { await file?.close() }
}

async function indexedConfigurations(root, now) {
  const runtime = join(resolve(root), '.pwnabase')
  const directory = join(runtime, 'batch-index')
  if (!await safeDirectory(runtime) || !await safeDirectory(directory) || await indexDirty(runtime)) return null
  const metadata = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (!entry.isFile() || !/^[a-f0-9]{64}\.json$/.test(entry.name)) continue
    let file
    try {
      file = await open(join(directory, entry.name), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
      const info = await file.stat()
      if (!info.isFile() || info.size > 65536) continue
      const item = JSON.parse(await file.readFile('utf8'))
      if (item?.configuration_id !== entry.name.slice(0, -5) || typeof item.source_label !== 'string' || item.source_label.length > 128 ||
          typeof item.started_at !== 'string' || !Number.isFinite(Date.parse(item.started_at)) ||
          (item.rule_label !== null && (typeof item.rule_label !== 'string' || item.rule_label.length > 128))) continue
      const latest = (await readIndexPage(root, item.configuration_id, null, now)).runs[0]
      metadata.push({ ...item, latest: latest || { state: 'unknown', started_at: item.started_at, configuration_id: item.configuration_id } })
    } catch (error) {
      if (!['ENOENT', 'ELOOP', 'ENOTDIR'].includes(error.code) && !(error instanceof SyntaxError)) throw error
    } finally { await file?.close() }
  }
  metadata.sort((a, b) => a.started_at.localeCompare(b.started_at) || a.configuration_id.localeCompare(b.configuration_id))
  const counts = new Map(), used = new Set()
  return metadata.map(item => {
    const base = item.rule_label ? `${item.source_label} · ${item.rule_label}` : item.source_label
    let n = (counts.get(base) || 0) + 1
    let label = n === 1 ? base : `${base} ${n}`
    while (used.has(label)) { n++; label = `${base} ${n}` }
    counts.set(base, n); used.add(label)
    return { id: item.configuration_id, label, latest: item.latest }
  })
}

async function indexDirty(runtime) {
  try { await lstat(join(runtime, 'batch-index-dirty')); return true }
  catch (error) { if (error.code === 'ENOENT') return false; throw error }
}

export async function readBatchConfigurations(root, now = Date.now()) {
  const indexed = await indexedConfigurations(root, now)
  if (indexed !== null) return indexed
  const runs = await readRuns(root, now)
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

async function historySize(root) {
  const runtime = join(resolve(root), '.pwnabase')
  if (!await safeDirectory(runtime)) return 0
  let total = 0
  for (const [name, pattern] of [['batch-runs', /^[a-f0-9]{32}\.json$/],
    ['batch-events', /^[a-f0-9]{32}\.jsonl$/]]) {
    const directory = join(runtime, name)
    if (!await safeDirectory(directory)) continue
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (!entry.isFile() || !pattern.test(entry.name)) continue
      try {
        const info = await lstat(join(directory, entry.name))
        if (info.isFile() && !info.isSymbolicLink()) total += info.size
      } catch (error) { if (error.code !== 'ENOENT') throw error }
    }
  }
  return total
}

async function indexedHistorySize(root) {
  const runtime = join(resolve(root), '.pwnabase')
  const directory = join(runtime, 'batch-index')
  const runDirectory = join(runtime, 'batch-runs'), eventDirectory = join(runtime, 'batch-events')
  const hasRuns = await safeDirectory(runDirectory), hasEvents = await safeDirectory(eventDirectory)
  let total = 0
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (!entry.isFile() || !/^[a-f0-9]{64}\.idx$/.test(entry.name)) continue
    try {
      const info = await lstat(join(directory, entry.name))
      if (!info.isFile() || info.isSymbolicLink()) continue
      const count = Math.floor(info.size / 33)
      total += info.size
      let sample = 0, sampled = 0
      // Sample the oldest, middle and newest records, rather than assuming a
      // newly started run is representative of all historical logs.
      for (const position of new Set([0, Math.floor((count - 1) / 2), count - 1])) {
        if (position < 0) continue
        const run = (await readIndexPage(root, entry.name.slice(0, -4), String((position + 1) * 33), Date.now(), 1)).runs[0]
        if (!run) continue
        sampled++
        for (const [allowed, path] of [[hasRuns, join(runDirectory, run.run_id + '.json')],
          [hasEvents, join(eventDirectory, run.run_id + '.jsonl')]]) {
          if (!allowed) continue
          try { const file = await lstat(path); if (file.isFile() && !file.isSymbolicLink()) sample += file.size }
          catch (error) { if (error.code !== 'ENOENT') throw error }
        }
      }
      if (sampled) total += Math.round(sample / sampled * count)
    } catch (error) { if (error.code !== 'ENOENT') throw error }
  }
  return total
}

export async function readBatchHistory(root, configuration, before = null, now = Date.now()) {
  const empty = { runs: [], before: null, storage_bytes: 0 }
  if (typeof configuration !== 'string' || !/^[a-f0-9]{64}$/.test(configuration) || typeof before !== 'string' && before !== null) return empty
  const runtime = join(resolve(root), '.pwnabase')
  if (await safeDirectory(runtime) && await safeDirectory(join(runtime, 'batch-index')) && !await indexDirty(runtime)) {
    if (before !== null && !/^\d{1,15}:[a-f0-9]{32}$/.test(before)) return { ...empty, reset: true }
    const page = await readIndexPage(root, configuration, before, now)
    if (await indexDirty(runtime)) return { ...empty, reset: true }
    return { ...page, storage_bytes: await indexedHistorySize(root) }
  }
  if (before !== null && !/^[a-f0-9]{32}$/.test(before)) return { ...empty, reset: true }
  const runs = (await readRuns(root, now)).filter(run => run.configuration_id === configuration).reverse()
  const position = before === null ? 0 : runs.findIndex(run => run.run_id === before) + 1
  if (before !== null && position === 0) return { ...empty, reset: true }
  const page = runs.slice(position, position + 20)
  return { runs: page, before: position + page.length < runs.length ? page.at(-1).run_id : null,
    storage_bytes: await historySize(root) }
}
