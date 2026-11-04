import { lstat, open } from 'node:fs/promises'
import { constants } from 'node:fs'
import { join, resolve } from 'node:path'

const kinds = new Set(['batch_started', 'batch_running', 'batch_completed', 'batch_interrupted',
  'batch_failed', 'capture_started', 'capture_unusable', 'capture_skipped', 'record_recovered',
  'record_exhausted', 'record_skipped', 'record_failed', 'capture_failed', 'checkpoint_saved'])

export async function readBatchEvents(root, run, before = null) {
  const empty = { events: [], before: null }
  if (typeof run !== 'string' || !/^[a-f0-9]{32}$/.test(run)) return empty
  if (before !== null && (!Number.isSafeInteger(before) || before < 0)) return empty
  const runtime = join(resolve(root), '.pwnabase')
  const directory = join(runtime, 'batch-events')
  let file
  try {
    for (const path of [runtime, directory]) {
      const info = await lstat(path)
      if (!info.isDirectory() || info.isSymbolicLink()) return empty
    }
    file = await open(join(directory, `${run}.jsonl`), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    const info = await file.stat()
    if (!info.isFile()) return empty
    const end = before === null ? info.size : Math.min(before, info.size)
    if (!end) return empty
    let position = end, start = 0, delimiters = 0
    while (position > 0 && end - position < 2 * 1024 * 1024) {
      const length = Math.min(16384, position, 2 * 1024 * 1024 - (end - position))
      const block = Buffer.alloc(length)
      const { bytesRead } = await file.read(block, 0, length, position - length)
      if (bytesRead !== length) return empty
      for (let i = length - 1; i >= 0; i--) {
        const offset = position - length + i
        if (block[i] === 10 && offset !== end - 1 && ++delimiters === 200) { start = offset + 1; break }
      }
      position -= length
      if (delimiters === 200) break
      start = position
    }
    const bytes = Buffer.alloc(end - start)
    const { bytesRead } = await file.read(bytes, 0, bytes.length, start)
    if (bytesRead !== bytes.length) return empty
    const events = []
    let offset = 0
    while (offset < bytes.length) {
      const newline = bytes.indexOf(10, offset)
      if (newline < 0) break
      try {
        const value = JSON.parse(bytes.subarray(offset, newline).toString('utf8'))
        if (value && kinds.has(value.kind) && typeof value.at === 'string' && Number.isFinite(Date.parse(value.at))) {
          const event = { id: start + offset, kind: value.kind, at: value.at }
          if (['tool', 'input', 'filesystem', 'unknown'].includes(value.category)) event.category = value.category
          for (const key of ['capture_name', 'ssid', 'bssid']) {
            if (typeof value[key] === 'string' && value[key].length <= 512) event[key] = value[key]
          }
          events.push(event)
        }
      } catch { /* Ignore incomplete or malformed events. */ }
      offset = newline + 1
    }
    return { events, before: start > 0 ? start : null }
  } catch (error) {
    if (['ENOENT', 'ELOOP', 'ENOTDIR'].includes(error.code)) return empty
    throw error
  } finally { await file?.close() }
}
