import { lstat, open } from 'node:fs/promises'
import { constants } from 'node:fs'
import { join, resolve } from 'node:path'

export async function readBatchStatus(root, now = Date.now()) {
  const directory = join(resolve(root), '.pwnabase')
  let file
  try {
    const metadata = await lstat(directory)
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) return null
    file = await open(join(directory, 'batch-status.json'), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    const info = await file.stat()
    if (!info.isFile() || info.size > 65536) return null
    const data = JSON.parse(await file.readFile('utf8'))
    if (!data || data.schema_version !== 1 || !/^[a-f0-9]{32}$/.test(data.run_id) ||
        !['starting', 'running', 'completed', 'interrupted', 'failed'].includes(data.state) ||
        typeof data.started_at !== 'string' || typeof data.updated_at !== 'string' ||
        !Number.isFinite(Date.parse(data.started_at)) || !Number.isFinite(Date.parse(data.updated_at))) return null
    const stale = ['starting', 'running'].includes(data.state) && now - Date.parse(data.updated_at) > 30000
    return { run_id: data.run_id, state: stale ? 'unknown' : data.state,
      started_at: data.started_at, updated_at: data.updated_at }
  } catch (error) {
    if (['ENOENT', 'ELOOP', 'ENOTDIR'].includes(error.code) || error instanceof SyntaxError) return null
    throw error
  } finally {
    await file?.close()
  }
}
