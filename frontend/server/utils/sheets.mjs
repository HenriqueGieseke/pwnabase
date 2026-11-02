import { readdir, stat, readFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { basename, join, resolve } from 'node:path'

export const SHEETS = ['complete', 'exhausted', 'no-usable-handshake', 'tool-error', 'rules']
const MAX_BYTES = 5 * 1024 * 1024
const sortable = new Set(['name', 'status', 'bssid', 'password', 'kind', 'wordlist', 'ruleSet', 'updated', 'filename'])
async function entries(directory) {
  try { return await readdir(directory, { withFileTypes: true }) }
  catch (error) { if (error.code === 'ENOENT') return []; throw error }
}
function scalar(value, fallback = '') { return typeof value === 'string' ? value : fallback }

export function createStore(root) {
  root = resolve(root)
  const cache = new Map()
  // Directories are explicit; no arbitrary project browsing or symlink following.
  async function discover(tab) {
    if (!SHEETS.includes(tab)) throw new Error('Unknown sheet')
    const top = (await entries(root)).find(entry => entry.name === tab && entry.isDirectory())
    if (!top) return []
    const found = []
    for (const item of await entries(join(root, tab))) {
      if (item.isFile() && item.name.endsWith('.json')) found.push(item.name)
      if (tab === 'exhausted' && item.isDirectory()) {
        for (const child of await entries(join(root, tab, item.name))) {
          if (child.isFile() && child.name.endsWith('.json')) found.push(join(item.name, child.name))
        }
      }
    }
    return found.sort()
  }
  async function scan(tab) {
    const files = await discover(tab)
    const current = new Set()
    const results = []
    // Sequential metadata reads avoid an I/O burst while recovery is running.
    for (const filename of files) {
      const key = `${tab}/${filename}`
      const id = createHash('sha256').update(key).digest('hex')
      current.add(key)
      try {
        const path = join(root, key)
        const metadata = await stat(path)
        const stamp = `${metadata.mtimeMs}:${metadata.ctimeMs}:${metadata.size}:${metadata.ino}`
        let cached = cache.get(key)
        if (!cached || cached.stamp !== stamp) {
          let data, problem
          try {
            if (metadata.size > MAX_BYTES) throw new Error('File exceeds the 5 MB viewer limit')
            data = JSON.parse(await readFile(path, 'utf8'))
            if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Expected a JSON object')
          } catch (error) {
            if (error.code === 'ENOENT') continue
            problem = error.message.startsWith('File exceeds') ? error.message : 'Cannot parse this file as a JSON object'
          }
          const record = data?.record || {}
          const row = {
            id, filename, name: scalar(record.ssid, scalar(data?.id,
              basename(scalar(data?.sources?.[0]?.path, filename)))),
            status: problem ? 'invalid_json' : scalar(data?.status, tab === 'rules' ? 'catalog' : 'unknown'),
            bssid: scalar(record.bssid), password: scalar(data?.password),
            passwordHex: scalar(data?.password_hex), kind: scalar(record.kind),
            wordlist: scalar(data?.wordlist?.label, tab === 'exhausted' && filename.includes('/') ? filename.split('/')[0] : ''),
            ruleSet: scalar(data?.rules?.id),
            ruleCount: Array.isArray(data?.rules) ? data.rules.length : null,
            updated: scalar(data?.updated_at, metadata.mtime.toISOString()),
            sourceCount: Array.isArray(data?.sources) ? data.sources.length : 0,
            error: problem || scalar(data?.error),
          }
          cached = { stamp, row, data, problem }
          cache.set(key, cached)
        }
        results.push(cached)
      } catch (error) {
        if (error.code === 'ENOENT') continue
        results.push({ row: { id, filename, name: filename, status: 'read_error', error: 'File could not be read', updated: '' }, problem: 'File could not be read' })
      }
    }
    for (const key of cache.keys()) if (key.startsWith(tab + '/') && !current.has(key)) cache.delete(key)
    return results
  }
  return {
    async sheet(tab, options = {}) {
      const records = await scan(tab)
      const words = [...new Set(records.map(({ row }) => row.wordlist).filter(Boolean))].sort()
      const query = String(options.search || '').toLowerCase().slice(0, 500)
      const wordlist = String(options.wordlist || '')
      const filtered = records.map(({ row }) => row).filter(row =>
        (!wordlist || row.wordlist === wordlist) &&
        (!query || Object.values(row).some(value => typeof value === 'string' && value.toLowerCase().includes(query))))
      const sort = sortable.has(options.sort) ? options.sort : 'updated'
      const direction = options.direction === 'asc' ? 1 : -1
      filtered.sort((a, b) => {
        const left = a[sort] || '', right = b[sort] || ''
        if (!left && right) return 1
        if (left && !right) return -1
        return direction * String(left).localeCompare(String(right), undefined, { numeric: true }) || a.id.localeCompare(b.id)
      })
      const pages = Math.max(1, Math.ceil(filtered.length / 50))
      const page = Math.min(pages, Math.max(1, Number.parseInt(options.page) || 1))
      return { tabs: SHEETS, rows: filtered.slice((page - 1) * 50, page * 50), total: records.length,
        filtered: filtered.length, pages, page, wordlists: words, refreshedAt: new Date().toISOString() }
    },
    async detail(tab, id) {
      const match = (await scan(tab)).find(item => item.row.id === id)
      return match ? { row: match.row, data: match.data ?? null, problem: match.problem ?? null } : null
    },
  }
}
