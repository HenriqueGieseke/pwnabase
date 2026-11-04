import { readBatchEvents } from '../utils/batch-events.mjs'

export default defineEventHandler(async event => {
  const query = getQuery(event)
  const run = String(query.run || '')
  if (!/^[a-f0-9]{32}$/.test(run)) throw createError({ statusCode: 400, statusMessage: 'Invalid run' })
  if (query.before !== undefined && !/^\d{1,15}$/.test(String(query.before))) throw createError({ statusCode: 400, statusMessage: 'Invalid cursor' })
  const before = query.before === undefined ? null : Number(query.before)
  setHeader(event, 'Cache-Control', 'no-store')
  return readBatchEvents(useRuntimeConfig(event).dataRoot, run, before)
})
