import { readBatchHistory } from '../utils/batch-status.mjs'

export default defineEventHandler(async event => {
  const query = getQuery(event)
  const configuration = String(query.configuration || '')
  const before = query.before === undefined ? null : String(query.before)
  if (!/^[a-f0-9]{64}$/.test(configuration) || (before !== null && !/^(?:[a-f0-9]{32}|\d{1,15}:[a-f0-9]{32})$/.test(before))) {
    throw createError({ statusCode: 400, statusMessage: 'Invalid history request' })
  }
  setHeader(event, 'Cache-Control', 'no-store')
  return readBatchHistory(useRuntimeConfig(event).dataRoot, configuration, before)
})
