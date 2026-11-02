import { SHEETS, createStore } from '../utils/sheets.mjs'

let store

export default defineEventHandler(async event => {
  store ||= createStore(useRuntimeConfig(event).dataRoot)
  const query = getQuery(event)
  const tab = String(query.tab || 'complete')
  if (!SHEETS.includes(tab)) throw createError({ statusCode: 400, statusMessage: 'Unknown sheet' })
  setHeader(event, 'Cache-Control', 'no-store')
  if (query.id) {
    const detail = await store.detail(tab, String(query.id))
    if (!detail) throw createError({ statusCode: 404, statusMessage: 'Result no longer exists' })
    return detail
  }
  return store.sheet(tab, query)
})
