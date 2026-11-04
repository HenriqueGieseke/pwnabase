import { readBatchStatus } from '../utils/batch-status.mjs'

export default defineEventHandler(async event => {
  setHeader(event, 'Cache-Control', 'no-store')
  return { status: await readBatchStatus(useRuntimeConfig(event).dataRoot) }
})
