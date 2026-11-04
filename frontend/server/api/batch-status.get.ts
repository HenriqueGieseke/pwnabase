import { readBatchStatus, readBatchConfigurations } from '../utils/batch-status.mjs'

export default defineEventHandler(async event => {
  setHeader(event, 'Cache-Control', 'no-store')
  const root = useRuntimeConfig(event).dataRoot
  return { status: await readBatchStatus(root), configurations: await readBatchConfigurations(root) }
})
