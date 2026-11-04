// Keep refresh and backward pagination serialized so their cursors remain contiguous.
export function createEventQueue() {
  let current = null
  let olderRunning = false
  return {
    refresh(task) {
      if (current || olderRunning) return current
      current = Promise.resolve().then(task).finally(() => { current = null })
      return current
    },
    async older(task) {
      if (olderRunning) return
      olderRunning = true
      try {
        if (current) await current
        return await task()
      } finally { olderRunning = false }
    },
  }
}
