export default defineEventHandler(event => {
  const url = getRequestURL(event)
  if (!['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname)) {
    throw createError({ statusCode: 403, statusMessage: 'Local access only' })
  }
  if (url.pathname.startsWith('/api/')) {
    const origin = getHeader(event, 'origin')
    if (origin && origin !== url.origin) throw createError({ statusCode: 403, statusMessage: 'Origin not allowed' })
  }
})
