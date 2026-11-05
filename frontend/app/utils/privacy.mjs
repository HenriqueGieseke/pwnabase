export const PREFERENCES_KEY = 'pwnabase.viewer.preferences.v1'
const HIDDEN = '••••••'

export function loadPreferences(storage, tabs) {
  const defaults = { hidePasswords: true, hideSsids: true, duplicates: Object.fromEntries(tabs.map(tab => [tab, false])) }
  try {
    const value = JSON.parse(storage.getItem(PREFERENCES_KEY))
    if (!value || typeof value !== 'object' || Array.isArray(value)) return defaults
    if (typeof value.hidePasswords === 'boolean') defaults.hidePasswords = value.hidePasswords
    if (typeof value.hideSsids === 'boolean') defaults.hideSsids = value.hideSsids
    if (value.duplicates && typeof value.duplicates === 'object' && !Array.isArray(value.duplicates)) {
      for (const tab of tabs) if (typeof value.duplicates[tab] === 'boolean') defaults.duplicates[tab] = value.duplicates[tab]
    }
  } catch { /* Invalid or unavailable storage uses private defaults. */ }
  return defaults
}

export function savePreferences(storage, hidePasswords, views, tabs, hideSsids = true) {
  try {
    const duplicates = Object.fromEntries(tabs.map(tab => [tab, Boolean(views[tab].hideDuplicates)]))
    storage.setItem(PREFERENCES_KEY, JSON.stringify({ hidePasswords: Boolean(hidePasswords), hideSsids: Boolean(hideSsids), duplicates }))
  } catch { /* Browsing remains usable if storage is unavailable. */ }
}

export function redactDetails(value, hidePasswords, hideSsids) {
  if (Array.isArray(value)) return value.map(entry => redactDetails(entry, hidePasswords, hideSsids))
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(Object.entries(value).map(([key, entry]) => {
    const secret = hidePasswords && /^password(?:_?hex)?$/i.test(key)
    const network = hideSsids && /^(?:ssid(?:_?hex)?|hashcat_record|capture_name|path|filename|error)$/i.test(key)
    return [key, (secret || network) && entry !== null ? HIDDEN : redactDetails(entry, hidePasswords, hideSsids)]
  }))
}

export function redactPasswords(value) { return redactDetails(value, true, false) }

export { HIDDEN }
