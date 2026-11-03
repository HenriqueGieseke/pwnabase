<script setup>
const tabs = ['complete', 'exhausted', 'no-usable-handshake', 'tool-error', 'rules']
const titles = { complete: 'Complete', exhausted: 'Exhausted', 'no-usable-handshake': 'No usable handshake', 'tool-error': 'Tool errors', rules: 'Rules' }
const descriptions = {
  complete: 'Verified recoveries, with the source and experiment that produced each result.',
  exhausted: 'Finished wordlist and SSID-derived experiments, including attempts with no eligible candidates. These are historical attempts.',
  'no-usable-handshake': 'Readable captures that did not yield usable authentication material.',
  'tool-error': 'Capture and record failures. The recovery batch retries these on its next run.',
  rules: 'Mutation catalogs. Open a file to explore its individual transformation rules.',
}
const active = ref('complete')
const views = reactive(Object.fromEntries(tabs.map(tab => [tab, { search: '', hideDuplicates: false, wordlist: '', sort: 'updated', direction: 'desc', page: 1, selected: null, scroll: 0 }])))
const view = computed(() => views[active.value])
const sheet = ref(null)
const detail = ref(null)
const detailError = ref('')
const error = ref('')
const busy = ref(false)
const refreshed = ref('')
const grid = ref(null)
const detailOpen = ref(false)
let restoringScroll = false
let timer, debounce, controller, request = 0

const columns = computed(() => {
  const common = [{ key: 'name', label: active.value === 'rules' ? 'Catalog' : active.value === 'no-usable-handshake' || active.value === 'tool-error' ? 'Capture / result' : 'Network / SSID' }]
  if (['complete', 'exhausted'].includes(active.value)) {
    common.push({ key: 'bssid', label: 'BSSID' })
    if (active.value === 'complete') common.push({ key: 'password', label: 'Password' })
    else common.push({ key: 'status', label: 'Outcome' })
    common.push({ key: 'kind', label: 'Record type' }, { key: 'wordlist', label: 'Candidate source' }, { key: 'ruleSet', label: 'Rule set' })
  } else if (active.value === 'rules') {
    common.push({ key: 'filename', label: 'File' }, { key: 'ruleCount', label: 'Rules', sortable: false })
  } else {
    common.push({ key: 'status', label: 'Outcome' }, { key: 'filename', label: 'Result file' })
    if (active.value === 'tool-error') common.push({ key: 'error', label: 'Diagnostic', sortable: false })
  }
  common.push({ key: 'updated', label: 'Updated' })
  return common
})
function date(value) {
  if (!value) return '—'
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}
function cell(row, key) {
  if (key === 'updated') return date(row.updated)
  if (key === 'ruleSet') return row.ruleSet || (row.candidateSource === 'ssid' ? 'SSID profile' : 'Plain wordlist')
  if (key === 'kind') return row.kind?.toUpperCase() || '—'
  if (key === 'password' && !row.password && row.passwordHex) return `HEX: ${row.passwordHex}`
  return row[key] ?? '—'
}
function switchTab(tab) {
  if (tab === active.value) return
  views[active.value].scroll = grid.value?.scrollTop || 0
  restoringScroll = true
  active.value = tab
  sheet.value = null
  detail.value = null
  detailOpen.value = Boolean(views[tab].selected)
}
function sort(column) {
  if (column.sortable === false) return
  if (view.value.sort === column.key) view.value.direction = view.value.direction === 'asc' ? 'desc' : 'asc'
  else { view.value.sort = column.key; view.value.direction = 'asc' }
  view.value.page = 1
}
async function load(force = false) {
  if (busy.value && !force) return
  controller?.abort()
  controller = new AbortController()
  const signal = controller.signal
  const number = ++request
  const tab = active.value
  busy.value = true
  try {
    const result = await $fetch('/api/sheets', { query: { tab, ...views[tab], selected: undefined, scroll: undefined }, signal, timeout: 10000 })
    if (number !== request) return
    sheet.value = result
    // Server clamps pages if files disappear; preserve the nearest valid page.
    views[tab].page = result.page
    error.value = ''
    refreshed.value = new Date(result.refreshedAt).toLocaleTimeString()
    await nextTick()
    if (grid.value) grid.value.scrollTop = views[tab].scroll
    restoringScroll = false
    if (views[tab].selected && detailOpen.value) await loadDetail(tab, views[tab].selected)
  } catch (cause) {
    if (number === request && !signal.aborted) error.value = 'Could not refresh the sheet. Showing the last available results; retrying automatically.'
  } finally { if (number === request) busy.value = false }
}
async function loadDetail(tab, id) {
  try {
    const result = await $fetch('/api/sheets', { query: { tab, id }, timeout: 10000 })
    if (active.value === tab && view.value.selected === id) { detail.value = result; detailError.value = '' }
  } catch {
    if (active.value === tab && view.value.selected === id) detailError.value = 'This file is no longer available or could not be read.'
  }
}
function select(row) {
  view.value.selected = row.id
  detailOpen.value = true
  detail.value = null
  detailError.value = ''
  loadDetail(active.value, row.id)
}
watch(() => [active.value, view.value.search, view.value.hideDuplicates, view.value.wordlist, view.value.sort, view.value.direction, view.value.page], () => {
  clearTimeout(debounce)
  debounce = setTimeout(() => load(true), 250)
})
onMounted(() => { load(); timer = setInterval(() => load(), 5000) })
onUnmounted(() => { clearTimeout(debounce); clearInterval(timer); controller?.abort() })
const generationFields = computed(() => ['seeds', 'generated', 'duplicates', 'rejected_length', 'eligible', 'non_utf8_seeds', 'valid_utf8', 'source_complete'].filter(key => Object.hasOwn(detail.value?.data?.candidate_generation || {}, key)))
const raw = computed(() => JSON.stringify(detail.value?.data, null, 2))
const ruleObjects = computed(() => Array.isArray(detail.value?.data?.rules) ? detail.value.data.rules.filter(rule => rule && typeof rule === 'object') : [])
</script>

<template>
  <div class="workspace">
    <header class="topbar">
      <div class="brand"><span class="mark" aria-hidden="true">▦</span><div>PWNABASE <span class="brand-label">RESULT WORKSPACE</span></div></div>
      <div class="topbar-status">
        <div class="live"><span class="dot"></span> LIVE SYNC <span>every 5s</span></div>
        <div class="local"><span class="dot"></span> Local files <span class="separator">/</span> Read only</div>
      </div>
    </header>

    <main>
      <section class="sheet-shell" aria-label="Result sheets">
        <div class="sheet-title"><div><span class="sheet-icon" aria-hidden="true">▤</span><h1>{{ titles[active] }}</h1><span class="count">{{ sheet?.total ?? '—' }} files</span></div><span class="file-type">JSON COLLECTION</span></div>
        <p class="sheet-description">{{ descriptions[active] }}</p>
        <div class="toolbar">
          <label class="search"><span aria-hidden="true">⌕</span><input v-model="view.search" type="search" :aria-label="`Search ${titles[active]}`" placeholder="Search this sheet…" @input="view.page = 1"></label>
          <label class="deduplicate"><input v-model="view.hideDuplicates" type="checkbox" @change="view.page = 1"> Hide duplicates</label>
          <label v-if="active === 'exhausted'" class="filter"><span class="sr-only">Candidate source</span><select v-model="view.wordlist" @change="view.page = 1"><option value="">All sources</option><option v-for="wordlist in sheet?.wordlists || []" :key="wordlist">{{ wordlist }}</option></select></label>
          <div class="toolbar-end"><span class="sync" aria-live="polite">{{ busy ? 'Refreshing…' : refreshed ? `Synced ${refreshed}` : 'Connecting…' }}</span><button class="refresh" :disabled="busy" @click="load(true)"><span aria-hidden="true">↻</span> Refresh</button></div>
        </div>
        <div v-if="error" class="notice" role="alert">{{ error }}</div>

        <div class="sheet-body" :class="{ 'has-detail': detailOpen }">
          <div ref="grid" class="grid-scroll" @scroll="!restoringScroll && (view.scroll = $event.target.scrollTop)">
            <table>
              <thead><tr><th class="row-number">#</th><th v-for="column in columns" :key="column.key" :aria-sort="view.sort === column.key ? view.direction === 'asc' ? 'ascending' : 'descending' : 'none'"><button :disabled="column.sortable === false" @click="sort(column)">{{ column.label }} <span v-if="view.sort === column.key">{{ view.direction === 'asc' ? '↑' : '↓' }}</span></button></th></tr></thead>
              <tbody><tr v-for="(row, index) in sheet?.rows || []" :key="row.id" :class="{ selected: view.selected === row.id, 'bad-row': ['invalid_json', 'read_error'].includes(row.status) }" tabindex="0" aria-label="Open result details" @click="select(row)" @keydown.enter="select(row)">
                <td class="row-number">{{ (view.page - 1) * 50 + index + 1 }}</td>
                <td v-for="column in columns" :key="column.key" :class="[column.key, { mono: ['bssid', 'password', 'filename'].includes(column.key) }]" :title="String(cell(row, column.key))"><span v-if="column.key === 'name'" class="row-dot" :class="active"></span><span :class="{ badge: column.key === 'kind' }">{{ cell(row, column.key) || '—' }}</span><span v-if="column.key === 'name' && ['invalid_json', 'read_error'].includes(row.status)" class="invalid">Cannot read JSON</span></td>
              </tr></tbody>
            </table>
            <div v-if="!sheet?.rows.length" class="empty"><span class="empty-icon" aria-hidden="true">▦</span><h3>{{ !sheet && busy ? 'Reading your result files…' : view.search || view.wordlist ? 'No matching results' : 'This sheet is waiting for results' }}</h3><p>{{ view.search || view.wordlist ? 'Try another search or source filter.' : 'New JSON files appear here automatically. Your batch can keep running.' }}</p></div>
          </div>

          <aside v-if="detailOpen" class="details" aria-label="Result details">
            <div class="details-heading"><span>FILE DETAILS</span><button aria-label="Close details" @click="detailOpen = false">×</button></div>
            <template v-if="detail"><h3>{{ detail.row.name }}</h3><p class="detail-filename mono">{{ detail.row.filename }}</p><div class="detail-status">{{ detail.row.status.replaceAll('_', ' ') }}</div>
              <p v-if="detail.problem" class="notice">{{ detail.problem }}</p>
              <dl v-if="detail.data && active !== 'rules'"><template v-for="key in ['bssid', 'kind', 'wordlist', 'ruleSet', 'updated']" :key="key"><dt>{{ { bssid: 'BSSID', kind: 'Record type', wordlist: 'Candidate source', ruleSet: 'Rule set', updated: 'Updated' }[key] }}</dt><dd>{{ cell(detail.row, key) || '—' }}</dd></template><template v-if="active === 'complete'"><dt>Password</dt><dd class="password mono">{{ cell(detail.row, 'password') || '—' }}</dd></template></dl>
              <div v-if="active === 'rules' && detail.data" class="catalog-intro"><p>{{ detail.data.description }}</p><span>{{ ruleObjects.length }} transformation stages / rules</span></div>
              <section v-if="Array.isArray(detail.data?.sources) && detail.data.sources.length" class="source-list"><h4>CAPTURE PROVENANCE · {{ detail.data.sources.length }}</h4><article v-for="(source, index) in detail.data.sources" :key="index"><p>{{ source?.path || 'Unknown source path' }}</p><code v-if="source?.sha256">SHA-256 {{ source.sha256 }}</code></article></section>
              <section v-if="detail.data?.candidate_generation" class="generation"><h4>CANDIDATE GENERATION</h4><dl><template v-for="key in generationFields" :key="key"><dt>{{ key.replaceAll('_', ' ') }}</dt><dd>{{ detail.data.candidate_generation[key] }}</dd></template></dl></section>
              <section v-if="ruleObjects.length" class="rule-list"><h4>TRANSFORMATIONS · {{ ruleObjects.length }}</h4><article v-for="rule in ruleObjects" :key="rule.id"><code>{{ rule.expression || rule.operation }}</code><pre v-if="rule.operation" class="profile-config">{{ JSON.stringify(Object.fromEntries(Object.entries(rule).filter(([key]) => !['id', 'description', 'operation'].includes(key))), null, 2) }}</pre><strong>{{ rule.id }}</strong><p>{{ rule.description }}</p></article></section>
              <details v-if="detail.data" class="raw"><summary>Raw JSON <span>{ }</span></summary><pre>{{ raw }}</pre></details>
            </template>
            <p v-else-if="!detailError" class="muted">Reading file…</p><p v-if="detailError" class="notice">{{ detailError }}</p>
          </aside>
        </div>

        <div class="sheet-footer"><span>{{ sheet?.filtered ?? 0 }} {{ sheet?.filtered === 1 ? 'row' : 'rows' }}<template v-if="sheet && sheet.filtered !== sheet.total"> of {{ sheet.total }}</template><span class="footer-divider">·</span>50 per page<template v-if="sheet?.duplicatesHidden"> · {{ sheet.duplicatesHidden }} duplicates hidden</template></span><div class="pagination"><button :disabled="!sheet || view.page <= 1" aria-label="Previous page" @click="view.page--">←</button><span>Page {{ view.page }} of {{ sheet?.pages || 1 }}</span><button :disabled="!sheet || view.page >= sheet.pages" aria-label="Next page" @click="view.page++">→</button></div></div>
        <nav class="tabs" aria-label="Directory sheets"><button v-for="tab in tabs" :key="tab" :aria-current="active === tab ? 'page' : undefined" :class="{ active: active === tab }" @click="switchTab(tab)"><span aria-hidden="true">▤</span>{{ titles[tab] }}</button><span class="tab-spacer"></span><span class="tabs-caption">LOCAL WORKBOOK</span></nav>
      </section>
      <footer class="page-footer"><span><span class="dot"></span> Changes are read from disk. Recovery runs independently.</span><span>PWNABASE / 01</span></footer>
    </main>
  </div>
</template>

<style>
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#101312;color:#e6eae7;font-synthesis:none}*{box-sizing:border-box}body{margin:0}button,input,select{font:inherit}button{cursor:pointer;color:inherit}button:disabled{cursor:default;opacity:.4}button:focus-visible,input:focus-visible,select:focus-visible,tr:focus-visible{outline:2px solid #91d6ac;outline-offset:-2px}button{background:none;border:0}.topbar{min-height:76px;gap:16px;flex-wrap:wrap;border-bottom:1px solid #2a302c;display:flex;align-items:center;justify-content:space-between;padding:0 40px;background:#141816}.brand{display:flex;gap:13px;align-items:center;font-size:15px;font-weight:750;letter-spacing:2px}.mark{display:grid;place-items:center;font-size:29px;line-height:1;width:35px;height:35px;background:#afd8b7;color:#14251b;border-radius:6px}.brand-label{font-weight:450;color:#87928b;letter-spacing:1.4px;font-size:10px;border-left:1px solid #3a443d;margin-left:20px;padding-left:20px}.topbar-status{display:flex;align-items:center;justify-content:flex-end;gap:20px;flex-wrap:wrap;margin-left:auto}.local{display:flex;align-items:center;gap:9px;color:#a1aaa4;font-size:12px}.dot{display:inline-block;width:6px;height:6px;background:#a2d5ae;border-radius:50%;flex-shrink:0}.separator{color:#515e55;margin:0 6px}main{max-width:1900px;padding:24px 40px;margin:auto}.live{display:flex;align-items:center;gap:8px;color:#b8c7bd;font-size:10px;letter-spacing:1px;background:#1c2720;border:1px solid #314136;padding:10px 13px;border-radius:5px}.live>span:last-child{color:#859b8c;letter-spacing:0;margin-left:7px}.sheet-shell{background:#171c19;border:1px solid #343e37;border-radius:8px;overflow:hidden;box-shadow:0 15px 55px #0002}.sheet-title{padding:24px 24px 0;display:flex;align-items:center;justify-content:space-between}.sheet-title>div{display:flex;align-items:center;gap:10px}.sheet-icon{color:#a8ccb1;font-size:22px}.sheet-title h1{font-size:18px;font-weight:550;margin:0}.count{font-size:11px;color:#aabbb0;background:#26352b;border:1px solid #34463b;border-radius:4px;padding:3px 8px;margin-left:6px}.file-type{font-size:9px;letter-spacing:1.5px;color:#697d6f}.sheet-description{font-size:12px;color:#95a198;margin:10px 24px 23px}.toolbar{display:flex;align-items:center;gap:12px;border-top:1px solid #2c362f;border-bottom:1px solid #343e37;padding:14px 20px;background:#1b211d}.search{display:flex;align-items:center;gap:10px;border:1px solid #39433d;background:#141a16;border-radius:5px;width:310px;padding:8px 12px}.search>span{font-size:21px;color:#91a497;line-height:1}.search input{color:#e1e8e3;font-size:12px;width:100%;outline:0;background:none;border:none;min-width:0}.search input::placeholder{color:#7e9184}.search kbd{font-size:10px;border:1px solid #37473c;border-radius:3px;padding:1px 5px;color:#7c8b81}.deduplicate{display:flex;align-items:center;gap:7px;white-space:nowrap;font-size:11px;color:#b5c6bb;cursor:pointer}.deduplicate input{accent-color:#a8d9b7;width:15px;height:15px;margin:0}.filter select{background:#1c261f;border:1px solid #3a493f;border-radius:5px;padding:8px 10px;font-size:12px;color:#bdc9c0;max-width:190px}.toolbar-end{display:flex;align-items:center;gap:18px;margin-left:auto}.sync{font-size:10px;color:#7e9285}.refresh{display:flex;align-items:center;gap:7px;font-size:11px;border:1px solid #445449;padding:8px 12px;border-radius:5px;background:#26322a}.refresh span{font-size:16px}.sheet-body{display:flex;min-height:430px;height:clamp(430px,56vh,820px)}.grid-scroll{overflow:auto;flex:1;min-width:0;scrollbar-color:#415247 #1b211d;scrollbar-width:thin}table{width:100%;border-collapse:separate;border-spacing:0;font-size:12px;white-space:nowrap}th{position:sticky;top:0;background:#212923;z-index:1;border-bottom:1px solid #3e4b41;text-align:left;color:#a0b0a5;font-weight:450;height:39px}th button{font-size:10px;font-weight:550;width:100%;height:39px;text-align:left;padding:0 18px}th button span{color:#b5dec1;margin-left:6px}td{height:64px;padding:0 18px;border-right:1px solid #26312a;border-bottom:1px solid #2a352d;max-width:340px;overflow:hidden;text-overflow:ellipsis}tbody tr{cursor:pointer;background:#171e19}tbody tr:nth-child(even){background:#1a221c}tbody tr:hover{background:#243229}tbody tr.selected{background:#293d30}tbody tr.selected td:first-child{box-shadow:inset 3px 0 #a8d9b7}.row-number{width:46px;min-width:46px;padding:0 10px;text-align:center;color:#6c8273;background:#1b251e;font-size:10px;border-right:1px solid #344039;font-variant-numeric:tabular-nums}td.name{font-weight:550;color:#e1e9e3;min-width:190px}td.updated{font-size:11px;color:#91a497;min-width:155px}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11px}td.password{color:#c5e6bf;min-width:170px}.row-dot{display:inline-block;width:6px;height:6px;border-radius:2px;background:#9acd9b;margin-right:10px}.row-dot.exhausted{background:#c1aa72}.row-dot.tool-error{background:#d78f86}.row-dot.no-usable-handshake{background:#819caa}.row-dot.rules{background:#b0a3d4}.badge{color:#a2b6aa;border:1px solid #3b4e41;background:#223228;border-radius:4px;padding:4px 6px;font-size:9px;letter-spacing:.5px}.invalid{font-size:10px;color:#e6ac9c;margin-left:10px}.bad-row td{color:#dcb3a8}.empty{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:340px;padding:35px;text-align:center}.empty-icon{font-size:38px;color:#668473;border:1px dashed #435d4b;border-radius:12px;width:80px;height:80px;display:grid;place-items:center;margin-bottom:10px}.empty h3{font-size:16px;font-weight:500}.empty p{font-size:12px;color:#8ea095;max-width:390px;line-height:1.7}.sheet-footer{border-top:1px solid #3c4940;padding:12px 20px;display:flex;align-items:center;justify-content:space-between;font-size:10px;color:#8d9e93;background:#1a231d}.footer-divider{margin:0 10px;color:#536d5c}.pagination{display:flex;gap:14px;align-items:center}.pagination button{border:1px solid #384d40;background:#223329;border-radius:3px;padding:3px 9px;font-size:15px}.tabs{display:flex;align-items:stretch;background:#111913;border-top:1px solid #34463b;overflow-x:auto;min-height:48px}.tabs button{display:flex;align-items:center;gap:8px;padding:0 20px;font-size:11px;color:#94a69a;border-right:1px solid #2a3a2e;white-space:nowrap;border-top:2px solid transparent}.tabs button.active{background:#2b4032;border-top-color:#aedebc;color:#e1f3e6}.tabs button:hover{background:#26392d}.tabs button span{font-size:14px;color:#91b29c}.tab-spacer{flex:1}.tabs-caption{font-size:8px;letter-spacing:1.7px;color:#536e5d;padding:18px 20px;white-space:nowrap}.page-footer{display:flex;justify-content:space-between;color:#6f8678;font-size:10px;margin-top:18px;gap:20px}.page-footer>span:first-child{display:flex;gap:8px;align-items:center}.page-footer>span:last-child{letter-spacing:1.5px;font-size:9px}.page-footer .dot{width:4px;height:4px;background:#6b977a}.details{width:365px;min-width:300px;max-width:42%;border-left:1px solid #3b5142;background:#1c2820;overflow:auto;padding:20px;scrollbar-width:thin}.details-heading{display:flex;justify-content:space-between;align-items:center;font-size:9px;color:#8ca795;letter-spacing:1.5px}.details-heading button{font-size:24px;line-height:1;color:#a7c1af;padding:0 5px}.details h3{font-size:19px;font-weight:500;overflow-wrap:anywhere;margin:22px 0 8px}.detail-filename{color:#88a493;overflow-wrap:anywhere;line-height:1.6}.detail-status{display:inline-block;font-size:10px;border:1px solid #49664f;color:#bad5be;padding:5px 9px;border-radius:4px;margin:7px 0 16px}.details dl{display:grid;grid-template-columns:90px 1fr;gap:14px 10px;font-size:11px;line-height:1.5}.details dt{color:#8da996}.details dd{margin:0;overflow-wrap:anywhere;color:#d8e7dc}.details dd.password{color:#d1edbf;white-space:pre-wrap}.raw{border-top:1px solid #39513f;margin-top:22px;padding-top:15px}.raw summary{font-size:11px;color:#a8c5b1;cursor:pointer;display:flex;justify-content:space-between}.raw pre{font-size:10px;line-height:1.7;white-space:pre-wrap;overflow-wrap:anywhere;color:#a9c3b2;background:#132018;border:1px solid #2e4435;border-radius:5px;padding:12px}.catalog-intro{font-size:12px;line-height:1.7;color:#b1c5b7}.catalog-intro>span{font-size:10px;color:#8ea797}.source-list h4{font-size:9px;color:#8ea797;letter-spacing:1px;margin-top:24px}.source-list article{padding:8px 0;border-bottom:1px solid #334b3c;overflow-wrap:anywhere}.source-list p{font-size:11px;line-height:1.6;margin:4px 0}.source-list code{font-size:9px;color:#8ea797}.profile-config{font-size:10px;white-space:pre-wrap;overflow-wrap:anywhere;color:#a9c3b2}.generation h4{font-size:9px;color:#8ea797;letter-spacing:1px;margin-top:24px}.rule-list h4{font-size:9px;color:#8ea797;letter-spacing:1px;margin-top:24px}.rule-list article{border:1px solid #395140;border-radius:5px;padding:11px;margin:9px 0}.rule-list strong{font-size:10px;font-weight:500;overflow-wrap:anywhere}.rule-list code{display:block;color:#c9e2b7;font-size:12px;margin-bottom:8px}.rule-list p{color:#92aa9a;font-size:11px;line-height:1.6;margin-bottom:0}.notice{background:#352b21;color:#e6c9a7;font-size:12px;padding:12px 20px;line-height:1.5}.details .notice{padding:10px}.muted{color:#8fa997;font-size:12px}.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)}@media(min-width:1600px){main{padding-top:24px}}@media(max-width:900px){.topbar{padding:14px 20px}.topbar-status{gap:10px}.brand-label{display:none}main{padding:16px}.live{font-size:9px}.live>span:last-child{display:none}.sheet-title{padding:20px 16px 0}.sheet-description{margin-left:16px;margin-right:16px;line-height:1.7}.toolbar{padding:12px;flex-wrap:wrap}.search{width:240px;flex:1}.toolbar-end{gap:8px}.sync{display:none}.details{position:absolute;right:0;top:0;bottom:0;max-width:90%;width:365px;z-index:3;box-shadow:-15px 0 40px #0005}.sheet-body{position:relative}.file-type,.tabs-caption{display:none}.tabs button{padding:0 14px}.page-footer>span:last-child{display:none}.page-footer{line-height:1.6}.sheet-footer{padding:12px;font-size:9px}.pagination{gap:8px}}@media(prefers-reduced-motion:no-preference){button,tr{transition:background-color .12s}}
</style>
