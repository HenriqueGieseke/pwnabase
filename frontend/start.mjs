// Run from any directory: node frontend/start.mjs
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { spawnSync } from 'node:child_process'

const cwd = dirname(fileURLToPath(import.meta.url))
const runtime = join(cwd, '.runtime')
const [major, minor, patch] = process.versions.node.split('.').map(Number)
const compatible = major >= 26 || major === 24 && minor >= 15 || major === 22 && (minor > 22 || minor === 22 && patch >= 3)
const env = { ...process.env, NUXT_TELEMETRY_DISABLED: '1', npm_config_cache: join(cwd, '.npm-cache') }
function run(command, args, extra = {}) {
  const result = spawnSync(command, args, { cwd, env, stdio: 'inherit', ...extra })
  if (result.error || result.status !== 0) {
    console.error(result.error?.message || 'Command did not complete. Check the output above, then rerun this launcher.')
    process.exit(result.status || 1)
  }
}
if (!compatible) {
  if (!existsSync(join(runtime, 'node_modules/node/bin/node'))) {
    console.log('Installing a project-local Node 22.22.3 runtime. The system Node stays unchanged.')
    run('npm', ['install', '--prefix', runtime, '--no-save', '--no-audit', '--no-fund', 'node@22.22.3'])
  }
  env.PATH = join(runtime, 'node_modules/node/bin') + ':' + env.PATH
}
if (!existsSync(join(cwd, 'node_modules/nuxt/package.json'))) {
  console.log('Installing viewer dependencies…')
  run('npm', ['install', '--no-audit', '--no-fund'])
}
console.log('Starting the viewer. Open http://127.0.0.1:3000 (Ctrl+C stops only the viewer).')
run('npm', ['run', 'dev'])
