// A separate temporary data root keeps the fictional demo away from real data.
import { access, copyFile, cp, mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { spawn } from 'node:child_process'

const frontend = dirname(fileURLToPath(import.meta.url))
const sheets = ['complete', 'exhausted', 'no-usable-handshake', 'tool-error', 'rules']

export async function createDemoRoot() {
  const fixture = JSON.parse(await readFile(join(frontend, 'demo', 'fixtures.json'), 'utf8'))
  const root = await mkdtemp(join(tmpdir(), 'pwnabase-demo-'))
  try {
    for (const sheet of sheets) {
      const directory = join(root, sheet)
      await mkdir(directory, { mode: 0o700 })
      for (const [index, record] of fixture[sheet].entries()) {
        await writeFile(join(directory, `example-${index + 1}.json`), JSON.stringify(record), { mode: 0o600 })
      }
    }
    const runtime = join(root, '.pwnabase')
    await mkdir(join(runtime, 'batch-runs'), { recursive: true, mode: 0o700 })
    await mkdir(join(runtime, 'batch-events'), { mode: 0o700 })
    const status = JSON.stringify(fixture.batch)
    await writeFile(join(runtime, 'batch-status.json'), status, { mode: 0o600 })
    await writeFile(join(runtime, 'batch-runs', `${fixture.batch.run_id}.json`), status, { mode: 0o600 })
    await writeFile(join(runtime, 'batch-events', `${fixture.batch.run_id}.jsonl`),
      fixture.events.map(event => JSON.stringify(event) + '\n').join(''), { mode: 0o600 })
    return root
  } catch (error) { await rm(root, { recursive: true, force: true }); throw error }
}

export function demoEnvironment(parent, root) {
  const env = Object.fromEntries(Object.entries(parent).filter(([key]) => !/^(NUXT_|NITRO_)/i.test(key)))
  return { ...env, PWNA_DATA_ROOT: root, PWNA_DEMO: '1', NUXT_DATA_ROOT: root,
    NITRO_DATA_ROOT: root, NUXT_PUBLIC_DEMO: 'true', NITRO_PUBLIC_DEMO: 'true' }
}

async function createWorkspace(root) {
  const workspace = join(root, 'viewer-workspace')
  await mkdir(workspace, { mode: 0o700 })
  for (const name of ['app', 'server']) await cp(join(frontend, name), join(workspace, name), { recursive: true })
  for (const name of ['start.mjs', 'nuxt.config.ts', 'package.json', 'package-lock.json']) {
    await copyFile(join(frontend, name), join(workspace, name))
  }
  await mkdir(join(workspace, 'node_modules'), { mode: 0o700 })
  try {
    for (const name of await readdir(join(frontend, 'node_modules'))) {
      if (name !== '.cache') await symlink(join(frontend, 'node_modules', name), join(workspace, 'node_modules', name))
    }
  } catch (error) { if (error.code !== 'ENOENT') throw error }
  try {
    await access(join(frontend, '.runtime'))
    await symlink(join(frontend, '.runtime'), join(workspace, '.runtime'), 'dir')
  }
  catch (error) { if (error.code !== 'ENOENT') throw error }
  return workspace
}

async function main() {
  const root = await createDemoRoot()
  let child
  try {
    const workspace = await createWorkspace(root)
    console.log('Starting the fictional Pwnabase demo. No real results are used.')
    child = spawn(process.execPath, [join(workspace, 'start.mjs')], {
      cwd: workspace, stdio: 'inherit', detached: true, env: demoEnvironment(process.env, root),
    })
  } catch (error) { await rm(root, { recursive: true, force: true }); throw error }
  const stop = signal => { try { if (child.pid) process.kill(-child.pid, signal) } catch (error) { if (error.code !== 'ESRCH') throw error } }
  const interrupt = () => stop('SIGINT'), terminate = () => stop('SIGTERM')
  process.on('SIGINT', interrupt)
  process.on('SIGTERM', terminate)
  try {
    const result = await new Promise((resolve, reject) => {
      child.once('error', reject)
      child.once('exit', (code, signal) => resolve(code ?? (signal ? 130 : 1)))
    })
    process.exitCode = result
  } finally {
    process.off('SIGINT', interrupt)
    process.off('SIGTERM', terminate)
    stop('SIGTERM')
    await rm(root, { recursive: true, force: true })
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => { console.error(`Demo could not start: ${error.message}`); process.exitCode = 1 })
}
