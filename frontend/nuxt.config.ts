import { fileURLToPath } from 'node:url'

export default defineNuxtConfig({
  compatibilityDate: '2026-11-01',
  devtools: { enabled: false },
  telemetry: false,
  runtimeConfig: { dataRoot: process.env.PWNA_DATA_ROOT || fileURLToPath(new URL('../', import.meta.url)),
    public: { demo: process.env.PWNA_DEMO === '1' } },
  app: { head: { title: 'Pwnabase · Result sheets', htmlAttrs: { lang: 'en' } } },
})
