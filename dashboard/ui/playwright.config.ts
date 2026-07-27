import { defineConfig, devices } from '@playwright/test';

const demo = process.env.DASHBOARD_E2E_DEMO === '1';

export default defineConfig({
  testDir: './e2e',
  outputDir: process.env.PLAYWRIGHT_OUTPUT_DIR || 'test-results',
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'line',
  use: {
    baseURL: process.env.DASHBOARD_E2E_BASE_URL || (demo ? 'http://127.0.0.1:4173' : 'http://127.0.0.1:8081'),
    trace: 'retain-on-failure',
  },
  webServer: demo ? {
    command: 'pnpm build:demo && pnpm preview --host 127.0.0.1 --port 4173',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: !process.env.CI,
  } : undefined,
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
