import { expect, test } from '@playwright/test';

const machineKey = process.env.DASHBOARD_E2E_API_KEY || 'your-secure-api-key-here';
const adminPassword = process.env.DASHBOARD_E2E_ADMIN_PASSWORD || 'e2e-password';

test('session dashboard renders and updates without browser errors', async ({ page, request }) => {
  const browserErrors: string[] = [];
  const runID = Date.now();
  const browserGroup = 'browser-group-' + runID;
  const seedHost = 'browser-seed-' + runID;
  const browserHost = 'browser-agent-' + runID;

  const seedResponse = await request.post('/api/v1/logs', {
    headers: {
      'Content-Type': 'application/json',
      'X-Api-Key': machineKey,
    },
    data: { msg: 'browser-seed', action: 'ALLOWED', hostname: seedHost },
  });
  expect(seedResponse.status()).toBe(201);

  page.on('pageerror', (error) => browserErrors.push('pageerror: ' + error.message));
  page.on('console', (message) => {
    if (message.type() === 'error' && !message.text().startsWith('Failed to load resource:')) {
      browserErrors.push('console: ' + message.text());
    }
  });
  page.on('response', (response) => {
    if (response.status() < 400) return;
    const path = new URL(response.url()).pathname;
    if (response.status() === 401 && path === '/api/v1/auth/me') return;
    browserErrors.push('response: ' + response.status() + ' ' + path);
  });

  await page.goto('/');
  await expect(page).toHaveURL(/\/login\.html$/);

  await page.getByLabel('Username').fill('admin');
  await page.getByLabel('Password').fill(adminPassword);
  await page.getByRole('button', { name: 'Sign in' }).click();

  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole('row').filter({ hasText: seedHost })).toBeVisible();

  await page.getByRole('button', { name: 'Aggregates' }).click();
  await expect(page.getByRole('heading', { name: 'Traffic over time' })).toBeVisible();

  await page.getByRole('button', { name: 'API Keys' }).click();
  await expect(page.getByRole('heading', { name: 'API Keys' })).toBeVisible();
  await expect(page.getByRole('row').filter({ hasText: 'e2e-agent' })).toBeVisible();

  await page.getByRole('button', { name: 'Fleet' }).click();
  await expect(page.getByRole('heading', { name: 'Fleet' })).toBeVisible();
  await expect(page.locator('td').filter({ hasText: /^e2e-group$/ })).toBeVisible();

  await page.getByPlaceholder('New group name').fill(browserGroup);
  await page.getByRole('button', { name: 'Add' }).click();
  await expect(page.locator('td').filter({ hasText: new RegExp('^' + browserGroup + '$') })).toBeVisible();

  await page.getByRole('button', { name: 'Stream' }).click();
  const response = await request.post('/api/v1/logs', {
    headers: {
      'Content-Type': 'application/json',
      'X-Api-Key': machineKey,
    },
    data: {
      msg: 'browser-live-e2e',
      action: 'ALLOWED',
      hostname: browserHost,
    },
  });
  expect(response.status()).toBe(201);
  await expect(page.getByRole('row').filter({ hasText: browserHost })).toBeVisible();

  await page.getByRole('button', { name: 'Clear Logs', exact: true }).click();
  await page.getByRole('button', { name: 'Clear logs', exact: true }).click();
  await expect(page.getByText('No traffic yet')).toBeVisible();

  expect(browserErrors).toEqual([]);

  await page.getByRole('button', { name: 'Logout' }).click();
  await expect(page).toHaveURL(/\/login\.html$/);
});
