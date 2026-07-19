import { expect, test } from '@playwright/test';

const machineKey = process.env.DASHBOARD_E2E_API_KEY || 'your-secure-api-key-here';
const adminPassword = process.env.DASHBOARD_E2E_ADMIN_PASSWORD || 'e2e-password';

test('session dashboard renders and updates without browser errors', async ({ page, request }) => {
  const browserErrors: string[] = [];
  const runID = Date.now();
  const browserGroup = 'browser-group-' + runID;
  const seedHost = 'browser-seed-' + runID;
  const browserHost = 'browser-agent-' + runID;
  const aggregateHost = 'aggregate-' + runID + '.example';

  const seedResponse = await request.post('/api/v1/logs', {
    headers: {
      'Content-Type': 'application/json',
      'X-Api-Key': machineKey,
    },
    data: { msg: 'browser-seed', action: 'ALLOWED', hostname: seedHost },
  });
  expect(seedResponse.status()).toBe(201);

  for (const action of ['ALLOWED', 'BLOCKED', 'AUDIT']) {
    const aggregateResponse = await request.post('/api/v1/logs', {
      headers: {
        'Content-Type': 'application/json',
        'X-Api-Key': machineKey,
      },
      data: {
        msg: 'browser-aggregate',
        action,
        http_host: aggregateHost,
        source_ip: '10.10.10.10',
        source_port: 51234,
        destination_ip: '7.7.7.7',
        destination_port: 443,
      },
    });
    expect(aggregateResponse.status()).toBe(201);
  }

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

  const rowsSelect = page.getByLabel('Rows');
  await expect(rowsSelect).toHaveValue('500');
  const limitedReload = page.waitForRequest((incoming) => {
    const url = new URL(incoming.url());
    return url.pathname === '/api/v1/logs' && url.searchParams.get('limit') === '1000';
  });
  await rowsSelect.selectOption('1000');
  await limitedReload;
  await expect.poll(() => page.evaluate(() => localStorage.getItem('streamRows'))).toBe('1000');

  const streamAggregateRow = page.getByRole('row').filter({ hasText: aggregateHost }).first();
  await expect(streamAggregateRow.getByRole('link', {
    name: 'Search ' + aggregateHost + ' on VirusTotal',
  })).toHaveAttribute('href', 'https://www.virustotal.com/gui/search?query=' + aggregateHost);
  await expect(streamAggregateRow.getByRole('link', {
    name: 'Search 7.7.7.7 on VirusTotal',
  })).toHaveAttribute('href', 'https://www.virustotal.com/gui/search?query=7.7.7.7');
  await expect(streamAggregateRow.getByRole('link', {
    name: 'Search 10.10.10.10 on VirusTotal',
  })).toHaveCount(0);

  await page.getByRole('button', { name: 'Aggregates' }).click();
  await expect(page.getByRole('heading', { name: 'Traffic over time' })).toBeVisible();
  await page.getByLabel('Filter aggregates by host or IP').fill(aggregateHost);
  await expect(page.getByLabel('Range')).toHaveValue('24h');
  await expect(page.getByText('3 verdict events - Last 24 hours')).toBeVisible();

  const aggregateStats = page.locator('.aggregate-stats .stat .n');
  await expect(aggregateStats).toHaveText(['3', '1', '1', '1', '50.0%']);

  const aggregateRow = page.getByRole('row').filter({ hasText: aggregateHost });
  await expect(aggregateRow.getByRole('link', {
    name: 'Search ' + aggregateHost + ' on VirusTotal',
  })).toHaveAttribute('href', 'https://www.virustotal.com/gui/search?query=' + aggregateHost);
  await expect(page.getByRole('link', {
    name: 'Search ' + aggregateHost + ' on VirusTotal',
  })).toHaveCount(4);
  await expect(aggregateRow.locator('td').nth(1)).toHaveText('3');
  await expect(aggregateRow.locator('td').nth(2)).toHaveText('1');
  await expect(aggregateRow.locator('td').nth(3)).toHaveText('1');
  await expect(aggregateRow.locator('td').nth(4)).toHaveText('1');
  await expect(aggregateRow.locator('td').nth(5)).toHaveText('50.0%');

  await page.getByRole('button', { name: 'API Keys' }).click();
  await expect(page.getByRole('heading', { name: 'API Keys' })).toBeVisible();
  await expect(page.getByRole('row').filter({ hasText: 'env-bootstrap' })).toBeVisible();

  await page.getByRole('button', { name: 'Fleet' }).click();
  await expect(page.getByRole('heading', { name: 'Fleet' })).toBeVisible();

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
