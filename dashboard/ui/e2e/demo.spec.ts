import { expect, test } from '@playwright/test';

test('demo dashboard offers and completes an unblock', async ({ page }) => {
  test.skip(process.env.DASHBOARD_E2E_DEMO !== '1', 'demo dashboard only');

  await page.goto('/');

  const blockedRow = page.locator('tbody tr').filter({ hasText: 'telemetry.bad.example' }).first();
  await expect(blockedRow).toBeVisible();

  await blockedRow.getByRole('button', { name: 'Allow telemetry.bad.example' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Queue unblock' }).click();

  await expect(blockedRow.getByText('Unblocked')).toBeVisible();
});
