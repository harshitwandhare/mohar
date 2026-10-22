import { test, expect } from '@playwright/test';

test('first screen says what Mohar is and offers one action', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Trust, earned.');
  await expect(page.getByRole('link', { name: 'Watch an agent earn it' })).toBeVisible();
});

test('no console errors or failed requests on load', async ({ page }) => {
  const errors = [];
  page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('response', r => { if (r.status() >= 400) errors.push(`${r.status()} ${r.url()}`); });
  await page.goto('/');
  await page.waitForLoadState('networkidle');
  expect(errors).toEqual([]);
});

test('verified passes promote a capability; a gated failure demotes it to the bottom', async ({ page }) => {
  await page.goto('/');
  const next = page.getByRole('button', { name: 'Next task' });
  // Three capabilities take turns, so 24 tasks give the migration eight passes: two promotions.
  for (let i = 0; i < 24; i++) await next.click();
  const migrate = page.locator('.cap').filter({ hasText: 'Run migrations' });
  await expect(migrate.locator('.level')).toHaveText('Trusted');
  // From the top, a gated failure must drop all the way down, not one level.

  await page.getByRole('button', { name: 'Break a migration' }).click();
  await expect(migrate.locator('.level')).toHaveText('Ask first');
  await expect(migrate).toHaveClass(/demoted/);
});

test('receipts form a hash chain: each one differs and the list is newest first', async ({ page }) => {
  await page.goto('/');
  const next = page.getByRole('button', { name: 'Next task' });
  await next.click();
  await next.click();
  const items = page.locator('#receipts li');
  await expect(items).toHaveCount(2);
  await expect(items.first().locator('.stamp')).toHaveText('#2');
  const [a, b] = await items.locator('code').allTextContents();
  expect(a).toMatch(/^sha256 [0-9a-f]{32}/);
  expect(a).not.toEqual(b);
});

test('without WebGL or with reduced motion the still seal shows', async ({ browser }) => {
  const page = await browser.newPage({ reducedMotion: 'reduce' });
  await page.goto('http://localhost:4173/');
  await expect(page.locator('#seal3d img')).toBeVisible();
  await expect(page.locator('#seal3d canvas')).toHaveCount(0);
  await page.close();
});

test('every archival picture has alt text and a credit in the footer', async ({ page }) => {
  await page.goto('/');
  for (const img of await page.locator('main img').all()) {
    expect((await img.getAttribute('alt'))?.length).toBeGreaterThan(10);
  }
  const credits = page.locator('.credits');
  for (const word of ['Raigad', 'Jnanesvari', 'Shaniwar Wada']) await expect(credits).toContainText(word);
});

test('design page is built from docs/design.md, with a working contents list', async ({ page, request }) => {
  await page.goto('/design.html');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Mohar design');
  await page.getByRole('navigation', { name: 'On this page' }).getByRole('link', { name: '7. Receipts' }).click();
  await expect(page).toHaveURL(/#7-receipts$/);
  const md = await request.get('/docs/design.md');
  expect(md.ok()).toBeTruthy();
  expect(await md.text()).toContain('## 4. Trust levels and the rules that move them');
});

test('llms.txt points agents at the markdown docs', async ({ request }) => {
  const res = await request.get('/llms.txt');
  expect(res.ok()).toBeTruthy();
  const body = await res.text();
  expect(body).toMatch(/^# Mohar/);
  expect(body).toContain('/docs/design.md');
});
