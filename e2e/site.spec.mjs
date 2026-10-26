import { readdirSync, readFileSync } from 'node:fs';
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

test('once the 3D seal is drawn the still under it is hidden, so the two never show together', async ({ page }) => {
  await page.goto('/');
  // Engines without WebGL 2 keep the still, which the test above covers.
  const webgl = await page.evaluate(() => !!document.createElement('canvas').getContext('webgl2'));
  test.skip(!webgl, 'no WebGL 2 in this browser');
  await expect(page.locator('#seal3d canvas')).toHaveCount(1, { timeout: 20000 });
  await expect(page.locator('#seal3d')).toHaveClass(/(^| )shown( |$)/, { timeout: 8000 });
  await expect(page.locator('#seal3d img')).toBeHidden();
});

test('the story of the name lives on its own page, with every picture credited', async ({ page }) => {
  await page.goto('/name.html');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Why Mohar');
  for (const img of await page.locator('main img').all()) {
    expect((await img.getAttribute('alt'))?.length).toBeGreaterThan(10);
  }
  const credits = page.locator('.credits');
  for (const word of ['Raigad', 'Jnanesvari', 'Shaniwar Wada']) await expect(credits).toContainText(word);
});

test('the main page stays about the product', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('.seal-story, .band')).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'About the name' })).toHaveAttribute('href', 'name.html');
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

const pages = ['/', '/name.html', '/design.html', '/roadmap.html', '/integrations.html', '/compliance.html', '/engineering-bar.html', '/business-model.html', '/404.html'];

test('no page is wider than a 320px phone, and each has the same header', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 720 });
  for (const path of pages) {
    await page.goto(path);
    // On failure, name what sticks out, so the fix doesn't have to be guessed.
    const wide = await page.evaluate(() => {
      const W = document.documentElement.clientWidth;
      if (document.documentElement.scrollWidth <= W) return [];
      return [...document.querySelectorAll('body *')].filter(e => e.getBoundingClientRect().right > W + 0.5 && !e.closest('pre'))
        .slice(0, 6).map(e => `${e.tagName.toLowerCase()}.${e.className} ends at ${Math.round(e.getBoundingClientRect().right)}px: ${e.textContent.trim().slice(0, 30)}`);
    });
    expect(wide, `${path} scrolls sideways`).toEqual([]);
    const menu = page.locator('.menu');
    await expect(menu, `${path} has no menu`).toBeVisible();
    await menu.locator('summary').click();
    for (const name of ['Docs', 'Design', 'Roadmap', 'Integrations', 'Compliance', 'GitHub']) {
      await expect(page.getByRole('navigation', { name: 'Menu' }).getByRole('link', { name, exact: true })).toBeVisible();
    }
  }
});

test('body text stays readable but not oversized on a phone', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto('/');
  const size = await page.evaluate(() => parseFloat(getComputedStyle(document.body).fontSize));
  expect(size).toBeGreaterThanOrEqual(16);
  expect(size).toBeLessThanOrEqual(17);
});

test('no text spills out of its box at phone, tablet or desktop width', async ({ page }) => {
  for (const width of [320, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    for (const path of pages) {
      await page.goto(path);
      const spills = await page.evaluate(() => {
        const out = [];
        for (const e of document.querySelectorAll('main *, footer *')) {
          // Code blocks, tables and the contents chip row scroll on purpose.
          if (e.children.length || !e.textContent.trim() || e.closest('pre, table, .toc, svg')) continue;
          if (e.clientWidth && e.scrollWidth > e.clientWidth + 1) out.push(`${e.tagName} "${e.textContent.trim().slice(0, 30)}"`);
        }
        return out;
      });
      expect(spills, `${path} at ${width}px`).toEqual([]);
    }
  }
});

test('the trust meter fills as passes are verified, under the production CSP', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'Next task' }).click();
  const fill = page.locator('.cap').filter({ hasText: 'Edit docs' }).locator('.meter span');
  const ratio = async () => (await fill.boundingBox()).width / (await fill.locator('..').boundingBox()).width;
  // One pass of the eight needed to reach the top: an eighth of the meter, not empty and not full.
  await expect.poll(ratio).toBeGreaterThan(0.1);
  await expect.poll(ratio).toBeLessThan(0.15);
});

test('no example on the site or in the docs is dated after today', () => {
  // A receipt stamped in the future reads as made up, and honesty is the whole product.
  const today = new Date().toISOString().slice(0, 10);
  const files = [
    ...readdirSync('site').filter(f => f.endsWith('.html')).map(f => `site/${f}`),
    ...readdirSync('docs').filter(f => f.endsWith('.md')).map(f => `docs/${f}`),
  ];
  const late = files.flatMap(f =>
    (readFileSync(f, 'utf8').match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/g) ?? [])
      .filter(stamp => stamp.slice(0, 10) > today)
      .map(stamp => `${f}: ${stamp}`));
  expect(late).toEqual([]);
});

test('example hashes on the home page are full length and only cut by the browser', async ({ page }) => {
  // A hash typed as "7be1…c09a" looks hand-made; the page holds the real length and CSS shortens it.
  const html = readFileSync('site/index.html', 'utf8');
  expect(html.match(/(sha256|ed25519):[0-9a-zA-Z]*…/g) ?? []).toEqual([]);
  await page.goto('/');
  const hashes = await page.locator('.hash').evaluateAll(els => els.map(e => ({
    text: e.textContent,
    cut: e.scrollWidth > e.clientWidth,
  })));
  expect(hashes.length).toBe(5);
  for (const { text, cut } of hashes) {
    expect(text).toMatch(/^(sha256:|ed25519:)?([0-9a-f]{64}|[0-9a-f]{128})$/);
    expect(cut, text).toBe(true);
  }
});

test('running text avoids one-word last lines and headings wrap evenly', async ({ page }) => {
  await page.goto('/');
  const support = await page.evaluate(() => ({
    pretty: CSS.supports('text-wrap', 'pretty'),
    balance: CSS.supports('text-wrap', 'balance'),
  }));
  test.skip(!support.pretty, 'this browser has no text-wrap: pretty and wraps greedily');
  const styles = await page.evaluate(() => {
    const wrap = sel => [...document.querySelectorAll(sel)].map(e => getComputedStyle(e).textWrapStyle);
    return { p: wrap('main p, main li, main dd'), h: wrap('h1, h2, h3') };
  });
  expect(styles.p.length).toBeGreaterThan(10);
  expect(new Set(styles.p)).toEqual(new Set(['pretty']));
  if (support.balance) expect(new Set(styles.h)).toEqual(new Set(['balance']));
});
