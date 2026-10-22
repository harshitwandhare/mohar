// Renders og.html to site/assets/brand/og.png (1200x630), the image link previews show.
//   node tools/logo/og.mjs
import { chromium } from '@playwright/test';
import { fileURLToPath } from 'node:url';

const here = new URL('.', import.meta.url);
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1200, height: 630 } });
await page.goto(new URL('og.html', here).href);
await page.evaluate(() => document.fonts.ready);
await page.screenshot({ path: fileURLToPath(new URL('../../site/assets/brand/og.png', here)) });
await browser.close();
console.log('wrote site/assets/brand/og.png');
