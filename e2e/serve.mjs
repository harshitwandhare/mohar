// Tiny static server for the site, so tests run without extra dependencies. It sends the same
// headers vercel.json sets for production (CSP included), so a page that would break under the
// real policy fails the tests too.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('../site/', import.meta.url)));
const types = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.jpg': 'image/jpeg',
  '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json', '.webmanifest': 'application/manifest+json',
  '.wasm': 'application/wasm', '.glb': 'model/gltf-binary', '.md': 'text/markdown', '.txt': 'text/plain',
};
const port = Number(process.env.PORT || 4173);
const vercel = JSON.parse(await readFile(fileURLToPath(new URL('../vercel.json', import.meta.url)), 'utf8'));
// Only the catch-all header rule applies to every page; that is the one with the CSP.
const headers = Object.fromEntries((vercel.headers ?? []).filter(h => h.source === '/(.*)').flatMap(h => h.headers).map(h => [h.key, h.value]));

createServer(async (req, res) => {
  const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  const file = resolve(join(root, rel === '/' ? 'index.html' : rel));
  if (file !== root && !file.startsWith(root + sep)) { res.writeHead(403).end(); return; }
  try {
    const body = await readFile(file);
    res.writeHead(200, { ...headers, 'content-type': types[extname(file)] || 'application/octet-stream' }).end(body);
  } catch {
    res.writeHead(404).end('not found');
  }
}).listen(port, () => console.log(`site on http://localhost:${port}`));
