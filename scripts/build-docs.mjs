// Renders docs/*.md into site pages and publishes the raw markdown beside them for agents.
// Runs on every deploy, so the site can't drift from the design document in the repo.
import { readFile, writeFile, mkdir, copyFile } from 'node:fs/promises';
import { marked } from 'marked';

const docs = [
  { src: 'docs/design.md', page: 'design.html', title: 'Design', blurb: 'How Mohar decides what an agent may do, how trust is earned and lost, and what each receipt proves.' },
  { src: 'docs/ROADMAP.md', page: 'roadmap.html', title: 'Roadmap', blurb: 'What gets built, in what order.' },
  { src: 'docs/integrations.md', page: 'integrations.html', title: 'Integrations', blurb: 'How Mohar plugs into Claude Code, Codex, CAO, ADK, MCP, A2A and agent governance platforms, and how strong each seam is.' },
  { src: 'docs/business-model.md', page: 'business-model.html', title: 'Sustainability', blurb: 'What stays free, what could be paid for later, and what would trigger a company.' },
  { src: 'docs/engineering-bar.md', page: 'engineering-bar.html', title: 'Engineering bar', blurb: 'The correctness, reliability, performance, security and compatibility standard every part of Mohar is held to.' },
  { src: 'docs/compliance.md', page: 'compliance.html', title: 'Compliance', blurb: 'How Mohar maps onto the EU AI Act, GDPR, the Cyber Resilience Act, US export rules and NIST, SOC 2 and ISO frameworks.' },
];

// Anchors come from the heading's plain text; anything that isn't a letter or digit becomes a dash.
const slug = s => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

const navLinks = cur => [
  ['https://harshitwandhare.github.io/mohar/', 'Docs'],
  ['design.html', 'Design'],
  ['roadmap.html', 'Roadmap'],
  ['integrations.html', 'Integrations'],
  ['compliance.html', 'Compliance'],
].map(([h, t]) => `<a href="${h}"${h === cur ? ' aria-current="page"' : ''}>${t}</a>`).join('') +
  '<a class="action" href="https://github.com/harshitwandhare/mohar">GitHub</a>';

// Same header as the hand-written pages; under 900px the links fold into the menu.
const header = cur => `<header class="bar">
  <a class="wordmark" href="./" translate="no"><img src="assets/brand/mohar-mark-96.png" alt="" width="28" height="28">Mohar</a>
  <nav aria-label="Primary">${navLinks(cur)}</nav>
  <details class="menu"><summary>Menu</summary><nav aria-label="Menu">${navLinks(cur)}</nav></details>
</header>`;

function page({ title, blurb, body, toc, md, page }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · Mohar</title>
<meta name="description" content="${blurb}">
<meta name="theme-color" content="#16130f">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Tiro+Devanagari+Marathi&family=Schibsted+Grotesk:wght@400;500;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="styles.css">
<link rel="icon" href="favicon.ico" sizes="any">
<link rel="icon" href="assets/brand/favicon-32.png" type="image/png" sizes="32x32">
<link rel="apple-touch-icon" href="assets/brand/apple-touch-icon.png">
<link rel="manifest" href="site.webmanifest">
<meta property="og:type" content="website">
<meta property="og:site_name" content="Mohar">
<meta property="og:title" content="${title} · Mohar">
<meta property="og:description" content="${blurb}">
<meta property="og:url" content="https://mohar-liard.vercel.app/${page}">
<meta property="og:image" content="https://mohar-liard.vercel.app/assets/brand/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="The Mohar gold seal beside the words Mohar, Trust, earned.">
<meta name="twitter:card" content="summary_large_image">
<link rel="alternate" type="text/markdown" href="${md}">
</head>
<body class="doc">
<a class="skip" href="#main">Skip to content</a>
${header(page)}
<div class="doc-layout">
  <nav class="toc" aria-label="On this page">${toc}</nav>
  <main id="main" class="prose">${body}<p class="page-meta">Generated from <a href="https://github.com/harshitwandhare/mohar/blob/main/${md}">${md}</a>. Read it <a href="${md}">as Markdown</a>.</p></main>
</div>
<footer class="close"><p>Apache-2.0. <a href="./">Home</a> · <a href="https://harshitwandhare.github.io/mohar/">Docs</a> · <a href="engineering-bar.html">Engineering bar</a> · <a href="business-model.html">Sustainability</a> · <a href="name.html">About the name</a></p></footer>
</body>
</html>
`;
}

await mkdir('site/docs', { recursive: true });
const index = [];
for (const d of docs) {
  const md = await readFile(d.src, 'utf8');
  const heads = [];
  const renderer = new marked.Renderer();
  renderer.heading = ({ tokens, depth, text: plain }) => {
    const text = marked.Parser.parseInline(tokens);
    const id = slug(plain);
    if (depth === 2) heads.push({ id, text });
    return `<h${depth} id="${id}">${text}</h${depth}>`;
  };
  // Links between docs point at the rendered pages.
  const body = marked.parse(md, { renderer }).replaceAll('href="ROADMAP.md"', 'href="roadmap.html"').replaceAll('href="design.md"', 'href="design.html"').replaceAll('href="compliance.md"', 'href="compliance.html"').replaceAll('href="engineering-bar.md"', 'href="engineering-bar.html"');
  const toc = heads.map(h => `<a href="#${h.id}">${h.text}</a>`).join('');
  const raw = `docs/${d.src.split('/').pop()}`;
  await copyFile(d.src, `site/${raw}`);
  await writeFile(`site/${d.page}`, page({ ...d, body, toc, md: raw }));
  index.push(`- [${d.title}](https://mohar-liard.vercel.app/${raw}): ${d.blurb}`);
}

await writeFile('site/llms.txt', `# Mohar

> Open-source trust layer for AI agents. Authority is earned per capability from verified outcomes and lost immediately on failure. Every decision produces a signed, hash-chained receipt. Early stage: the design is specified, implementation is in progress.

## Docs

${index.join('\n')}

## Repository

- [Source and issues](https://github.com/harshitwandhare/mohar): start with AGENTS.md if you are a coding agent.
`);
console.log('built', docs.map(d => d.page).join(', '));
