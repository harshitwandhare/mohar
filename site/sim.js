// Browser simulation of Mohar's rules. Receipts are a real SHA-256 hash chain; there are no keys here,
// so nothing is signed. The real log signs each entry with Ed25519.
const LEVELS = ['Ask first', 'Supervised', 'Trusted'];
const PROMOTE_AFTER = 4; // verified passes in a row needed to move up one level

const caps = {
  docs: { name: 'Edit docs', gated: false },
  tests: { name: 'Write tests', gated: false },
  migrate: { name: 'Run migrations', gated: true },
};
let state, prevHash, n;

function reset() {
  state = {};
  for (const k in caps) state[k] = { level: 0, streak: 0, why: 'No record yet.', demoted: false };
  prevHash = '0'.repeat(64);
  n = 0;
  document.getElementById('receipts').innerHTML = '';
  render();
}

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function act(key, passed) {
  const c = state[key];
  const before = LEVELS[c.level];
  let decision;
  if (passed) {
    c.streak += 1;
    c.demoted = false;
    if (c.streak >= PROMOTE_AFTER && c.level < LEVELS.length - 1) {
      c.level += 1;
      c.streak = 0;
      c.why = `Promoted after ${PROMOTE_AFTER} verified passes.`;
    } else {
      c.why = `${c.streak} of ${PROMOTE_AFTER} verified passes toward the next level.`;
    }
    decision = c.level === 0 ? 'asked a person, then ran' : 'ran inside earned limits';
  } else {
    // A gated capability drops to the bottom on one failure; others drop one level.
    c.level = caps[key].gated ? 0 : Math.max(0, c.level - 1);
    c.streak = 0;
    c.demoted = true;
    c.why = caps[key].gated ? 'Tests failed on a gated capability. Back to asking first.' : 'Tests failed. Down one level.';
    decision = 'failed verification, demoted';
  }
  n += 1;
  const entry = `${n}|${caps[key].name}|${passed ? 'pass' : 'fail'}|${before}->${LEVELS[c.level]}|${prevHash}`;
  const hash = await sha256(entry);
  prevHash = hash;
  addReceipt(n, caps[key].name, decision, passed, hash);
  render();
}

function addReceipt(i, name, decision, passed, hash) {
  const li = document.createElement('li');
  li.innerHTML = `<span class="stamp ${passed ? 'ok' : ''}">#${i}</span><strong></strong><code></code>`;
  li.querySelector('strong').textContent = `${name}: ${decision}`;
  li.querySelector('code').textContent = `sha256 ${hash.slice(0, 32)}…`;
  const list = document.getElementById('receipts');
  list.prepend(li);
  while (list.children.length > 40) list.lastElementChild.remove();
  document.dispatchEvent(new CustomEvent('mohar:receipt'));
}

function render() {
  const el = document.getElementById('caps');
  el.innerHTML = '';
  for (const k in caps) {
    const c = state[k];
    const pct = ((c.level * PROMOTE_AFTER + c.streak) / ((LEVELS.length - 1) * PROMOTE_AFTER)) * 100;
    const div = document.createElement('div');
    div.className = 'cap' + (c.demoted ? ' demoted' : '');
    div.innerHTML = `<p class="name"></p><p class="level"></p><div class="meter"><span></span></div><p class="why"></p>`;
    div.querySelector('.name').textContent = caps[k].name + (caps[k].gated ? ' (gated)' : '');
    div.querySelector('.level').textContent = LEVELS[c.level];
    div.querySelector('.why').textContent = c.why;
    // Set through the CSSOM: the site's CSP blocks inline style attributes.
    div.querySelector('.meter span').style.width = `${Math.min(pct, 100)}%`;
    el.append(div);
  }
}

// Mostly passing work spread across capabilities; failures only when the visitor asks for one.
const order = ['docs', 'tests', 'migrate'];
let turn = 0;
document.getElementById('step').addEventListener('click', () => act(order[turn++ % order.length], true));
document.getElementById('fail').addEventListener('click', () => act('migrate', false));
document.getElementById('reset').addEventListener('click', reset);
reset();
