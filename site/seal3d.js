// The hero seal: an octagonal brass matrix in the Maratha tradition, engraved with मोहर. It tilts toward the
// pointer; a click (or a receipt from the simulator) presses a vermilion impression onto the manuscript.
// Without WebGL 2, or with reduced motion, the still image in the markup stays.
import * as THREE from 'three';
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js';

const host = document.getElementById('seal3d');
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
const gl = (() => { try { return !!document.createElement('canvas').getContext('webgl2'); } catch { return false; } })();

// Octagon path with a flat top edge, the shape of Maratha royal seals.
function octagon(ctx, cx, cy, r) {
  ctx.beginPath();
  for (let i = 0; i < 8; i++) {
    const a = Math.PI / 8 + (i * Math.PI) / 4;
    ctx[i ? 'lineTo' : 'moveTo'](cx + r * Math.cos(a), cy + r * Math.sin(a));
  }
  ctx.closePath();
}

// The seal face as an image: double octagon border and the inscription. White = raised.
export function sealFace(size, ink, ground, mirror) {
  const c = document.createElement('canvas');
  c.width = c.height = size;
  const ctx = c.getContext('2d');
  ctx.fillStyle = ground;
  ctx.fillRect(0, 0, size, size);
  if (mirror) { ctx.translate(size, 0); ctx.scale(-1, 1); }
  const m = size / 2;
  ctx.strokeStyle = ink;
  ctx.lineWidth = size * 0.028;
  octagon(ctx, m, m, size * 0.47); ctx.stroke();
  ctx.lineWidth = size * 0.012;
  octagon(ctx, m, m, size * 0.41); ctx.stroke();
  // Centre the two lines as one block using the glyphs' measured ink, not the font's nominal
  // box: Devanagari's headline and vowel signs sit well outside what textBaseline 'middle' assumes.
  ctx.fillStyle = ink;
  ctx.textAlign = 'left';
  ctx.textBaseline = 'alphabetic';
  const lines = [
    { text: 'मोहर', font: `700 ${size * 0.25}px "Tiro Devanagari Marathi", serif` },
    { text: '॥ सत्यमेव साक्षी ॥', font: `400 ${size * 0.075}px "Tiro Devanagari Marathi", serif` },
  ];
  for (const l of lines) {
    ctx.font = l.font;
    const t = ctx.measureText(l.text);
    l.left = t.actualBoundingBoxLeft;
    l.width = t.actualBoundingBoxLeft + t.actualBoundingBoxRight;
    l.ascent = t.actualBoundingBoxAscent;
    l.height = t.actualBoundingBoxAscent + t.actualBoundingBoxDescent;
  }
  // The name is centred on the octagon by its own ink; the motto sits in the lower band, the way a
  // seal's legend runs below the device.
  const [name, motto] = lines;
  // Font metrics are close but not exact for this face, so measure the drawn ink once and correct.
  const probe = document.createElement('canvas');
  probe.width = probe.height = size;
  const p = probe.getContext('2d', { willReadFrequently: true });
  p.font = name.font;
  p.fillText(name.text, m - name.width / 2 + name.left, m - name.height / 2 + name.ascent);
  const px = p.getImageData(0, 0, size, size).data;
  let x0 = size, x1 = 0, y0 = size, y1 = 0;
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    if (px[(y * size + x) * 4 + 3] > 127) { x0 = Math.min(x0, x); x1 = Math.max(x1, x); y0 = Math.min(y0, y); y1 = Math.max(y1, y); }
  }
  const dx = x1 >= x0 ? m - (x0 + x1) / 2 : 0, dy = y1 >= y0 ? m - (y0 + y1) / 2 : 0;
  // Lay the name centred and the motto below it, then lift both so the pair's common centre is
  // the octagon's centre.
  const nameH = y1 >= y0 ? y1 - y0 : name.height;
  const mottoCentre = m + size * 0.235;
  const lift = (m - nameH / 2 + mottoCentre + motto.height / 2) / 2 - m;
  ctx.font = name.font;
  ctx.fillText(name.text, m - name.width / 2 + name.left + dx, m - name.height / 2 + name.ascent + dy - lift);
  ctx.font = motto.font;
  ctx.fillText(motto.text, m - motto.width / 2 + motto.left, mottoCentre - motto.height / 2 + motto.ascent - lift);
  return c;
}

async function start() {
  await document.fonts.load('700 40px "Tiro Devanagari Marathi"').catch(() => {});

  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  renderer.shadowMap.enabled = true;
  renderer.shadowMap.type = THREE.PCFSoftShadowMap;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  host.append(renderer.domElement);
  host.classList.add('live');

  const scene = new THREE.Scene();
  const pmrem = new THREE.PMREMGenerator(renderer);
  scene.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;
  scene.environmentIntensity = 0.35;

  const camera = new THREE.PerspectiveCamera(32, 1, 0.1, 100);
  camera.position.set(0, 6.6, 9.2);
  camera.lookAt(0, 2.0, 0);

  // One warm lamp: a pool of light on the page that falls off into the dark ground around it.
  const lamp = new THREE.SpotLight(0xffe2b8, 420, 40, Math.PI / 6, 0.9, 2);
  lamp.position.set(-3, 14, 5);
  lamp.target.position.set(0, 0, 0.5);
  lamp.castShadow = true;
  lamp.shadow.mapSize.set(2048, 2048);
  lamp.shadow.radius = 8;
  lamp.shadow.bias = -0.0004;
  scene.add(lamp, lamp.target, new THREE.AmbientLight(0xffffff, 0.04));

  // Paper: an 1843 Marathi manuscript page (credited on the page).
  const loader = new THREE.TextureLoader();
  const paperTex = loader.load('assets/1765-saka-1843-ce-jnanesvari-jnandeva-dnyaneshwar.jpg');
  paperTex.colorSpace = THREE.SRGBColorSpace;
  paperTex.anisotropy = renderer.capabilities.getMaxAnisotropy();
  const paper = new THREE.Mesh(new THREE.PlaneGeometry(22, 27), new THREE.MeshStandardMaterial({ map: paperTex, roughness: 0.95 }));
  paper.rotation.x = -Math.PI / 2;
  paper.position.z = -1;
  paper.receiveShadow = true;
  scene.add(paper);

  // Brass matrix: octagonal die with the engraving as a bump map, turned brass handle above it.
  const brass = new THREE.MeshStandardMaterial({ color: 0x9c7840, metalness: 1, roughness: 0.42 });
  const face = new THREE.CanvasTexture(sealFace(1024, '#fff', '#000', true));
  const faceMat = brass.clone();
  faceMat.bumpMap = face;
  faceMat.bumpScale = 6;
  faceMat.roughness = 0.55;

  // The stamp tool, modelled on 17th-century Deccani gilt-brass finials: an octagonal die, a lotus
  // petal collar, a pierced ogee-lattice shaft between beaded rings, and a scaled lotus bud on top.
  // All carving is drawn here as textures; nothing is copied from a photograph.
  const stamp = new THREE.Group();
  // Corners at pi/8 + k*pi/4, the same angles sealFace draws, so the engraved border sits on the edges.
  const die = new THREE.Mesh(new THREE.CylinderGeometry(1.5, 1.5, 0.45, 8, 1, false, Math.PI / 8), [brass, brass, faceMat]);
  die.position.y = 0.225;
  // The face is the bottom cap; give it planar UVs so the octagon texture sits on it.
  const pos = die.geometry.attributes.position, uv = die.geometry.attributes.uv;
  for (let i = 0; i < pos.count; i++) {
    if (pos.getY(i) < 0) uv.setXY(i, 0.5 + pos.getX(i) / 3.2, 0.5 + pos.getZ(i) / 3.2);
  }
  stamp.add(die);

  // A carved texture drawn into a canvas, used as a bump map and to darken the recesses.
  function carved(draw, w = 1024, h = 1024, rx = 1, ry = 1) {
    const c = document.createElement('canvas');
    c.width = w; c.height = h;
    const g = c.getContext('2d');
    g.fillStyle = '#fff'; g.fillRect(0, 0, w, h);
    draw(g, w, h);
    const t = new THREE.CanvasTexture(c);
    t.wrapS = t.wrapT = THREE.RepeatWrapping;
    t.repeat.set(rx, ry);
    return t;
  }
  function carvedBrass(tex, bump) {
    const m = brass.clone();
    m.bumpMap = tex; m.bumpScale = bump;
    m.aoMap = tex; m.aoMapIntensity = 0.9;
    return m;
  }
  // Ogee lattice: rows of almond cells, each cell sunk, the net between them left standing.
  const lattice = carved((g, w, h) => {
    const cols = 8, rows = 6, cw = w / cols, ch = h / rows;
    g.fillStyle = '#111';
    for (let r = -1; r <= rows; r++) for (let c = -1; c <= cols; c++) {
      const x = (c + (r % 2 ? 0.5 : 0)) * cw + cw / 2, y = r * ch + ch / 2;
      g.beginPath();
      g.moveTo(x, y - ch * 0.46);
      g.bezierCurveTo(x + cw * 0.42, y - ch * 0.2, x + cw * 0.42, y + ch * 0.2, x, y + ch * 0.46);
      g.bezierCurveTo(x - cw * 0.42, y + ch * 0.2, x - cw * 0.42, y - ch * 0.2, x, y - ch * 0.46);
      g.fill();
    }
  }, 1024, 768, 2, 1);
  // Overlapping scale-petals for the lotus bud.
  const scales = carved((g, w, h) => {
    const n = 16, rows = 12, sw = w / n, sh = h / rows;
    for (let r = rows; r >= -1; r--) for (let c = -1; c <= n; c++) {
      const x = (c + (r % 2 ? 0.5 : 0)) * sw, y = r * sh;
      const grd = g.createRadialGradient(x, y, sw * 0.1, x, y, sw * 0.62);
      grd.addColorStop(0, '#fff'); grd.addColorStop(0.8, '#bbb'); grd.addColorStop(1, '#222');
      g.fillStyle = grd;
      g.beginPath(); g.arc(x, y, sw * 0.6, 0, Math.PI); g.fill();
    }
  }, 1024, 1024, 1, 1);
  // Fine vertical fluting for collars.
  const flutes = carved((g, w, h) => {
    for (let i = 0; i < 64; i++) { g.fillStyle = i % 2 ? '#fff' : '#333'; g.fillRect((i * w) / 64, 0, w / 128, h); }
  }, 1024, 64, 1, 1);

  const lathe = (pts, mat, y) => {
    const m = new THREE.Mesh(new THREE.LatheGeometry(pts.map(([x, yy]) => new THREE.Vector2(x, yy)), 96), mat);
    m.position.y = y;
    stamp.add(m);
    return m;
  };
  const beads = (radius, y, count, size) => {
    const geo = new THREE.SphereGeometry(size, 12, 8);
    for (let i = 0; i < count; i++) {
      const a = (i / count) * Math.PI * 2;
      const b = new THREE.Mesh(geo, brass);
      b.position.set(Math.cos(a) * radius, y, Math.sin(a) * radius);
      stamp.add(b);
    }
  };
  const petals = (radius, y, count, len, tilt, mat) => {
    const geo = new THREE.SphereGeometry(1, 16, 10);
    for (let i = 0; i < count; i++) {
      const a = (i / count) * Math.PI * 2;
      const p = new THREE.Mesh(geo, mat);
      p.scale.set(len * 0.38, len, len * 0.16);
      p.position.set(Math.cos(a) * radius, y, Math.sin(a) * radius);
      p.rotation.set(0, -a + Math.PI / 2, 0);
      p.rotateX(tilt);
      stamp.add(p);
    }
  };

  // Plinth and petal collar above the die.
  lathe([[0, 0], [1.05, 0], [1.1, 0.08], [0.95, 0.14], [0.98, 0.22], [0.8, 0.3], [0, 0.3]], carvedBrass(flutes, 3), 0.45);
  petals(0.62, 0.95, 12, 0.42, -0.55, brass);
  beads(0.5, 1.12, 22, 0.055);
  // Lattice shaft.
  lathe([[0.36, 0], [0.4, 0.12], [0.38, 0.9], [0.4, 1.02]], carvedBrass(lattice, 5), 1.15);
  beads(0.44, 2.2, 20, 0.05);
  lathe([[0, 0], [0.5, 0], [0.56, 0.06], [0.42, 0.14], [0, 0.14]], carvedBrass(flutes, 2), 2.2);
  // Lotus calyx and the scaled bud.
  petals(0.42, 2.48, 10, 0.34, -0.85, brass);
  const bud = [];
  for (let i = 0; i <= 24; i++) {
    const t = i / 24;
    bud.push([Math.sin(Math.PI * Math.pow(t, 0.8)) * 0.48 * (1 - t * 0.35), t * 1.15]);
  }
  bud.push([0, 1.2]);
  lathe(bud, carvedBrass(scales, 4), 2.36);
  const tip = new THREE.Mesh(new THREE.ConeGeometry(0.06, 0.28, 16), brass);
  tip.position.y = 3.68;
  stamp.add(tip);
  stamp.traverse(o => { if (o.isMesh) o.castShadow = true; });
  const REST = 1.6;
  stamp.position.y = REST;
  scene.add(stamp);

  // Vermilion impression texture: the face, unmirrored, with a little uneven ink.
  const inkCanvas = sealFace(1024, 'rgba(178,34,30,0.92)', 'rgba(0,0,0,0)', false);
  const ictx = inkCanvas.getContext('2d');
  ictx.globalCompositeOperation = 'destination-out';
  for (let i = 0; i < 900; i++) {
    ictx.fillStyle = `rgba(0,0,0,${Math.random() * 0.35})`;
    ictx.fillRect(Math.random() * 1024, Math.random() * 1024, 1 + Math.random() * 7, 1 + Math.random() * 7);
  }
  const inkTex = new THREE.CanvasTexture(inkCanvas);
  inkTex.colorSpace = THREE.SRGBColorSpace;

  const spots = [[-1.7, 1.2], [1.7, 1.6], [-1.4, -1.0], [1.8, -0.6], [0.1, 2.6], [0, 0.3]];
  const impressions = [];
  let next = 0;
  function leaveImpression() {
    const m = new THREE.Mesh(new THREE.PlaneGeometry(3.3, 3.3),
      new THREE.MeshStandardMaterial({ map: inkTex, transparent: true, roughness: 0.6, depthWrite: false }));
    m.rotation.set(-Math.PI / 2, 0, (Math.random() - 0.5) * 0.25);
    m.position.set(stamp.position.x, 0.005 + impressions.length * 0.0005, stamp.position.z);
    m.receiveShadow = true;
    scene.add(m);
    impressions.push(m);
    if (impressions.length > 5) scene.remove(impressions.shift());
  }
  function press() {
    if (stamp.userData.t !== undefined) return;
    const [x, z] = spots[next++ % spots.length];
    stamp.userData = { t: 0, from: stamp.position.clone(), to: new THREE.Vector3(x, REST, z), left: false };
  }

  const tilt = { x: 0, y: 0 };
  addEventListener('pointermove', e => {
    tilt.x = (e.clientX / innerWidth - 0.5) * 0.5;
    tilt.y = (e.clientY / innerHeight - 0.5) * 0.35;
  }, { passive: true });
  const cv = renderer.domElement;
  cv.tabIndex = 0;
  cv.setAttribute('role', 'button');
  cv.setAttribute('aria-label', 'Press the seal');
  cv.addEventListener('click', press);
  cv.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); press(); } });
  document.addEventListener('mohar:receipt', press);

  function size() {
    const w = host.clientWidth, h = host.clientHeight;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    // Narrow frames see less width, so widen the view to keep every press spot in shot.
    camera.fov = w / h < 0.9 ? 40 : 32;
    camera.updateProjectionMatrix();
  }
  new ResizeObserver(size).observe(host);
  size();
  let visible = true;
  new IntersectionObserver(([e]) => { visible = e.isIntersecting; }).observe(host);

  const timer = new THREE.Timer();
  const ease = t => t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
  renderer.setAnimationLoop(time => {
    timer.update(time);
    if (!visible) return;
    const dt = timer.getDelta();
    stamp.rotation.z += (-tilt.x - stamp.rotation.z) * 0.07;
    stamp.rotation.x += (tilt.y - stamp.rotation.x) * 0.07;
    const u = stamp.userData;
    if (u.t !== undefined) {
      u.t += dt / 1.1;
      const move = ease(Math.min(u.t / 0.45, 1));
      stamp.position.x = u.from.x + (u.to.x - u.from.x) * move;
      stamp.position.z = u.from.z + (u.to.z - u.from.z) * move;
      const p = Math.max(0, Math.min((u.t - 0.45) / 0.55, 1));
      stamp.position.y = REST - Math.sin(p * Math.PI) * REST;
      if (p >= 0.5 && !u.left) { leaveImpression(); u.left = true; }
      if (u.t >= 1) stamp.userData = {};
    } else {
      stamp.position.y = REST + Math.sin(timer.getElapsed() * 1.4) * 0.05;
      // Drift back to the centre of the page between presses.
      stamp.position.x += (0 - stamp.position.x) * 0.04;
      stamp.position.z += (0.3 - stamp.position.z) * 0.04;
    }
    renderer.render(scene, camera);
  });
}

if (host && gl && !reduced) start();
