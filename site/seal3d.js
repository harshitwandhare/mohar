// The hero seal: an octagonal brass matrix in the Maratha tradition, engraved with मोहर. It tilts toward the
// pointer; a click (or a receipt from the simulator) presses a vermilion impression onto the manuscript.
// Without WebGL 2, or with reduced motion, the still image in the markup stays.
import * as THREE from 'three';
import { HDRLoader } from 'three/addons/loaders/HDRLoader.js';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';
import { DRACOLoader } from 'three/addons/loaders/DRACOLoader.js';

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

  // Load the model and the studio first; if either fails, the still image stays.
  const draco = new DRACOLoader().setDecoderPath('vendor/draco/');
  let gltf, hdr;
  try {
    [gltf, hdr] = await Promise.all([
      new GLTFLoader().setDRACOLoader(draco).loadAsync('assets/stamp.glb'),
      // A photographed studio (Poly Haven, CC0) gives the metal and lacquer real softboxes to reflect.
      new HDRLoader().loadAsync('assets/pbr/brown_photostudio_02_1k.hdr'),
    ]);
  } catch {
    return;
  } finally {
    draco.dispose();
  }

  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  renderer.shadowMap.enabled = true;
  renderer.shadowMap.type = THREE.PCFSoftShadowMap;
  renderer.toneMapping = THREE.AgXToneMapping;
  renderer.toneMappingExposure = 1.15;
  host.append(renderer.domElement);
  host.classList.add('live');

  const scene = new THREE.Scene();
  const pmrem = new THREE.PMREMGenerator(renderer);
  scene.environment = pmrem.fromEquirectangular(hdr).texture;
  hdr.dispose();
  scene.environmentIntensity = 0.75;

  const camera = new THREE.PerspectiveCamera(32, 1, 0.1, 100);
  camera.position.set(0, 7.6, 12.8);
  camera.lookAt(0, 2.8, 0);

  // One warm lamp: a pool of light on the page that falls off into the dark ground around it.
  const lamp = new THREE.SpotLight(0xffe2b8, 420, 40, Math.PI / 6, 0.9, 2);
  lamp.position.set(-3, 14, 5);
  lamp.target.position.set(0, 0, 0.5);
  lamp.castShadow = true;
  lamp.shadow.mapSize.set(2048, 2048);
  lamp.shadow.radius = 8;
  lamp.shadow.bias = -0.0004;
  // A cool rim from behind separates the stamp from the dark ground.
  const rim = new THREE.DirectionalLight(0xd8e4ff, 1.4);
  rim.position.set(4, 6, -8);
  scene.add(lamp, lamp.target, rim, new THREE.AmbientLight(0xffffff, 0.04));

  const aniso = renderer.capabilities.getMaxAnisotropy();
  // Paper: an 1843 Marathi manuscript page (credited on the page).
  const loader = new THREE.TextureLoader();
  const paperTex = loader.load('assets/1765-saka-1843-ce-jnanesvari-jnandeva-dnyaneshwar.jpg');
  paperTex.colorSpace = THREE.SRGBColorSpace;
  paperTex.anisotropy = aniso;
  const paper = new THREE.Mesh(new THREE.PlaneGeometry(22, 27), new THREE.MeshStandardMaterial({ map: paperTex, roughness: 0.95 }));
  paper.rotation.x = -Math.PI / 2;
  paper.position.z = -1;
  paper.receiveShadow = true;
  scene.add(paper);

  // The stamp is modelled and carved in Blender (tools/stamp/build_stamp.py): an octagonal brass die
  // with incised lotus engraving, a turned brass plinth and ferrule, and a sheesham handle with two
  // bands of vine relief. Ambient occlusion is baked into its vertex colours.
  // Fine lathe rings in the roughness, so the brass reads as turned metal, not plastic.
  const rings = document.createElement('canvas');
  rings.width = 4; rings.height = 512;
  const rg = rings.getContext('2d');
  for (let y = 0; y < 512; y++) { const v = 150 + Math.random() * 60; rg.fillStyle = `rgb(${v},${v},${v})`; rg.fillRect(0, y, 4, 1); }
  const ringTex = new THREE.CanvasTexture(rings);
  ringTex.wrapS = ringTex.wrapT = THREE.RepeatWrapping;
  ringTex.repeat.set(1, 3);
  const brass = new THREE.MeshPhysicalMaterial({ color: 0xb48c52, metalness: 1, roughness: 0.42, roughnessMap: ringTex, vertexColors: true });
  // The printing face is drawn here, so its engraving always matches the impression.
  const face = new THREE.CanvasTexture(sealFace(1024, '#fff', '#000', true));
  const faceMat = new THREE.MeshPhysicalMaterial({ color: 0xb48c52, metalness: 1, roughness: 0.55, bumpMap: face, bumpScale: 6 });

  // Photographed rosewood (Poly Haven, CC0): sheesham is Indian rosewood. Grain runs along the handle.
  const pbr = (name, srgb) => {
    const t = loader.load('assets/pbr/rosewood_veneer1_' + name + '_1k.jpg');
    t.wrapS = t.wrapT = THREE.RepeatWrapping;
    t.repeat.set(2, 0.5);
    t.anisotropy = aniso;
    if (srgb) t.colorSpace = THREE.SRGBColorSpace;
    return t;
  };
  const wood = new THREE.MeshPhysicalMaterial({
    map: pbr('diff', true), normalMap: pbr('nor_gl'), roughnessMap: pbr('rough'), vertexColors: true,
    color: 0xa89482, roughness: 0.8, clearcoat: 0.35, clearcoatRoughness: 0.18,
  });

  const stamp = new THREE.Group();
  gltf.scene.traverse(o => {
    if (!o.isMesh) return;
    o.material = o.name.startsWith('wood') ? wood : brass;
    o.castShadow = true;
  });
  stamp.add(gltf.scene);
  // Bottom face, corners at pi/8 + k*pi/4 like the model and sealFace, so the border meets the edges.
  const faceGeo = new THREE.CircleGeometry(1.5, 8, Math.PI / 8);
  const fp = faceGeo.attributes.position, fuv = faceGeo.attributes.uv;
  for (let i = 0; i < fp.count; i++) fuv.setXY(i, 0.5 + fp.getX(i) / 3.2, 0.5 + fp.getY(i) / 3.2);
  const die = new THREE.Mesh(faceGeo, faceMat);
  die.rotation.x = Math.PI / 2;
  stamp.add(die);
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
