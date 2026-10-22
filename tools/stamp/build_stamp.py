"""Builds the hero seal stamp for the Mohar site and exports site/assets/stamp.glb.

Run with Blender 5.2 or newer:
    blender --background --factory-startup --python tools/stamp/build_stamp.py

Every part is generated here: turned profiles are swept around the axis, and the carving is cut
into the geometry itself (raised vine relief on the wooden bands, incised lotus engraving on the
brass die). Ambient occlusion is baked into vertex colours so the cuts darken like real carving.
The export is Draco-compressed to keep the file small; the site decodes it with three.js DRACOLoader.
The die's printing face is drawn by the site at runtime, so it is left open here.

Units match the site's scene: the die's bottom face sits at height 0 and its corners are 1.5
from the axis. Blender is Z-up; the glTF exporter converts to Y-up.
"""
import math
import os

import bpy
import numpy as np

OUT = os.path.join(os.path.dirname(__file__), "..", "..", "site", "assets", "stamp.glb")
TAU = math.tau


def smooth(edge0, edge1, x):
    t = np.clip((x - edge0) / (edge1 - edge0), 0.0, 1.0)
    return t * t * (3 - 2 * t)


# ---- carving patterns: functions of (s, t) on a band, 0 = surface, 1 = full depth ----------------

def vine_relief(s, t, waves=6):
    """Indian vine scroll in raised relief: the motif stands, the ground between is cut.

    s runs around the band (0..1), t along it (0..1). Returns cut depth 0..1.
    """
    x = s * waves  # one wave per unit
    y = t
    stem_y = 0.5 + 0.2 * np.sin(x * TAU)
    d = np.abs(y - stem_y)
    motif = 1 - smooth(0.035, 0.06, d)
    # A leaf on each crest and trough, pointing away from the stem; a curl tucked in beside it.
    for k in range(waves * 2):
        cx = (k + 0.5) / 2
        up = k % 2 == 0
        cy = 0.5 + (0.2 if up else -0.2) + (0.13 if up else -0.13)
        ang = -0.55 if up else 0.55
        dx, dy = (x - cx), (y - cy)
        rx = dx * math.cos(ang) - dy * math.sin(ang)
        ry = dx * math.sin(ang) + dy * math.cos(ang)
        e = np.sqrt((rx / 0.14) ** 2 + (ry / 0.085) ** 2)
        leaf = 1 - smooth(0.85, 1.0, e)
        vein = smooth(0.006, 0.02, np.abs(ry)) * leaf  # a fine vein cut along the leaf
        motif = np.maximum(motif, leaf * (0.35 + 0.65 * vein))
        ccx, ccy = cx + 0.22, 0.5 + (-0.1 if up else 0.1)
        r = np.sqrt((x - ccx) ** 2 + (y - ccy) ** 2)
        curl = 1 - smooth(0.045, 0.065, np.abs(r - 0.06))
        motif = np.maximum(motif, curl)
    # Raised borders top and bottom, with a groove inside each.
    border = (smooth(0.0, 0.0001, 0.1 - y) + smooth(0.0, 0.0001, y - 0.9)).clip(0, 1)
    groove = 1 - smooth(0.012, 0.025, np.minimum(np.abs(y - 0.13), np.abs(y - 0.87)))
    stand = np.maximum(motif, border) * (1 - groove)
    return 1 - stand


def die_side(s, t):
    """Incised engraving on one side of the die: framing lines, beaded rows, lotus buds and diamonds."""
    cut = np.zeros_like(s)
    for yy in (0.12, 0.88):
        cut = np.maximum(cut, 1 - smooth(0.012, 0.022, np.abs(t - yy)))
    for yy in (0.2, 0.8):
        bx = (s * 16) % 1 - 0.5
        cut = np.maximum(cut, 1 - smooth(0.13, 0.2, np.sqrt(bx ** 2 + ((t - yy) * 5) ** 2)))
    for k in range(3):
        cx = (k + 0.5) / 3
        dx, dy = (s - cx) * 3.2, (t - 0.5) * 1.0
        # Lotus bud outline: an ogee arch, incised as a line, with a centre vein.
        width = 0.32 * (1 - ((dy + 0.24) / 0.48) ** 2).clip(0, 1) ** 0.5 * (1 - 0.6 * (dy > 0.05))
        inside = (np.abs(dx) < width) & (dy > -0.24) & (dy < 0.22)
        edge = inside & (np.abs(np.abs(dx) - width) < 0.05)
        cut = np.maximum(cut, edge.astype(float))
        cut = np.maximum(cut, ((np.abs(dx) < 0.018) & (dy > -0.15) & (dy < 0.16)).astype(float))
        if k < 2:
            ddx, ddy = (s - (k + 1) / 3) * 3.2, (t - 0.5)
            diamond = np.abs(ddx) / 0.09 + np.abs(ddy) / 0.12
            cut = np.maximum(cut, (1 - smooth(0.8, 1.0, diamond)) * 0.8)
    return cut


def petal_ring(theta, r):
    """Incised ring of 32 petals and a bead row, on the die's top between plinth and edge."""
    cut = np.zeros_like(theta)
    a = (theta / TAU * 32) % 1 - 0.5
    pr = (r - 1.24) / 0.1
    petal = np.sqrt((a / 0.32) ** 2 + pr ** 2)
    cut = np.maximum(cut, 1 - smooth(0.06, 0.14, np.abs(petal - 0.85)))
    bead = np.sqrt(((((theta / TAU * 64) % 1) - 0.5) / 0.3) ** 2 + ((r - 1.37) / 0.02) ** 2)
    cut = np.maximum(cut, 1 - smooth(0.7, 1.0, bead))
    cut = np.maximum(cut, 1 - smooth(0.006, 0.012, np.abs(r - 1.15)))
    return cut


# ---- geometry ------------------------------------------------------------------------------------

def mesh_from_grid(name, verts, nu, nv, closed_u, uv=None):
    """Quad grid (nu around, nv along) to a Blender mesh object."""
    me = bpy.data.meshes.new(name)
    faces = []
    for j in range(nv - 1):
        for i in range(nu if closed_u else nu - 1):
            i2 = (i + 1) % nu
            a, b, c, d = j * nu + i, j * nu + i2, (j + 1) * nu + i2, (j + 1) * nu + i
            faces.append((a, b, c, d))
    me.from_pydata(verts.tolist(), [], faces)
    if uv is not None:
        layer = me.uv_layers.new(name="UVMap")
        loop_v = np.zeros(len(me.loops), dtype=np.int64)
        me.loops.foreach_get("vertex_index", loop_v)
        layer.data.foreach_set("uv", uv[loop_v].ravel())
    me.update()
    ob = bpy.data.objects.new(name, me)
    bpy.context.collection.objects.link(ob)
    for p in me.polygons:
        p.use_smooth = True
    return ob


def lathe(name, profile, z0, around=192, per_seg=6, carve=None, depth=0.0, waves=6):
    """Sweep a (radius, height) profile around Z. carve(s, t) cuts radially inward by depth."""
    pts = []
    for (r0, h0), (r1, h1) in zip(profile, profile[1:]):
        for k in range(per_seg):
            f = k / per_seg
            pts.append((r0 + (r1 - r0) * f, h0 + (h1 - h0) * f))
    pts.append(profile[-1])
    pts = np.array(pts)
    seg = np.r_[0, np.cumsum(np.hypot(*np.diff(pts, axis=0).T))]
    tv = seg / seg[-1]
    nu, nv = around, len(pts)
    s = np.tile(np.arange(nu) / nu, nv)
    t = np.repeat(tv, nu)
    r = np.repeat(pts[:, 0], nu)
    if carve is not None:
        r = r - depth * carve(s, t)
    th = s * TAU
    verts = np.stack([r * np.cos(th), r * np.sin(th), np.repeat(pts[:, 1], nu) + z0], 1)
    uv = np.stack([s, t], 1)
    return mesh_from_grid(name, verts, nu, nv, True, uv)


def octagon_die(name, R=1.5, H=0.45, side_res=(220, 70), top_res=(512, 60)):
    """The die body: eight engraved sides and an engraved top ring. Bottom left open for the site."""
    apothem = R * math.cos(math.pi / 8)
    half = R * math.sin(math.pi / 8)
    parts = []
    nu, nv = side_res
    for k in range(8):
        # Face centres at k*pi/4 + pi/8 offset so corners land where the site's seal face expects.
        a = k * math.pi / 4
        s = np.tile(np.linspace(0, 1, nu), nv)
        t = np.repeat(np.linspace(0, 1, nv), nu)
        inward = 0.012 * die_side(s, t)
        x = -half + 2 * half * s
        n = np.array([math.cos(a), math.sin(a)])
        tang = np.array([-math.sin(a), math.cos(a)])
        px = (apothem - inward) * n[0] + x * tang[0]
        py = (apothem - inward) * n[1] + x * tang[1]
        verts = np.stack([px, py, t * H], 1)
        parts.append(mesh_from_grid(f"{name}_side{k}", verts, nu, nv, False, np.stack([s, t], 1)))
    # Top: polar grid from the plinth's foot out to the octagon edge.
    nu, nv = top_res
    th = np.tile(np.linspace(0, TAU, nu, endpoint=False), nv)
    # Rows run from the edge inward so the faces point up (profiles that rise face outward).
    f = np.repeat(np.linspace(1, 0, nv), nu)
    # Distance to the octagon edge along each angle (corners at k*pi/4 + pi/8).
    local = ((th - math.pi / 8) % (math.pi / 4)) - math.pi / 8
    edge = apothem / np.cos(local)
    r = 1.08 + (edge - 1.08) * f
    z = H - 0.009 * petal_ring(th, r)
    verts = np.stack([r * np.cos(th), r * np.sin(th), z], 1)
    parts.append(mesh_from_grid(f"{name}_top", verts, nu, nv, True, np.stack([th / TAU, f], 1)))
    return join(parts, name)


def join(objs, name):
    bpy.ops.object.select_all(action="DESELECT")
    for o in objs:
        o.select_set(True)
    bpy.context.view_layer.objects.active = objs[0]
    bpy.ops.object.join()
    ob = bpy.context.view_layer.objects.active
    ob.name = name
    ob.data.name = name
    return ob


def beads(name, radius, z, count, size):
    objs = []
    for i in range(count):
        a = i / count * TAU
        bpy.ops.mesh.primitive_uv_sphere_add(segments=16, ring_count=10, radius=size,
                                             location=(radius * math.cos(a), radius * math.sin(a), z))
        o = bpy.context.active_object
        bpy.ops.object.shade_smooth()
        objs.append(o)
    return join(objs, name)


def main():
    bpy.ops.wm.read_factory_settings(use_empty=True)
    brass, wood = [], []

    brass.append(octagon_die("brass_die"))
    # Plinth and ferrule, turned brass: a stepped base, a cove, a bead row, the collar the wood sits in.
    brass.append(lathe("brass_plinth", [(1.08, 0), (1.12, 0.07), (0.98, 0.13), (1.0, 0.2), (0.72, 0.3),
                                        (0.62, 0.42), (0.0, 0.42)], 0.45, around=192, per_seg=8))
    brass.append(beads("brass_beads", 0.64, 0.9, 36, 0.045))
    brass.append(lathe("brass_ferrule", [(0.0, 0), (0.6, 0), (0.62, 0.05), (0.56, 0.2), (0.6, 0.26),
                                         (0.5, 0.3), (0.0, 0.3)], 0.92, per_seg=8))

    # The handle, turned sheesham. Profile: a neck, a carved band, a long grip with a cove and two
    # fillets, a second carved band, a bead, and a round knob.
    y0 = 1.22
    wood.append(lathe("wood_neck", [(0.0, 0), (0.5, 0), (0.46, 0.06), (0.4, 0.2), (0.36, 0.4),
                                    (0.385, 0.46), (0.4, 0.5)], y0, per_seg=10))
    wood.append(lathe("wood_band_low", [(0.4, 0), (0.42, 0.02), (0.42, 0.38), (0.4, 0.4)], y0 + 0.5,
                      around=768, per_seg=60, carve=lambda s, t: vine_relief(s, t, 6), depth=0.045))
    wood.append(lathe("wood_grip", [(0.4, 0), (0.37, 0.05), (0.335, 0.16), (0.31, 0.32), (0.325, 0.5),
                                    (0.37, 0.72), (0.43, 0.93), (0.46, 1.04), (0.47, 1.1), (0.46, 1.14)],
                      y0 + 0.9, per_seg=12))
    wood.append(lathe("wood_band_high", [(0.46, 0), (0.48, 0.02), (0.48, 0.29), (0.46, 0.31)], y0 + 2.04,
                      around=768, per_seg=60, carve=lambda s, t: vine_relief(s, t, 7), depth=0.045))
    knob = [(0.46, 0), (0.4, 0.04), (0.33, 0.1), (0.36, 0.14), (0.33, 0.18)]
    for i in range(1, 25):
        u = i / 24
        knob.append((0.56 * math.sin(math.pi * (0.1 + 0.9 * u)) * (1 - 0.12 * u), 0.18 + 0.86 * u))
    knob.append((0.0, 1.05))
    wood.append(lathe("wood_knob", knob, y0 + 2.35, per_seg=6))
    brass.append(lathe("brass_cap", [(0.0, 0.0), (0.17, 0.0), (0.14, 0.05), (0.0, 0.07)], y0 + 3.39, per_seg=4))

    brass_ob, wood_ob = join(brass, "brass"), join(wood, "wood")
    for ob in (brass_ob, wood_ob):
        bpy.context.view_layer.objects.active = ob
        bpy.ops.object.select_all(action="DESELECT")
        ob.select_set(True)
        ob.data.color_attributes.new("ao", "BYTE_COLOR", "POINT")

    # Bake ambient occlusion into vertex colours with Cycles.
    scene = bpy.context.scene
    scene.render.engine = "CYCLES"
    scene.cycles.device = "CPU"
    scene.cycles.samples = 64
    scene.render.bake.target = "VERTEX_COLORS"
    for ob in (brass_ob, wood_ob):
        mat = bpy.data.materials.new(ob.name)
        ob.data.materials.append(mat)
        bpy.ops.object.select_all(action="DESELECT")
        ob.select_set(True)
        bpy.context.view_layer.objects.active = ob
        ob.data.color_attributes.active_color = ob.data.color_attributes["ao"]
        bpy.ops.object.bake(type="AO")

    # Reduce triangle count while keeping the carving: collapse flat areas first.
    for ob, ratio in ((brass_ob, 0.35), (wood_ob, 0.3)):
        d = ob.modifiers.new("decimate", "DECIMATE")
        d.ratio = ratio
        d.use_collapse_triangulate = True
        bpy.context.view_layer.objects.active = ob
        bpy.ops.object.modifier_apply(modifier="decimate")

    bpy.ops.object.select_all(action="SELECT")
    bpy.ops.export_scene.gltf(filepath=os.path.abspath(OUT), export_format="GLB", use_selection=True,
                              export_attributes=True, export_vertex_color="ACTIVE", export_all_vertex_colors=False,
                              export_materials="PLACEHOLDER", export_yup=True,
                              export_draco_mesh_compression_enable=True,
                              export_draco_mesh_compression_level=10)
    for ob in (brass_ob, wood_ob):
        print(ob.name, len(ob.data.vertices), "verts", len(ob.data.polygons), "faces")
    print("wrote", os.path.abspath(OUT), os.path.getsize(OUT), "bytes")


main()
