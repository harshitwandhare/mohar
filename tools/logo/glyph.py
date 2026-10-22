import json, uharfbuzz as hb
from fontTools.ttLib import TTFont
from fontTools.pens.recordingPen import DecomposingRecordingPen
from PIL import Image, ImageDraw
import os
HERE=os.path.dirname(os.path.abspath(__file__))
P=os.path.join(HERE,'fonts','NotoSansModi-Regular.ttf')
f=TTFont(P); gs=f.getGlyphSet()
font=hb.Font(hb.Face(open(P,'rb').read())); b=hb.Buffer(); b.add_str('\U00011626\U0001163B'); b.guess_segment_properties(); hb.shape(font,b)
contours=[]; x=0
for i,p in zip(b.glyph_infos,b.glyph_positions):
    n=f.getGlyphName(i.codepoint); pen=DecomposingRecordingPen(gs); gs[n].draw(pen)
    ox,oy=x+p.x_offset,p.y_offset; cur=[]; last=None
    for op,args in pen.value:
        if op=='moveTo': cur=[args[0]]; last=args[0]
        elif op=='lineTo': cur.append(args[0]); last=args[0]
        elif op=='qCurveTo':
            pts=list(args); 
            if pts[-1] is None: pts=pts[:-1]; # implied
            # split into quadratic segments with implied on-points
            ons=[last]; 
            for k in range(len(pts)-1):
                c=pts[k]; nxt=pts[k+1] if k+1<len(pts)-1 else pts[-1]
                end=nxt if k+1==len(pts)-1 else ((c[0]+nxt[0])/2,(c[1]+nxt[1])/2)
                s=last
                for t in range(1,9):
                    t/=8; cur.append(((1-t)**2*s[0]+2*(1-t)*t*c[0]+t*t*end[0],(1-t)**2*s[1]+2*(1-t)*t*c[1]+t*t*end[1]))
                last=end
        elif op=='curveTo':
            c1,c2,e=args; s=last
            for t in range(1,13):
                t/=12; u=1-t; cur.append((u**3*s[0]+3*u*u*t*c1[0]+3*u*t*t*c2[0]+t**3*e[0],u**3*s[1]+3*u*u*t*c1[1]+3*u*t*t*c2[1]+t**3*e[1]))
            last=e
        elif op in('closePath','endPath'):
            if len(cur)>2: contours.append({"g":n,"pts":[(px+ox,py+oy) for px,py in cur]})
            cur=[]
    x+=p.x_advance
xs=[p[0] for c in contours for p in c["pts"]]; ys=[p[1] for c in contours for p in c["pts"]]
bb=(min(xs),min(ys),max(xs),max(ys)); print('ink bbox',bb,'contours',len(contours))
json.dump({'contours':contours,'bbox':bb},open(os.path.join(HERE,'glyph.json'),'w'))
# verification raster (even-odd via XOR)
S=0.5; W=int((bb[2]-bb[0])*S)+80; H=int((bb[3]-bb[1])*S)+80
img=Image.new('1',(W,H),0)
for c in contours:
    m=Image.new('1',(W,H),0); ImageDraw.Draw(m).polygon([((px-bb[0])*S+40,H-((py-bb[1])*S+40)) for px,py in c["pts"]],fill=1)
    img=Image.frombytes('1',(W,H),bytes(a^b for a,b in zip(img.tobytes(),m.tobytes())))
img.convert('L').point(lambda v:255-v).save('src/glyph-check.png')
