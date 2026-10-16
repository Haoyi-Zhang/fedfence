"""Vector drawing primitives; copied into each independent project generator."""
import argparse
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, Polygon, Circle, FancyArrowPatch

plt.rcParams.update({'font.family':'STIXGeneral', 'mathtext.fontset':'stix',
                     'font.size':9, 'pdf.fonttype':42, 'ps.fonttype':42,
                     'text.usetex':False, 'axes.unicode_minus':False})
CM = 1 / 2.54

class Drawing:
    def __init__(self, bounds):
        x0,y0,x1,y1 = bounds
        self.fig = plt.figure(figsize=((x1-x0)*CM,(y1-y0)*CM))
        self.ax = self.fig.add_axes([0,0,1,1], xlim=(x0,x1), ylim=(y0,y1))
        self.ax.set_aspect('equal'); self.ax.axis('off')
        self.nodes = {}
        self.labels = []

    def text(self,x,y,label,size=9,ha='center',va='center'):
        artist=self.ax.text(x,y,label,fontsize=size,ha=ha,va=va,
                            linespacing=1.15,clip_on=False,zorder=4)
        self.labels.append([artist,None])
        return artist

    def box(self,name,x,y,w,h,label,dashed=False,shape='rect',size=9):
        style = {'edgecolor':'black','facecolor':'white','linewidth':.55,
                 'linestyle':(0,(4,3)) if dashed else 'solid', 'zorder':2}
        if shape == 'diamond':
            obj = Polygon([(x-w/2,y),(x,y+h/2),(x+w/2,y),(x,y-h/2)],**style)
        elif shape == 'circle': obj = Circle((x,y),w/2,**style)
        else: obj = Rectangle((x-w/2,y-h/2),w,h,**style)
        self.ax.add_patch(obj); self.text(x,y,label,size)
        self.labels[-1][1]=(x-w/2,y-h/2,x+w/2,y+h/2)
        self.nodes[name] = (x,y,w,h,shape)

    def point(self,name,side):
        x,y,w,h,_ = self.nodes[name]
        return {'n':(x,y+h/2),'s':(x,y-h/2),'e':(x+w/2,y),
                'w':(x-w/2,y),'nw':(x-w/2,y+h/2),
                'ne':(x+w/2,y+h/2),'c':(x,y)}[side]

    def line(self,points,dashed=False):
        xs,ys=zip(*points)
        self.ax.plot(xs,ys,color='black',linewidth=.55,
                     linestyle=(0,(4,3)) if dashed else 'solid',zorder=1)

    def arrow(self,p,q,dashed=False,via=()):
        points=[p,*via,q]
        if via:self.line(points[:-1],dashed)
        self.ax.add_patch(FancyArrowPatch(points[-2],points[-1],
                         arrowstyle='-|>',mutation_scale=7.5,linewidth=.55,
                         color='black',shrinkA=0,shrinkB=0,
                         linestyle=(0,(4,3)) if dashed else 'solid',zorder=1))

    def edge(self,a,b,sa='s',sb='n',**kwargs):
        self.arrow(self.point(a,sa),self.point(b,sb),**kwargs)

    def frame(self,x,y,w,h):
        self.ax.add_patch(Rectangle((x,y),w,h,fill=False,edgecolor='black',
                                   linewidth=.55,linestyle=(0,(4,3)),zorder=0))

    def save(self,out,name):
        # Fixed physical canvas: do not enlarge or rasterize the scientific figure.
        self.fig.canvas.draw()
        renderer=self.fig.canvas.get_renderer()
        x0,x1=self.ax.get_xlim();y0,y1=self.ax.get_ylim()
        for artist,node in self.labels:
            b=artist.get_window_extent(renderer).transformed(self.ax.transData.inverted())
            if b.x0<x0-.02 or b.x1>x1+.02 or b.y0<y0-.02 or b.y1>y1+.02:
                raise ValueError(name+': clipped label '+repr(artist.get_text()))
            if node and (b.x0<node[0]-.02 or b.x1>node[2]+.02 or b.y0<node[1]-.02 or b.y1>node[3]+.02):
                raise ValueError(name+': label exceeds node '+repr(artist.get_text()))
        self.fig.savefig(out/(name+'.pdf'),format='pdf',
                         metadata={'Creator':'Python Matplotlib','Producer':None,
                                   'CreationDate':None,'ModDate':None})
        plt.close(self.fig)







PUBLIC_UNITS=(9,10,20,1)
INTERVALS=[('Policy',0,4),('Issuer',1,5),('Workflow',2,6),('Governance',1,5)]
ARCHITECTURE_EDGES=[('contract','validate'),('snapshots','validate'),('validate','core'),('validate','positive'),('core','decision'),('positive','decision'),('decision','receipt')]

def architecture(out):
    d=Drawing((0,0,15.1,7.4))
    for name,x,y,label in [
        ('contract',2.3,6.2,'Separate release contract\nupper bound and positives'),
        ('snapshots',2.3,3.9,'Four supplied snapshots\nissuer, workflow,\ngovernance, policy'),
        ('validate',7.55,6.2,'Strict packet validation\nprofile, scope, digests,\nreview record, freshness'),
        ('core',7.55,3.9,'Existing analyzer\nregular-language safety\nand certificate replay'),
        ('positive',12.8,6.2,'Required identity checks\nmintable, intended,\naccepted'),
        ('decision',12.8,3.9,'Shared decision rule\npass / fail / unknown\ndependency report'),
        ('receipt',12.8,1.55,'Two-sided receipt\npacket and semantic result\ncurrent-code replay')]:
        d.box(name,x,y,4.15,1.35,label,size=8.5)
    for a,b in ARCHITECTURE_EDGES:
        if (a,b) in [('contract','validate'),('validate','positive'),('core','decision'),('snapshots','validate')]:d.edge(a,b,'e','w')
        else:d.edge(a,b)
    d.save(out,'architecture')

def collision(out):
    d=Drawing((0,0,14.9,5.4))
    for n,y,label in [('yes',4.0,'Mintable state $w_m$\nbranch: main\nenvironment: prod\nintended'),('no',1.25,'Mintable state $w_d$\nbranch: dev\nenvironment: prod\nunintended')]:
        d.box(n,2.15,y,4.0,1.65,label,size=8.5)
    d.box('obs',7.7,2.65,3.9,1.65,'One observation $y$\nenvironment subject\nsame audience',size=8.5)
    d.box('policy',12.8,2.65,3.7,1.65,'Policy accepts $y$\ntherefore admits\nboth states',size=8.5)
    d.edge('yes','obs','e','w');d.edge('no','obs','e','w')
    d.text(4.9,3.9,r'$\pi$');d.text(4.9,1.35,r'$\pi$')
    d.edge('obs','policy','e','w');d.save(out,'collision')

def decision(out):
    d=Drawing((0,0,11.0,6.0))
    for n,y,label in [('v',4.9,'Required premises supported, fresh,\nand internally consistent?'),('o',3.0,'Over-admission or loss of a\nvalid required identity?'),('p',1.1,'Completed checks agree: pass\nexit 0')]:
        d.box(n,3.25,y,6.0,1.05,label,size=8.5)
    d.box('u',9.1,4.9,2.9,1.05,'unknown\nexit 2',size=8.5)
    d.box('f',9.1,3.0,2.9,1.05,'fail\nexit 1',size=8.5)
    d.edge('v','u','e','w');d.text(6.9,5.2,'No',size=8.5)
    d.edge('v','o');d.text(2.8,3.95,'Yes',size=8.5)
    d.edge('o','f','e','w');d.text(6.9,3.3,'Yes',size=8.5)
    d.edge('o','p');d.text(2.8,2.05,'No',size=8.5);d.save(out,'decision')

def denominators(out):
    commits,roles,phases,extra=PUBLIC_UNITS
    assert phases==2*roles and phases+extra==21
    d=Drawing((0,0,14.9,4.9))
    for n,x,y,label in [('commits',2.2,3.7,f'{commits} frozen commits\nsource unit'),('roles',7.45,3.7,f'{roles} role contracts\nsports-store split'),('phases',12.7,3.7,f'{phases} ordinary phases\nbefore and after'),('extra',12.7,1.3,f'{extra} additional branch\nmicroticket empty input'),('total',7.45,1.3,'21 configurations\n10 pass / 10 fail\n1 unknown')]:
        d.box(n,x,y,4.05,1.45,label,size=8.5)
    d.edge('commits','roles','e','w');d.edge('roles','phases','e','w')
    d.edge('phases','total');d.edge('extra','total','w','e');d.save(out,'denominators')

def evidence(out):
    d=Drawing((0,0,12.3,7.1))
    for n,x,y,label in [('excerpt',2.75,5.9,'Frozen public excerpt\n24 hashes checked'),('annotation',9.25,5.9,'Source annotation\n24 stored classifications'),('full',9.25,3.6,'Public source context\n0 full files available'),('extract',2.75,3.6,'Executed public extraction\n0 runs'),('cloud',2.75,1.25,'Authenticated deployment\n0 cloud executions')]:
        d.box(n,x,y,4.95,1.35,label,size=8.5)
    d.edge('excerpt','annotation','e','w');d.edge('annotation','full',dashed=True)
    d.text(9.55,4.75,'not established',size=8,ha='left')
    d.edge('full','extract','w','e',dashed=True);d.edge('extract','cloud',dashed=True);d.save(out,'evidence')

def freshness(out):
    d=Drawing((0,0,12.0,6.1))
    def x(t):return 2.35+1.35*t
    d.arrow((x(0),1.05),(x(6.65),1.05));d.text(x(6.75),1.05,'$t$',ha='left')
    for t in range(7):
        d.line([(x(t),.96),(x(t),1.14)]);d.text(x(t),.68,str(t),size=8.5)
    for row,(name,a,b) in enumerate(INTERVALS):
        y=4.65-row*.8;d.text(2.12,y,name,ha='right',size=8.5)
        d.line([(x(a),y),(x(b),y)]);d.ax.plot([x(a),x(b)],[y,y],'o',markersize=2.8,color='black')
    lo=max(a for _,a,_ in INTERVALS);hi=min(b for _,_,b in INTERVALS);assert (lo,hi)==(2,4)
    for t in (lo,hi):d.line([(x(t),.9),(x(t),5.25)],dashed=True)
    d.arrow((x(2),5.25),(x(4),5.25));d.arrow((x(4),5.25),(x(2),5.25))
    d.text(x(3),5.65,r'Joint interval $[2,4]$',size=8.5)
    d.text(6.0,.17,r'Illustrative units; each age bound is $\tau=4$.',size=8.5);d.save(out,'freshness')

def receipt(out):
    d=Drawing((0,0,15.0,7.3))
    for n,x,y,w,label in [('pkt',2.4,6.0,4.4,'Full packet\ncontract, positives,\nsnapshots'),('record',7.65,6.0,4.4,'Recorded semantic result\nverdict, checks, findings,\ndependencies, certificate'),('code',2.4,3.55,4.4,'Current implementation\nand current check time'),('gate',7.65,3.55,4.4,'Rerun existing strict gate'),('compare',12.75,3.55,3.9,'Compare complete\nsemantic views'),('out',12.75,1.2,3.9,'Agreement: current result\nDisagreement: unknown')]:
        d.box(n,x,y,w,1.45,label,size=8.5)
    d.edge('pkt','record','e','w');d.edge('pkt','gate');d.edge('code','gate','e','w')
    d.edge('gate','compare','e','w');d.edge('record','compare','e','n',via=((12.75,6.0),))
    d.edge('compare','out');d.save(out,'receipt')

def tuples(out):
    d=Drawing((0,0,14.9,4.9))
    d.ax.add_patch(Rectangle((.95,2.55),3.15,1.55,facecolor='.93',edgecolor='none'))
    for pts in [[(.95,1.0),(7.25,1.0),(7.25,4.1),(.95,4.1),(.95,1.0)],[(4.1,1.0),(4.1,4.1)],[(.95,2.55),(7.25,2.55)]]:d.line(pts)
    d.text(2.525,4.55,'$a_1$');d.text(5.675,4.55,'$a_2$')
    d.text(.6,3.325,'$s_1$');d.text(.6,1.775,'$s_2$')
    d.text(2.525,3.325,'Explicit Deny\nnot admitted',size=8.5)
    for x,y in [(5.675,3.325),(2.525,1.775),(5.675,1.775)]:d.text(x,y,'Admitted',size=8.5)
    d.text(11.2,3.5,r'Allow: $\{s_1,s_2\}\times\{a_1,a_2\}$',size=8.5)
    d.text(11.2,2.7,r'Deny: $\{(s_1,a_1)\}$',size=8.5)
    d.text(11.2,1.6,'Subtract complete tuples,\nnot subjects or audiences alone.',size=8.5);d.save(out,'tuples')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output-dir',type=Path,required=True)
    out=p.parse_args().output_dir;out.mkdir(parents=True,exist_ok=True)
    for draw in (architecture,collision,decision,denominators,evidence,freshness,receipt,tuples):draw(out)

