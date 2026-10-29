"""Tableau de bord de la boutique : commandes, stock, conversations à reprendre."""
import hashlib
import hmac
import os
import secrets
import time
from typing import List
from html import escape as esc
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response

import db

SESSION_COOKIE = "dashboard_session"
SESSION_SECONDS = 60 * 60 * 24 * 7
router = APIRouter(prefix="/dashboard")
auth_router = APIRouter()


def _session_secret():
    secret = os.getenv("DASHBOARD_SESSION_SECRET") or os.getenv("APP_SECRET") or os.getenv("DATABASE_URL")
    if not secret:
        raise HTTPException(status_code=503, detail="Configure DASHBOARD_SESSION_SECRET dans l'environnement")
    return secret.encode()


def _hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=64)
    return "scrypt$" + salt.hex() + "$" + digest.hex()


def _password_matches(password, stored):
    try:
        algorithm, salt_hex, digest_hex = stored.split("$", 2)
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex),
                                n=2**14, r=8, p=1, dklen=64)
        return secrets.compare_digest(actual.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def _same_origin(request):
    origin = request.headers.get("origin")
    return not origin or urlsplit(origin).netloc.lower() == request.headers.get("host", "").lower()


def _make_session(user_id):
    expires = int(time.time()) + SESSION_SECONDS
    payload = "{}:{}".format(int(user_id), expires)
    signature = hmac.new(_session_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return "{}:{}:{}".format(int(user_id), expires, signature)


def _read_session(token):
    try:
        user_id, expires, signature = token.split(":", 2)
        payload = "{}:{}".format(user_id, expires)
        expected = hmac.new(_session_secret(), payload.encode(), hashlib.sha256).hexdigest()
        if int(expires) < int(time.time()) or not hmac.compare_digest(signature, expected):
            return None
        return db.get_dashboard_user_by_id(int(user_id))
    except (ValueError, TypeError):
        return None


def _set_session(response, request, user_id):
    secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(SESSION_COOKIE, _make_session(user_id), max_age=SESSION_SECONDS,
                        httponly=True, secure=secure, samesite="lax", path="/")


def auth(request: Request):
    """Protège le tableau de bord avec une session signée en cookie."""
    token = request.cookies.get(SESSION_COOKIE, "")
    user = _read_session(token) if token else None
    if not user:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


router = APIRouter(prefix="/dashboard", dependencies=[Depends(auth)])

STATUS_LABEL = {
    "nouvelle": "Nouvelle",
    "confirmee": "Confirmée",
    "livree": "Livrée",
    "annulee": "Annulée",
}

AUTH_CSS = """
:root{color-scheme:dark;--bg:#06100e;--red:#e0201b;--red2:#ff3b34;--mint:#7fb8a6;--cream:#e9efe6;--muted:#8fa39b;--line:#e9efe61f;
--serif:"Playfair Display",Didot,"Bodoni 72",Georgia,serif;--sans:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
*{box-sizing:border-box}
html{scroll-padding-top:env(safe-area-inset-top,0px)}
body{margin:0;min-height:100vh;min-height:100svh;color:var(--cream);font:15px/1.5 var(--sans);overflow-x:hidden;
background:radial-gradient(1100px 700px at 22% 45%,#0e2a24 0,var(--bg) 70%);padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}
.topbar{display:flex;justify-content:space-between;align-items:center;padding:20px clamp(18px,4vw,48px);border-bottom:1px solid var(--line);
font-size:11px;letter-spacing:.28em;text-transform:uppercase;position:relative;z-index:2}
.brand{font-family:var(--serif);font-weight:800;font-size:15px;letter-spacing:.14em}.brand i{color:var(--red);font-style:normal}
.topbar span{color:var(--muted)}
.layout{display:grid;grid-template-columns:1.05fr 1fr;align-items:center;gap:clamp(12px,4vw,64px);max-width:1280px;margin:0 auto;
padding:clamp(16px,3vw,40px) clamp(18px,4vw,48px);min-height:calc(100svh - 70px);position:relative;z-index:1}
.stage{position:relative;display:grid;place-items:center;min-height:440px}
.beam{position:absolute;top:-10%;left:50%;width:96px;height:78%;transform:skewX(-10deg);border-radius:4px;opacity:.8;filter:blur(1px);
background:linear-gradient(180deg,#e0201b,#7a0f0c 78%,transparent)}
.floor{position:absolute;bottom:3%;width:92%;height:80px;background:radial-gradient(ellipse at center,#42d8ff55,transparent 70%);filter:blur(12px)}
.robot{position:relative;width:min(430px,82%);height:auto;filter:drop-shadow(0 30px 40px #000a);animation:float 5s ease-in-out infinite}
.eye{animation:blink 5s infinite;transform-box:fill-box;transform-origin:center}
.robot.shy .eye{animation:none;transform:scaleY(.08);transition:transform .25s}
.robot .eye{transition:transform .25s}
.stage{cursor:crosshair}
.stage canvas{position:absolute;inset:0;width:100%;height:100%;opacity:0;transition:opacity .7s;touch-action:pan-y}
.stage canvas.on{opacity:1}
@keyframes float{50%{transform:translateY(-10px)}}
@keyframes blink{0%,94%,100%{transform:scaleY(1)}97%{transform:scaleY(.1)}}
.panel{width:100%;max-width:450px;justify-self:center}
.eyebrow{font-size:11px;letter-spacing:.3em;text-transform:uppercase;color:var(--muted);line-height:1.8}
h1{margin:14px 0 4px;font-family:var(--serif);font-weight:800;line-height:.95;letter-spacing:-.01em;font-size:clamp(52px,7.5vw,92px);color:var(--red)}
h2{margin:0 0 20px;font-family:var(--serif);font-weight:600;letter-spacing:.02em;text-transform:uppercase;font-size:clamp(26px,3.4vw,42px)}
.rule{width:44px;height:2px;background:var(--muted);margin-bottom:16px}
.lead{color:var(--muted);font-size:14px;line-height:1.7;margin:0 0 24px}
label{display:block;font-size:10px;letter-spacing:.28em;text-transform:uppercase;color:var(--muted);margin:0 0 8px}
.field{margin-bottom:16px;position:relative}
input{width:100%;background:#e9efe60a;border:1px solid var(--line);border-radius:999px;padding:15px 22px;color:var(--cream);font:400 14px var(--sans);outline:none;transition:border-color .2s,box-shadow .2s}
input::placeholder{color:#8fa39b88}
input:focus{border-color:var(--red);box-shadow:0 0 0 3px #e0201b33}
.eye-btn{position:absolute;right:8px;bottom:6px;width:38px;height:38px;margin:0;padding:0;border:0;background:transparent;color:var(--muted);
border-radius:50%;cursor:pointer;display:grid;place-items:center;box-shadow:none}
.eye-btn:hover{color:var(--cream);background:#e9efe610;box-shadow:none}
.row{display:flex;justify-content:space-between;align-items:center;font-size:12px;color:var(--muted);margin:2px 4px 22px}
.row a{color:var(--mint);text-decoration:none}
.btn{width:100%;cursor:pointer;border-radius:999px;padding:15px 22px;font:500 12px var(--sans);letter-spacing:.28em;text-transform:uppercase;
display:flex;justify-content:center;align-items:center;gap:12px;background:var(--red);border:1px solid var(--red);color:#fff;transition:.2s}
.btn:hover{background:var(--red2);box-shadow:0 8px 30px #e0201b66}
.btn[disabled]{opacity:.7;cursor:wait}
.error{background:#2a0e0d;border:1px solid var(--red);color:#ffc2bf;padding:12px 18px;border-radius:18px;margin:0 0 18px;font-size:13px}
.secure{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12px;margin:0 0 18px}
.secure-dot{width:7px;height:7px;border-radius:50%;background:var(--mint);box-shadow:0 0 10px var(--mint)}
.form-foot{margin-top:22px;padding-top:14px;border-top:1px solid var(--line);color:#8fa39bb0;font-size:12px;text-align:center}
@media(max-width:860px){.layout{grid-template-columns:1fr;gap:0}.stage{min-height:290px;order:-1}.robot{width:min(250px,64%)}.beam{width:60px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;transition:none!important}}
"""

AUTH_ROBOT = """<svg class="robot" viewBox="0 0 400 460" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Robot InstaAgent">
<defs>
<linearGradient id="m" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#b6ded0"/><stop offset=".55" stop-color="#7fb8a6"/><stop offset="1" stop-color="#3d7566"/></linearGradient>
<linearGradient id="v" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#1a0b0b"/><stop offset="1" stop-color="#050a09"/></linearGradient>
<linearGradient id="rim" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#e0201b"/><stop offset=".5" stop-color="#ff9a5a"/><stop offset="1" stop-color="#7fb8a6"/></linearGradient>
<radialGradient id="g"><stop offset="0" stop-color="#ff5a50"/><stop offset="1" stop-color="#e0201b"/></radialGradient>
</defs>
<ellipse cx="200" cy="432" rx="150" ry="14" fill="#e0201b" opacity=".35"/>
<g id="bot-head"><rect x="190" y="14" width="6" height="40" fill="#3d7566"/><circle cx="193" cy="12" r="9" fill="url(#g)"/>
<path d="M96 180Q96 70 200 70Q304 70 304 180Q304 250 200 250Q96 250 96 180Z" fill="url(#m)"/>
<path d="M120 120Q150 80 215 80" stroke="#fff" stroke-opacity=".5" stroke-width="6" fill="none" stroke-linecap="round"/>
<rect x="66" y="150" width="34" height="64" rx="16" fill="#2c5a4e"/><rect x="300" y="150" width="34" height="64" rx="16" fill="#2c5a4e"/>
<rect x="62" y="168" width="10" height="28" rx="5" fill="url(#g)"/><rect x="328" y="168" width="10" height="28" rx="5" fill="url(#g)"/>
<rect x="122" y="128" width="156" height="92" rx="40" fill="url(#v)" stroke="url(#rim)" stroke-width="4"/>
<g id="bot-eyes"><ellipse class="eye" cx="162" cy="172" rx="16" ry="20" fill="url(#g)"/><ellipse class="eye" cx="238" cy="172" rx="16" ry="20" fill="url(#g)"/>
<ellipse cx="157" cy="164" rx="4" ry="6" fill="#fff" opacity=".8"/><ellipse cx="233" cy="164" rx="4" ry="6" fill="#fff" opacity=".8"/></g></g>
<g id="bot-body"><rect x="170" y="248" width="60" height="22" fill="#2c5a4e"/>
<path d="M110 300Q110 266 200 266Q290 266 290 300L300 420Q200 446 100 420Z" fill="url(#m)"/>
<path d="M84 310Q60 340 80 400" stroke="#7fb8a6" stroke-width="26" stroke-linecap="round" fill="none"/>
<path d="M316 310Q340 340 320 400" stroke="#3d7566" stroke-width="26" stroke-linecap="round" fill="none"/>
<rect x="168" y="304" width="64" height="64" rx="18" fill="#0a1a17" stroke="url(#g)" stroke-width="4"/>
<circle cx="200" cy="336" r="14" fill="none" stroke="#e0201b" stroke-width="4"/><circle cx="214" cy="322" r="3" fill="#e0201b"/>
<path d="M130 392L270 392" stroke="#e0201b" stroke-width="4" stroke-linecap="round" opacity=".8"/>
</g></svg>"""

AUTH_JS = """
(function(){
var f=document.getElementById('login-form'),b=document.getElementById('toggle-pw'),p=document.getElementById('password'),u=document.getElementById('username');
b.addEventListener('click',function(){var s=p.type==='password';p.type=s?'text':'password';b.setAttribute('aria-label',s?'Masquer le mot de passe':'Afficher le mot de passe');robot.classList.toggle('shy',document.activeElement===p&&p.type==='password');});
f.addEventListener('submit',function(){var s=document.getElementById('submit-btn');s.disabled=true;s.firstElementChild.textContent='Connexion…';});

var robot=document.querySelector('.robot'),head=document.getElementById('bot-head'),eyes=document.getElementById('bot-eyes'),body=document.getElementById('bot-body');
var reduce=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
var t={x:0,y:0},c={x:0,y:0};
function clamp(v){return Math.max(-1,Math.min(1,v));}
function aim(x,y){var r=robot.getBoundingClientRect(),cx=r.left+r.width/2,cy=r.top+r.height*0.4;
t.x=clamp((x-cx)/(window.innerWidth*0.5));t.y=clamp((y-cy)/(window.innerHeight*0.5));}
window.addEventListener('pointermove',function(e){aim(e.clientX,e.clientY);},{passive:true});
document.addEventListener('mouseleave',function(){t.x=0;t.y=0;});
p.addEventListener('focus',function(){if(p.type==='password')robot.classList.add('shy');});
p.addEventListener('blur',function(){robot.classList.remove('shy');});
u.addEventListener('input',function(){var r=u.getBoundingClientRect();aim(r.left+r.width*Math.min(1,u.value.length/24),r.top);});
robot.addEventListener('click',function(){robot.animate([{transform:'translateY(0) scale(1)'},{transform:'translateY(-22px) scale(1.04)'},{transform:'translateY(0) scale(1)'}],{duration:480,easing:'cubic-bezier(.3,1.6,.5,1)'});});
function tick(){
c.x+=(t.x-c.x)*0.12;c.y+=(t.y-c.y)*0.12;
head.setAttribute('transform','translate('+(c.x*10).toFixed(2)+' '+(c.y*6).toFixed(2)+') rotate('+(c.x*11).toFixed(2)+' 200 255)');
eyes.setAttribute('transform','translate('+(c.x*10).toFixed(2)+' '+(c.y*8).toFixed(2)+')');
body.setAttribute('transform','translate('+(c.x*-4).toFixed(2)+' '+(c.y*-1.5).toFixed(2)+')');
requestAnimationFrame(tick);}
if(!reduce)tick();
})();
"""


AUTH_IMPORTMAP = '<script type="importmap">{"imports":{"three":"https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.module.js","three/addons/":"https://cdn.jsdelivr.net/npm/three@0.160.0/examples/jsm/"}}</script>'

AUTH_3D_JS = """
(async function(){
var stage=document.querySelector('.stage'),svg=document.querySelector('.robot'),pw=document.getElementById('password'),un=document.getElementById('username');
if(!stage)return;
var THREE,ENV;
try{
THREE=await import('three');
ENV=await import('three/addons/environments/RoomEnvironment.js');
}catch(e){return;}
var renderer;
try{renderer=new THREE.WebGLRenderer({antialias:true,alpha:true});}catch(e){return;}
renderer.setPixelRatio(Math.min(window.devicePixelRatio||1,2));
renderer.toneMapping=THREE.ACESFilmicToneMapping;renderer.toneMappingExposure=1.0;
var canvas=renderer.domElement;stage.appendChild(canvas);
var scene=new THREE.Scene();
var pm=new THREE.PMREMGenerator(renderer);
scene.environment=pm.fromScene(new ENV.RoomEnvironment(),0.04).texture;
var camera=new THREE.PerspectiveCamera(30,1,0.1,80);
camera.position.set(0,4.0,10.9);camera.lookAt(0,1.35,0);

var key=new THREE.DirectionalLight(0xf4f8f6,1.6);key.position.set(3,6,6);scene.add(key);
var red=new THREE.PointLight(0xe0201b,70,16);red.position.set(-4,2.5,-1.5);scene.add(red);
var mintL=new THREE.PointLight(0x5ff0c8,18,10);mintL.position.set(3,1.5,3);scene.add(mintL);

var GLOW='#5ff0c8';
function phys(c,r,m,cc){return new THREE.MeshPhysicalMaterial({color:c,roughness:r,metalness:m,clearcoat:cc,clearcoatRoughness:0.12});}
var white=phys(0xf3f7f5,0.28,0.0,1),black=phys(0x14191b,0.32,0.35,0.6),grey=phys(0xc9d6d1,0.35,0.1,0.8);
var glowMat=new THREE.MeshBasicMaterial({color:0x5ff0c8,toneMapped:false}),redGlow=new THREE.MeshBasicMaterial({color:0xff3b34,toneMapped:false});
function SP(r,m,sx,sy,sz){var o=new THREE.Mesh(new THREE.SphereGeometry(r,40,28),m);o.scale.set(sx||1,sy||1,sz||1);return o;}
function CAP(r,l,m){return new THREE.Mesh(new THREE.CapsuleGeometry(r,l,10,24),m);}
function add(p,o,x,y,z){o.position.set(x||0,y||0,z||0);p.add(o);return o;}

/* ecran : fond + contour lumineux (dessine une fois) */
var W=800,H=476;
function rr(g,x,y,w,h,r){g.beginPath();g.moveTo(x+r,y);g.arcTo(x+w,y,x+w,y+h,r);g.arcTo(x+w,y+h,x,y+h,r);g.arcTo(x,y+h,x,y,r);g.arcTo(x,y,x+w,y,r);g.closePath();}
var bg=document.createElement('canvas');bg.width=W;bg.height=H;
(function(){var g=bg.getContext('2d');
var f=g.createLinearGradient(0,0,0,H);f.addColorStop(0,'#0a1c24');f.addColorStop(1,'#010304');
rr(g,16,16,W-32,H-32,170);g.fillStyle=f;g.fill();
var s=g.createLinearGradient(60,40,380,300);s.addColorStop(0,'rgba(255,255,255,0.20)');s.addColorStop(1,'rgba(255,255,255,0)');
g.save();rr(g,16,16,W-32,H-32,170);g.clip();g.fillStyle=s;g.beginPath();g.moveTo(40,30);g.lineTo(330,30);g.lineTo(150,300);g.lineTo(40,300);g.closePath();g.fill();g.restore();
var rg=g.createLinearGradient(0,0,W,H);rg.addColorStop(0,'#9bf7dc');rg.addColorStop(0.5,'#4fe0c0');rg.addColorStop(1,'#5fc8ff');
g.shadowColor='rgba(95,240,200,0.95)';g.shadowBlur=30;g.strokeStyle=rg;g.lineWidth=16;rr(g,16,16,W-32,H-32,170);g.stroke();g.stroke();
})();
var scr=document.createElement('canvas');scr.width=W;scr.height=H;var sg=scr.getContext('2d');
var tex=new THREE.CanvasTexture(scr);tex.colorSpace=THREE.SRGBColorSpace;tex.anisotropy=4;
var lastK='';
function drawScreen(ox,oy,open,happy){
var k=[ox.toFixed(2),oy.toFixed(2),open.toFixed(2),happy].join();if(k===lastK)return;lastK=k;
sg.clearRect(0,0,W,H);sg.drawImage(bg,0,0);
var ex=ox*34,ey=oy*18;
function eye(cx){
var x=cx+ex,y=225+ey;sg.save();sg.lineCap='round';sg.strokeStyle=GLOW;sg.shadowColor=GLOW;sg.shadowBlur=26;
if(happy){sg.lineWidth=16;sg.beginPath();sg.arc(x,y+30,48,Math.PI*1.12,Math.PI*1.88);sg.stroke();}
else if(open<0.22){sg.lineWidth=16;sg.beginPath();sg.arc(x,y-14,48,Math.PI*0.12,Math.PI*0.88);sg.stroke();}
else{sg.translate(x,y);sg.scale(1,open);sg.lineWidth=18;sg.beginPath();sg.arc(0,0,60,0,Math.PI*2);sg.stroke();
sg.shadowBlur=0;sg.fillStyle='#052028';sg.beginPath();sg.arc(0,0,51,0,Math.PI*2);sg.fill();
sg.fillStyle='#0f6a72';sg.beginPath();sg.arc(ox*10,oy*8,28,0,Math.PI*2);sg.fill();
sg.fillStyle='#ffffff';sg.beginPath();sg.arc(ox*10-9,oy*8-10,9,0,Math.PI*2);sg.fill();}
sg.restore();}
eye(285);eye(515);
sg.save();sg.lineCap='round';sg.strokeStyle=GLOW;sg.shadowColor=GLOW;sg.shadowBlur=22;sg.lineWidth=11;
sg.beginPath();sg.arc(400+ex*0.5,300+ey*0.5,66,Math.PI*0.2,Math.PI*0.8);sg.stroke();sg.restore();
tex.needsUpdate=true;}

/* smartphone et halo : le robot semble émerger de l’écran */
var phone=new THREE.Group();phone.position.y=-0.08;scene.add(phone);
add(phone,new THREE.Mesh(new THREE.BoxGeometry(3.45,0.16,1.92),black),0,0,0);
var glass=phys(0x07131b,0.2,0.25,0.9);
add(phone,new THREE.Mesh(new THREE.BoxGeometry(3.28,0.025,1.76),glass),0,0.092,0);
var screenLine=new THREE.MeshBasicMaterial({color:0x5ff0c8,toneMapped:false});
var screenRed=new THREE.MeshBasicMaterial({color:0xe0201b,toneMapped:false});
add(phone,new THREE.Mesh(new THREE.BoxGeometry(0.36,0.008,0.026),screenLine),0,0.108,-0.78);
[-1.05,-0.38,0.38,1.05].forEach(function(x,i){
var icon=add(phone,new THREE.Mesh(new THREE.CircleGeometry(0.09,28),i===1?screenRed:screenLine),x,0.108,-0.49);icon.rotation.x=-Math.PI/2;
});
var cardMat=new THREE.MeshBasicMaterial({color:0x17303a,toneMapped:false});
add(phone,new THREE.Mesh(new THREE.BoxGeometry(0.62,0.012,0.36),cardMat),-0.92,0.108,0.12);
add(phone,new THREE.Mesh(new THREE.BoxGeometry(0.62,0.012,0.36),cardMat),0.92,0.108,0.12);
var holo=new THREE.MeshBasicMaterial({color:0x62eaff,toneMapped:false,transparent:true,opacity:0.88});
var hologram=new THREE.Group();hologram.position.set(0,0.12,0);scene.add(hologram);
var r1=add(hologram,new THREE.Mesh(new THREE.TorusGeometry(0.78,0.022,12,96),holo),0,0,0);r1.rotation.x=Math.PI/2;
var r2=add(hologram,new THREE.Mesh(new THREE.TorusGeometry(1.08,0.009,10,96),holo),0,0.01,0);r2.rotation.x=Math.PI/2;
var beamMat=new THREE.MeshBasicMaterial({color:0x39cfff,toneMapped:false,transparent:true,opacity:0.09,side:THREE.DoubleSide,depthWrite:false});
add(hologram,new THREE.Mesh(new THREE.CylinderGeometry(0.78,0.34,1.8,48,1,true),beamMat),0,0.9,0);
var root=new THREE.Group();root.rotation.y=0.35;root.position.y=0.1;scene.add(root);
var body=new THREE.Group();root.add(body);
/* corps type humanoide */
var dg=phys(0x3b464a,0.34,0.3,0.7);
function leg(s){
add(body,SP(0.17,dg),s*0.28,0.99,0);
add(body,CAP(0.135,0.2,white),s*0.29,0.78,0);
add(body,SP(0.15,dg),s*0.3,0.55,0.01);
add(body,CAP(0.12,0.17,white),s*0.3,0.34,0);
var an=add(body,new THREE.Mesh(new THREE.TorusGeometry(0.125,0.03,12,32),dg),s*0.3,0.36,0);an.rotation.x=Math.PI/2;
add(body,SP(0.3,white,1,0.55,1.5),s*0.31,0.16,0.1);
add(body,SP(0.32,dg,1,0.17,1.52),s*0.31,0.04,0.1);
add(body,SP(0.15,dg,1,0.5,1.0),s*0.31,0.3,-0.12);
add(body,SP(0.2,grey,1,0.45,0.9),s*0.31,0.17,0.36);
}
leg(-1);leg(1);
/* bassin et taille */
add(body,SP(1,white,0.5,0.22,0.4),0,0.98,0);
add(body,SP(1,black,0.45,0.1,0.4),0,1.14,0);
add(body,SP(1,white,0.46,0.36,0.38),0,1.4,0);
/* poitrail large */
add(body,SP(1,white,0.7,0.5,0.5),0,1.82,0);
add(body,SP(1,black,0.4,0.18,0.05),0,1.6,0.47);
var chest=add(body,new THREE.Mesh(new THREE.CircleGeometry(0.055,32),glowMat),0,1.6,0.524);
var collar=add(body,new THREE.Mesh(new THREE.TorusGeometry(0.17,0.03,12,40),glowMat),0,2.22,0);collar.rotation.x=Math.PI/2;
add(body,new THREE.Mesh(new THREE.CylinderGeometry(0.13,0.17,0.2,24),dg),0,2.2,0);
/* bras : epaule grise, coude, poignet cannele, main a doigts */
function makeHand(s){var h=new THREE.Group();
add(h,SP(0.15,white,1.1,1.0,0.62),0,-0.13,0);
var L=[0.1,0.135,0.12,0.085];
for(var i=0;i<4;i++){var r=0.05,f=CAP(r,L[i],white);f.position.set((i-1.5)*0.077,-0.2-(L[i]/2+r)+0.05,0);f.rotation.z=-(i-1.5)*0.1;f.scale.z=0.85;h.add(f);}
var th=CAP(0.055,0.08,white);th.position.set(-s*0.16,-0.17,0.02);th.rotation.z=-s*0.4;th.scale.z=0.85;h.add(th);
h.scale.setScalar(1.22);return h;}
function makeArm(s){var g=new THREE.Group();g.position.set(s*0.8,2.0,0);
add(g,SP(0.19,dg),0,0,0);
add(g,CAP(0.125,0.24,white),0,-0.3,0);
var el=new THREE.Group();el.position.set(0,-0.58,0);g.add(el);
add(el,SP(0.125,dg),0,0,0);
add(el,CAP(0.11,0.2,white),0,-0.24,0);
[-0.38,-0.425,-0.47].forEach(function(y){var r=add(el,new THREE.Mesh(new THREE.TorusGeometry(0.112,0.014,10,32),dg),0,y,0);r.rotation.x=Math.PI/2;});
add(el,makeHand(s),0,-0.5,0);
body.add(g);g.userData.el=el;return g;}
var armL=makeArm(-1),armR=makeArm(1);
/* tete ronde */
var head=new THREE.Group();head.position.set(0,2.3,0);body.add(head);
var shape=new THREE.Group();shape.position.y=0.85;shape.scale.set(1.12,0.9,0.96);head.add(shape);
shape.add(new THREE.Mesh(new THREE.SphereGeometry(1,64,48),white));
var patch=new THREE.Mesh(new THREE.SphereGeometry(1.012,64,40,Math.PI/2-1.0,2.0,Math.PI/2-0.66,1.32),new THREE.MeshBasicMaterial({map:tex,transparent:true,toneMapped:false}));
shape.add(patch);
[-1,1].forEach(function(s){
var ear=add(head,new THREE.Mesh(new THREE.CylinderGeometry(0.3,0.3,0.1,48),grey),s*1.1,0.85,0);ear.rotation.z=Math.PI/2;ear.scale.set(1.15,1,0.8);
var rg=add(head,new THREE.Mesh(new THREE.TorusGeometry(0.17,0.032,16,56),glowMat),s*1.165,0.85,0);rg.rotation.y=Math.PI/2;
var dk=add(head,new THREE.Mesh(new THREE.CylinderGeometry(0.12,0.12,0.02,40),black),s*1.16,0.85,0);dk.rotation.z=Math.PI/2;
});
/* ligne de separation + capteurs sur le dessus de la tete */
function onHead(th,ph,k){return new THREE.Vector3(Math.sin(th)*Math.sin(ph),Math.cos(th),Math.sin(th)*Math.cos(ph)).multiplyScalar(k);}
var pts=[];for(var i=0;i<=28;i++){var p=-1.35+2.7*i/28;pts.push(onHead(0.72-0.12*p*p,p,1.004));}
shape.add(new THREE.Mesh(new THREE.TubeGeometry(new THREE.CatmullRomCurve3(pts),80,0.016,8,false),dg));
[-1,1].forEach(function(s){var d=new THREE.Mesh(new THREE.SphereGeometry(0.045,20,16),dg);d.position.copy(onHead(0.8,s*0.2,1.005));d.scale.set(1,0.8,0.5);d.lookAt(d.position.clone().multiplyScalar(2));shape.add(d);});
/* deux petites antennes */
function antenna(s,m){var th=-s*0.35,bx=s*0.6,by=1.57,len=0.4;
var a=add(head,new THREE.Mesh(new THREE.CylinderGeometry(0.017,0.017,len,12),grey),bx-Math.sin(th)*len/2,by+Math.cos(th)*len/2,-0.05);a.rotation.z=th;
return add(head,new THREE.Mesh(new THREE.SphereGeometry(0.05,16,16),m),bx-Math.sin(th)*len,by+Math.cos(th)*len,-0.05);}
var bulb=antenna(1,new THREE.MeshStandardMaterial({color:0xe0201b,emissive:0xff2a22,emissiveIntensity:1.5}));
antenna(-1,new THREE.MeshBasicMaterial({color:0x5ff0c8,toneMapped:false}));

function resize(){var w=stage.clientWidth||400,h=stage.clientHeight||400;renderer.setSize(w,h,false);camera.aspect=w/h;camera.updateProjectionMatrix();}
if(window.ResizeObserver){new ResizeObserver(resize).observe(stage);}else{window.addEventListener('resize',resize);}
resize();

function clamp(v){return Math.max(-1,Math.min(1,v));}
var tgt={x:0,y:0},cur={x:0,y:0},shy=0,shyT=0,blinkAt=2.5,blinkStart=-1,waveFrom=0.6,waveUntil=3.6,armRe=0,armRz=0.22,armLz=-0.22,armLx=0,jump=0;
var reduce=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
function aim(x,y){var r=stage.getBoundingClientRect();tgt.x=clamp((x-(r.left+r.width/2))/(window.innerWidth*0.5));tgt.y=clamp((y-(r.top+r.height*0.3))/(window.innerHeight*0.5));}
window.addEventListener('pointermove',function(e){aim(e.clientX,e.clientY);},{passive:true});
document.addEventListener('mouseleave',function(){tgt.x=0;tgt.y=0;});
if(un)un.addEventListener('input',function(){tgt.x=clamp(0.25+Math.min(un.value.length,24)/24*0.6);tgt.y=0.1;});
if(pw){pw.addEventListener('focus',function(){shyT=pw.type==='password'?1:0;});pw.addEventListener('blur',function(){shyT=0;});}
var ray=new THREE.Raycaster(),ndc=new THREE.Vector2();
canvas.addEventListener('pointerdown',function(e){var r=canvas.getBoundingClientRect();
ndc.set(((e.clientX-r.left)/r.width)*2-1,-((e.clientY-r.top)/r.height)*2+1);ray.setFromCamera(ndc,camera);
if(ray.intersectObject(body,true).length){waveFrom=0;waveUntil=clock.getElapsedTime()+2.2;jump=1;}});
var clock=new THREE.Clock(),shown=false,lastT=0;

function frame(){
var t=clock.getElapsedTime();var dt=Math.min(t-lastT,0.15);lastT=t;
var f8=1-Math.pow(0.92,dt*60),f12=1-Math.pow(0.88,dt*60);
cur.x+=(tgt.x-cur.x)*f8;cur.y+=(tgt.y-cur.y)*f8;shy+=(shyT-shy)*f12;jump*=Math.pow(0.92,dt*60);
body.position.y=Math.sin(t*1.6)*0.04+Math.sin(Math.min(1,jump)*Math.PI)*0.2*(jump>0.02?1:0);
body.rotation.y=cur.x*0.2;
head.rotation.y=cur.x*0.8*(1-shy*0.6);
head.rotation.x=cur.y*0.38+shy*0.3;
head.rotation.z=-cur.x*0.05;
if(t>blinkAt){blinkStart=t;blinkAt=t+2.5+Math.random()*3;}
var b=t-blinkStart,bl=(b>=0&&b<0.2)?1-Math.sin(b/0.2*Math.PI)*0.95:1;
var w=(t>=waveFrom&&t<waveUntil);
drawScreen(cur.x,cur.y,Math.min(bl,1-shy*0.95),w);
armRz+=((w?1.2:0.22+Math.sin(t*1.6)*0.03)-armRz)*f12;
armRe+=((w?1.62+Math.sin(t*11)*0.3:0)-armRe)*f12;armR.userData.el.rotation.z=armRe;
armLz+=((shy>0.5?-0.5:-0.22-Math.sin(t*1.6)*0.03)-armLz)*f12;
armLx+=((shy>0.5?-1.35:0)-armLx)*f12;
armR.rotation.z=armRz;armL.rotation.z=armLz;armL.rotation.x=armLx;
bulb.material.emissiveIntensity=1.3+Math.sin(t*3)*0.7;
chest.scale.setScalar(0.95+Math.sin(t*2.2)*0.06);
hologram.rotation.y=t*0.16;hologram.scale.setScalar(1+Math.sin(t*2.1)*0.025);holo.opacity=0.72+Math.sin(t*2.1)*0.12;
red.intensity=65+Math.sin(t*1.2)*8;
renderer.render(scene,camera);
if(!shown){shown=true;canvas.classList.add('on');if(svg)svg.style.display='none';}
if(!reduce)requestAnimationFrame(frame);
}
frame();
})();
"""


def auth_page(error=""):
    error_html = '<div class="error" role="alert">{}</div>'.format(esc(error)) if error else ""
    return """<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>Connexion · InstaAgent</title>
<meta name="theme-color" content="#06100e">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@600;800&family=Inter:wght@300;400;500;600&display=swap">
<style>{css}</style>{importmap}</head><body>
<header class="topbar"><div class="brand">INSTA<i>·</i>AGENT</div><span>Espace propriétaire</span></header>
<main class="layout">
<section class="stage" aria-hidden="true"><div class="beam"></div><div class="floor"></div>{robot}</section>
<section class="panel">
<div class="eyebrow">Mêmes conversations<br>Nouvelle intelligence</div>
<h1>AGIT</h1><h2>Autrement</h2><div class="rule"></div>
<p class="lead">Votre agent Instagram répond, prend les commandes et suit le stock pendant que vous créez. Connectez-vous pour reprendre le contrôle.</p>
{error}
<form id="login-form" method="post" action="/login">
<div class="field"><label for="username">Nom d’utilisateur</label>
<input id="username" name="username" autocomplete="username" placeholder="admin" required autofocus></div>
<div class="field"><label for="password">Mot de passe</label>
<input id="password" name="password" type="password" autocomplete="current-password" placeholder="••••••••" required style="padding-right:52px">
<button type="button" id="toggle-pw" class="eye-btn" aria-label="Afficher le mot de passe">
<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg></button></div>
<div class="secure"><span class="secure-dot"></span>Accès sécurisé propriétaire</div>
<button class="btn" id="submit-btn" type="submit"><span>Se connecter</span><span aria-hidden="true">→</span></button>
</form>
<div class="form-foot">Accès réservé à l’équipe InstaAgent.</div>
</section></main>
<script>{js}</script><script type="module">{js3d}</script></body></html>""".format(css=AUTH_CSS, robot=AUTH_ROBOT, error=error_html, js=AUTH_JS,
                   importmap=AUTH_IMPORTMAP, js3d=AUTH_3D_JS)


@auth_router.get("/login", response_class=HTMLResponse)
def login_page():
    return HTMLResponse(auth_page())


@auth_router.get("/auth/mascot.png")
def auth_mascot():
    path = os.path.join(os.path.dirname(__file__), "static", "instaagent-mascot.png")
    return FileResponse(path, media_type="image/png")


@auth_router.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if not _same_origin(request):
        raise HTTPException(status_code=403, detail="Origine invalide")
    username = username.strip().lower()
    user = db.get_dashboard_user(username)

    # Premier accès : seul le couple d’identifiants configuré par le propriétaire
    # dans l’environnement peut initialiser le compte, sans formulaire public.
    if user is None and db.dashboard_user_count() == 0:
        configured_user = os.getenv("DASHBOARD_USER", "admin").strip().lower()
        configured_password = os.getenv("DASHBOARD_PASSWORD", "")
        if (configured_password and secrets.compare_digest(username, configured_user)
                and secrets.compare_digest(password, configured_password)):
            db.create_initial_dashboard_user(username, _hash_password(password))
            user = db.get_dashboard_user(username)

    if not user or not _password_matches(password, user["password_hash"]):
        message = "Nom d’utilisateur ou mot de passe incorrect."
        if db.dashboard_user_count() == 0 and not os.getenv("DASHBOARD_PASSWORD"):
            message = "Le compte n’est pas encore configuré. Ajoutez DASHBOARD_USER et DASHBOARD_PASSWORD dans Render."
        return HTMLResponse(auth_page(message), status_code=401)
    response = RedirectResponse("/dashboard/orders", status_code=303)
    _set_session(response, request, user["id"])
    return response


@auth_router.get("/register")
def register_page():
    return RedirectResponse("/login", status_code=303)


@auth_router.post("/register")
def register_disabled():
    return RedirectResponse("/login", status_code=303)


@auth_router.post("/logout")
def logout(request: Request):
    if not _same_origin(request):
        raise HTTPException(status_code=403, detail="Origine invalide")
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


CSS = """
:root{--ink:#1E2A3B;--muted:#667085;--paper:#F4F5F7;--card:#fff;--line:#D9DDE3;
--accent:#C2185B;--ok:#2E7D5B;--info:#2F6DB5;--warn:#B25E09}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);
font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.top{background:var(--ink);color:#fff;display:flex;flex-wrap:wrap;align-items:center;
justify-content:space-between;gap:8px 24px;padding:10px 20px}
.brand{font-weight:700;font-size:1.05rem}
.top nav{display:flex;gap:4px;flex-wrap:wrap}
.top nav a{color:#CBD2DC;text-decoration:none;padding:8px 14px;border-radius:6px}
.top nav a.on{background:#fff;color:var(--ink);font-weight:600}
.logout{border:1px solid #526076;background:transparent;color:#fff;border-radius:6px;padding:8px 14px;font:inherit;cursor:pointer}
.pill{display:inline-block;min-width:1.4em;padding:0 .45em;margin-left:.35em;border-radius:99px;
background:var(--accent);color:#fff;font-size:.8rem;font-weight:700;text-align:center}
main{max-width:920px;margin:0 auto;padding:20px}
h1{font-size:1.4rem;margin:6px 0 14px}
h2{font-size:1.1rem;margin:28px 0 10px}
a{color:var(--info)}
.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 16px}
.tabs a{padding:6px 14px;border:1px solid var(--line);border-radius:99px;background:#fff;
color:var(--ink);text-decoration:none}
.tabs a.on{background:var(--ink);border-color:var(--ink);color:#fff}
.order,.alert{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--line);
border-radius:6px;padding:14px 16px;margin-bottom:12px}
.order.nouvelle{border-left-color:var(--accent)}
.order.confirmee{border-left-color:var(--info)}
.order.livree{border-left-color:var(--ok)}
.alert{border-left-color:var(--warn)}
.row{display:flex;flex-wrap:wrap;justify-content:space-between;gap:6px 16px;align-items:baseline}
.ref{font-weight:700}
.muted{color:var(--muted);font-size:.92rem}
.badge{display:inline-block;padding:2px 10px;border-radius:99px;font-size:.85rem;font-weight:600}
.badge.nouvelle{background:#FCE4EC;color:#880E4F}
.badge.confirmee{background:#E3EEFB;color:#1D4E89}
.badge.livree{background:#E1F2EA;color:#1E5C42}
.badge.annulee{background:#ECEEF1;color:#5B6574}
.item{font-size:1.05rem;margin:8px 0 4px}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.btn{border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:6px;
padding:8px 14px;font:inherit;cursor:pointer}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.danger{color:#B3261E}
.btn:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{outline:3px solid var(--info);outline-offset:2px}
.empty{padding:28px 16px;text-align:center;color:var(--muted);background:#fff;
border:1px dashed var(--line);border-radius:6px}
.wrap{overflow-x:auto;margin-bottom:8px}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line)}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
th{font-weight:600;color:var(--muted);font-size:.9rem}
td.out{color:#B3261E;font-weight:600}
input,select{font:inherit;padding:7px 9px;border:1px solid var(--line);border-radius:6px;
background:#fff;color:var(--ink)}
input[type=number]{width:6rem}
details{background:#fff;border:1px solid var(--line);border-radius:6px;padding:12px 16px;margin-bottom:20px}
summary{cursor:pointer;font-weight:600}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:14px 0}
label{display:flex;flex-direction:column;gap:4px;font-size:.9rem;color:var(--muted)}
.product{margin:22px 0 6px;display:flex;flex-wrap:wrap;gap:4px 12px;align-items:baseline}
.product strong{font-size:1.05rem}
.stock-card{display:grid;grid-template-columns:minmax(220px,280px) minmax(0,1fr);gap:18px;
background:#fff;border:1px solid var(--line);border-radius:12px;padding:16px;margin:10px 0 24px}
.stock-photo{display:flex;flex-direction:column;gap:12px;min-width:0}
.stock-photo img{display:block;width:100%;height:220px;object-fit:contain;background:#F8F9FB;
border:1px solid var(--line);border-radius:9px;padding:10px}
.stock-photo .placeholder{height:220px;display:grid;place-items:center;background:#F8F9FB;
border:1px dashed var(--line);border-radius:9px;color:var(--muted)}
.stock-photo form{display:grid;gap:8px}
.stock-photo input[type=file]{width:100%;font-size:.85rem}
.stock-table{min-width:0}
.stock-table .wrap{margin:0}
.stock-table table{min-width:500px}
.variant-entry{display:grid;grid-template-columns:1fr 1fr auto;gap:10px;align-items:end;margin:10px 0}
.variant-entry .remove-variant{padding:7px 11px}
@media(max-width:680px){.stock-card{grid-template-columns:1fr}.stock-photo img,.stock-photo .placeholder{height:240px}}
@media(max-width:520px){.variant-entry{grid-template-columns:1fr 1fr}.variant-entry .remove-variant{grid-column:1/-1}}
"""


def page(title, active, body):
    c = db.counts()
    shop = esc(os.getenv("SHOP_NAME", "Ma boutique"))
    orders_pill = ""
    todo = c["new_orders"] + c["handoffs"]
    if todo:
        orders_pill = '<span class="pill">{}</span>'.format(todo)
    return """<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · {shop}</title><style>{css}</style></head>
<body>
<header class="top"><div class="brand">{shop}</div>
<nav><a href="/dashboard/orders" class="{o}">Commandes{pill}</a>
<a href="/dashboard/stock" class="{s}">Stock</a>
<form method="post" action="/logout" style="display:inline;margin:0"><button type="submit" class="logout">Déconnexion</button></form></nav></header>
<main>{body}</main></body></html>""".format(
        title=esc(title), shop=shop, css=CSS, body=body, pill=orders_pill,
        o="on" if active == "orders" else "", s="on" if active == "stock" else "",
    )


def back(path):
    return RedirectResponse(path, status_code=303)


# ---------------------------------------------------------------- Commandes
@router.get("")
def home():
    return back("/dashboard/orders")


TABS = [("a-traiter", "À traiter"), ("livree", "Livrées"), ("annulee", "Annulées"), ("toutes", "Toutes")]
NEXT_ACTIONS = {
    "nouvelle": [("confirmee", "Confirmer", "primary"), ("annulee", "Annuler", "danger")],
    "confirmee": [("livree", "Marquer livrée", "primary"), ("annulee", "Annuler", "danger")],
}


def order_html(o):
    buttons = ""
    for status, label, kind in NEXT_ACTIONS.get(o["status"], []):
        confirm = ""
        if status == "annulee":
            confirm = ' onclick="return confirm(\'Annuler cette commande ? Le stock sera remis en rayon.\')"'
        buttons += (
            '<form method="post" action="/dashboard/orders/{id}/status">'
            '<input type="hidden" name="status" value="{st}">'
            '<button class="btn {kind}"{confirm}>{label}</button></form>'
        ).format(id=o["id"], st=status, kind=kind, confirm=confirm, label=label)
    phone = esc(o["phone"])
    return """<article class="order {status}">
<div class="row"><span><span class="ref">{ref}</span> <span class="muted">{date}</span></span>
<span class="badge {status}">{label}</span></div>
<div class="item">{qty} × {name} {color}, pointure {size} — <strong>{total} TND</strong></div>
<div>{customer} · <a href="tel:{phone}">{phone}</a></div>
<div class="muted">{address}</div>
<div class="muted">{payment} · Instagram {igid}</div>
<div class="actions">{buttons}</div></article>""".format(
        status=o["status"], ref=esc(o["order_ref"] or ""), date=esc(o["created_at"]),
        label=STATUS_LABEL.get(o["status"], o["status"]), qty=o["quantity"],
        name=esc(o["product_name"]), color=esc(o["color"]), size=esc(o["size"]),
        total=o["total"], customer=esc(o["customer_name"]), phone=phone,
        address=esc(o["address"]), payment=esc(o["payment"]), igid=esc(o["instagram_id"] or ""),
        buttons=buttons,
    )


@router.get("/orders", response_class=HTMLResponse)
def orders(statut: str = "a-traiter"):
    if statut not in dict(TABS):
        statut = "a-traiter"
    tabs = "".join(
        '<a href="/dashboard/orders?statut={k}" class="{on}">{label}</a>'.format(
            k=k, label=label, on="on" if k == statut else "")
        for k, label in TABS
    )

    handoffs = ""
    for h in db.list_handoffs():
        handoffs += """<div class="alert"><div class="row"><span class="ref">Un client attend une réponse humaine</span>
<span class="muted">{date}</span></div>
<div>{reason}</div><div class="muted">Dernier message : « {last} » · Instagram {igid}</div>
<div class="actions"><form method="post" action="/dashboard/handoffs/resolve">
<input type="hidden" name="instagram_id" value="{igid}">
<button class="btn">Rendre la conversation au bot</button></form></div></div>""".format(
            date=esc(h["created_at"]), reason=esc(h["reason"]), last=esc(h["last_message"]),
            igid=esc(h["instagram_id"]))
    if handoffs:
        handoffs = ("<h2>Conversations à reprendre</h2>"
                    '<p class="muted">Réponds au client directement dans Instagram, '
                    "puis rends la conversation au bot.</p>" + handoffs)

    items = db.list_orders(statut)
    if items:
        listing = "".join(order_html(o) for o in items)
    else:
        listing = '<div class="empty">Aucune commande dans cette vue.</div>'

    heading = "<h2>Commandes</h2>" if handoffs else ""
    body = '<h1>Commandes</h1>{}{}<div class="tabs">{}</div>{}'.format(handoffs, heading, tabs, listing)
    return page("Commandes", "orders", body)


@router.post("/orders/{pk}/status")
def change_status(pk: int, status: str = Form(...)):
    db.set_order_status(pk, status)
    return back("/dashboard/orders")


@router.post("/handoffs/resolve")
def resolve(instagram_id: str = Form(...)):
    db.resolve_handoff(instagram_id)
    return back("/dashboard/orders")


# -------------------------------------------------------------------- Stock
@router.get("/stock", response_class=HTMLResponse)
def stock():
    products = db.list_products()
    groups = {}
    for p in products:
        groups.setdefault(p["ref"], []).append(p)

    add_form = """<details {open}><summary>Ajouter un produit ou une pointure</summary>
<form method="post" action="/dashboard/stock/add">
<div class="grid">
<label>Référence<input name="ref" required placeholder="NK-AF1-BL"></label>
<label>Nom<input name="name" required placeholder="Nike Air Force 1"></label>
<label>Catégorie<input name="category" placeholder="basket"></label>
<label>Couleur<input name="color" placeholder="blanc"></label>
<label>Prix (TND)<input name="price" type="number" min="0" required></label>
</div>
<div id="variant-entries"><div class="variant-entry">
<label>Pointure<input name="sizes" required placeholder="42"></label>
<label>Stock pour cette pointure<input name="stocks" type="number" min="0" required placeholder="3"></label>
<button type="button" class="btn remove-variant" aria-label="Supprimer cette pointure" disabled>Retirer</button>
</div></div>
<button type="button" class="btn" id="add-variant">+ Ajouter une pointure</button>
<p class="muted">Le prix s’applique à toutes les pointures. Une référence et une pointure déjà présentes seront mises à jour.</p>
<button class="btn primary">Enregistrer</button></form></details>""".format(
        open="" if products else "open")

    add_form = add_form.replace(
        "</details>",
        """<script>
const variantEntries=document.getElementById('variant-entries');
document.getElementById('add-variant').addEventListener('click',()=>{
 const row=variantEntries.querySelector('.variant-entry').cloneNode(true);
 row.querySelectorAll('input').forEach(input=>input.value='');
 row.querySelector('.remove-variant').disabled=false;
 variantEntries.appendChild(row);
});
variantEntries.addEventListener('click',event=>{
 if(event.target.classList.contains('remove-variant') && variantEntries.children.length>1)
  event.target.closest('.variant-entry').remove();
});
</script></details>""")

    blocks = ""
    for ref, rows in groups.items():
        first = rows[0]
        trs = ""
        for r in rows:
            cls = ' class="out"' if r["stock"] == 0 else ""
            trs += """<tr><td>{size}</td>
<td><input form="u{id}" name="price" type="number" min="0" value="{price}" aria-label="Prix"></td>
<td><input form="u{id}" name="stock" type="number" min="0" value="{stock}" aria-label="Stock"></td>
<td{cls}>{state}</td>
<td><form id="u{id}" method="post" action="/dashboard/stock/{id}/update"></form>
<form id="d{id}" method="post" action="/dashboard/stock/{id}/delete"></form>
<button class="btn primary" form="u{id}">Enregistrer</button>
<button class="btn danger" form="d{id}" onclick="return confirm('Supprimer cette pointure ?')">Supprimer</button></td></tr>""".format(
                id=r["id"], size=esc(r["size"]), price=r["price"], stock=r["stock"], cls=cls,
                state="Rupture" if r["stock"] == 0 else ("Presque épuisé" if r["stock"] <= 2 else "En stock"))
        image = db.get_product_image(ref)
        preview = ('<img src="/dashboard/product-image/{ref}" alt="Photo de référence de {name}">'.format(
                       ref=esc(ref, quote=True), name=esc(first["name"])) if image else
                   '<div class="placeholder">Ajoute une photo de référence</div>')
        photo_panel = """<aside class="stock-photo">{preview}
<form method="post" enctype="multipart/form-data" action="/dashboard/stock/{ref}/image">
<input type="file" name="image" accept="image/*" required aria-label="Photo de référence">
<button class="btn primary">{button}</button></form></aside>""".format(
            preview=preview, ref=esc(ref, quote=True), button="Remplacer la photo" if image else "Ajouter la photo")
        blocks += """<div class="product"><strong>{name} {color}</strong>
<span class="muted">Réf. {ref} · {cat}</span></div>
<section class="stock-card">{photo_panel}<div class="stock-table"><div class="wrap"><table>
<tr><th>Pointure</th><th>Prix (TND)</th><th>Stock</th><th>État</th><th></th></tr>{trs}
</table></div></div></section>""".format(
            name=esc(first["name"]), color=esc(first["color"]), ref=esc(ref),
            cat=esc(first["category"]), photo_panel=photo_panel, trs=trs)

    if not blocks:
        blocks = '<div class="empty">Aucun produit pour l\'instant. Ajoute le premier ci-dessus.</div>'
    return page("Stock", "stock", "<h1>Stock</h1>" + add_form + blocks)


@router.get("/product-image/{ref}")
def product_image(ref: str):
    image = db.get_product_image(ref)
    if not image:
        raise HTTPException(status_code=404)
    return Response(content=image["image_data"], media_type=image["image_mime"])


@router.post("/stock/{ref}/image")
async def stock_image(ref: str, image: UploadFile = File(...)):
    if not image.content_type or not image.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Choisis un fichier image.")
    data = await image.read(5 * 1024 * 1024 + 1)
    if len(data) > 5 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="L’image doit faire 5 Mo maximum.")
    if not any(product["ref"] == ref for product in db.list_products()):
        raise HTTPException(status_code=404, detail="Produit introuvable.")
    db.set_product_image(ref, data, image.content_type)
    return back("/dashboard/stock")


@router.post("/stock/add")
def stock_add(ref: str = Form(...), name: str = Form(...), category: str = Form(""),
              color: str = Form(""), sizes: List[str] = Form(...),
              price: int = Form(...), stocks: List[int] = Form(...)):
    if len(sizes) != len(stocks) or not sizes or any(not size.strip() for size in sizes):
        raise HTTPException(status_code=400, detail="Vérifie les pointures et leurs stocks.")
    for size, quantity in zip(sizes, stocks):
        db.upsert_variant(ref, name, category, color, size, max(0, price), max(0, quantity))
    return back("/dashboard/stock")


@router.post("/stock/{pk}/update")
def stock_update(pk: int, price: int = Form(...), stock: int = Form(...)):
    db.update_variant(pk, stock, price)
    return back("/dashboard/stock")


@router.post("/stock/{pk}/delete")
def stock_delete(pk: int):
    db.delete_variant(pk)
    return back("/dashboard/stock")
