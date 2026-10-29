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
.floor{position:absolute;bottom:3%;width:92%;height:80px;background:radial-gradient(ellipse at center,#e0201b8c,transparent 70%);filter:blur(12px)}
.robot{position:relative;width:min(430px,82%);height:auto;filter:drop-shadow(0 30px 40px #000a);animation:float 5s ease-in-out infinite}
.eye{animation:blink 5s infinite;transform-box:fill-box;transform-origin:center}
.robot.shy .eye{animation:none;transform:scaleY(.08);transition:transform .25s}
.robot .eye{transition:transform .25s}
.stage{cursor:default}
.robot-frame{position:relative;z-index:1;width:min(470px,100%);height:min(74vh,610px);border:0}
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
@media(max-width:860px){.layout{grid-template-columns:1fr;gap:0}.stage{min-height:290px;order:-1}.robot{width:min(250px,64%)}.robot-frame{width:min(300px,82%);height:min(38vh,300px)}.beam{width:60px}}
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
var f=document.getElementById('login-form'),b=document.getElementById('toggle-pw'),p=document.getElementById('password');
b.addEventListener('click',function(){var s=p.type==='password';p.type=s?'text':'password';b.setAttribute('aria-label',s?'Masquer le mot de passe':'Afficher le mot de passe');});
f.addEventListener('submit',function(){var s=document.getElementById('submit-btn');s.disabled=true;s.firstElementChild.textContent='Connexion…';});
})();
"""


def auth_page(error=""):
    error_html = '<div class="error" role="alert">{}</div>'.format(esc(error)) if error else ""
    return """<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>Connexion · InstaAgent</title>
<meta name="theme-color" content="#06100e">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@600;800&family=Inter:wght@300;400;500;600&display=swap">
<style>{css}</style></head><body>
<header class="topbar"><div class="brand">INSTA<i>·</i>AGENT</div><span>Espace propriétaire</span></header>
<main class="layout">
<section class="stage" aria-hidden="true"><div class="beam"></div><div class="floor"></div><iframe class="robot-frame" src="/auth/robot-3d" title="Robot InstaAgent animé" tabindex="-1"></iframe></section>
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
<script>{js}</script></body></html>""".format(css=AUTH_CSS, robot=AUTH_ROBOT, error=error_html, js=AUTH_JS)


@auth_router.get("/login", response_class=HTMLResponse)
def login_page():
    return HTMLResponse(auth_page())


@auth_router.get("/auth/mascot.png")
def auth_mascot():
    path = os.path.join(os.path.dirname(__file__), "static", "instaagent-mascot.png")
    return FileResponse(path, media_type="image/png")


@auth_router.get("/auth/robot-3d")
def auth_robot_3d():
    path = os.path.join(os.path.dirname(__file__), "static", "login-robot.html")
    return FileResponse(path, media_type="text/html")


@auth_router.get("/auth/login-robot.js")
def auth_robot_3d_script():
    path = os.path.join(os.path.dirname(__file__), "static", "login-robot.js")
    return FileResponse(path, media_type="text/javascript")


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
