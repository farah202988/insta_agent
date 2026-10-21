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
:root{--orange:#ff7a1a;--text:#f6f3ef;--muted:#9a9691;--line:#ffffff1a}
*{box-sizing:border-box}body{margin:0;height:100vh;overflow:hidden;background:#080807;color:var(--text);
font:15px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;display:grid;place-items:center;padding:20px}
.layout{width:min(1180px,100%);height:min(720px,calc(100vh - 40px));min-height:0;border:1px solid #ffffff14;
border-radius:22px;overflow:hidden;background:#0d0d0c;box-shadow:0 32px 100px #000b;
display:grid;grid-template-columns:1.12fr .88fr}
.brand-panel{min-height:0;background-color:#0c0b09;background-image:linear-gradient(#ff9b2410 1px,transparent 1px),
linear-gradient(90deg,#ff9b2410 1px,transparent 1px),radial-gradient(ellipse at 54% 42%,#46200d55,transparent 55%);
background-size:42px 42px,42px 42px,auto;color:#fff;padding:34px 42px;display:flex;flex-direction:column;
position:relative;overflow:hidden;border-right:1px solid #ffffff12}
.brand-panel:before{content:"";position:absolute;width:520px;height:180px;right:-120px;top:90px;
background:linear-gradient(115deg,transparent 35%,#ff7a1a35 48%,#ffc06a88 50%,#ff7a1a20 53%,transparent 68%);
filter:blur(9px);transform:rotate(-12deg);pointer-events:none}
.brand-panel:after{content:"";position:absolute;width:500px;height:500px;border:1px solid #ff8c2a20;
border-radius:50%;left:50%;bottom:-340px;transform:translateX(-50%);box-shadow:0 0 0 38px #ff8c2a09,0 0 0 82px #ff8c2a06}
.logo{display:flex;align-items:center;gap:11px;font-weight:750;font-size:1.05rem;position:relative;z-index:2}
.logo-mark{width:36px;height:36px;border:1px solid #ff9b246b;border-radius:11px;background:#ff8a1a15;
color:#ff9a3c;display:grid;place-items:center;font-size:.82rem;letter-spacing:-.05em}
.product-tag{margin:40px 0 12px;padding:6px 10px;border:1px solid #ff9b243d;border-radius:99px;
color:#ffc083;font-size:.68rem;font-weight:700;letter-spacing:.14em;width:max-content;position:relative;z-index:2}
.pitch{position:relative;z-index:2;max-width:520px}.pitch h1{font-size:clamp(2.2rem,4vw,3.65rem);line-height:1.03;
margin:0 0 18px;letter-spacing:-.055em;font-weight:720}.pitch h1 span{color:#ff9a42}
.pitch p{color:#aaa6a0;max-width:440px;font-size:1rem;margin:0}
.visual{position:relative;z-index:2;display:flex;align-items:center;justify-content:center;flex:1;min-height:0}
.mascot{width:min(240px,58%);max-height:min(240px,32vh);object-fit:contain;filter:drop-shadow(0 18px 35px #ff75172a)}
.panel-foot{font-size:.76rem;color:#77736d;position:relative;z-index:2;letter-spacing:.02em}
.form-panel{min-height:0;padding:38px clamp(30px,5vw,70px);display:flex;flex-direction:column;justify-content:center;background:#10100f}
.secure{display:flex;align-items:center;gap:8px;color:#aaa49c;font-size:.76rem;margin-bottom:28px}
.secure-dot{width:7px;height:7px;background:#62c995;border-radius:50%;box-shadow:0 0 12px #62c99588}
.form-panel h2{font-size:1.9rem;letter-spacing:-.04em;margin:0 0 7px}.sub{color:var(--muted);margin:0 0 22px;font-size:.92rem}
label{display:block;color:#e7e1d9;font-size:.82rem;font-weight:600;margin:13px 0 7px}
input{width:100%;padding:13px 14px;border:1px solid #ffffff20;background:#0b0b0a;color:#fff;border-radius:9px;
font:inherit;outline:none;transition:border-color .18s,box-shadow .18s}
input:focus{border-color:var(--orange);box-shadow:0 0 0 3px #ff7a1a20}
button{width:100%;margin-top:19px;border:0;border-radius:9px;background:linear-gradient(100deg,#ff8a24,#f06b12);
color:#1d1008;padding:13px;font:inherit;font-weight:750;cursor:pointer;box-shadow:0 8px 26px #ff7a1a22;transition:transform .18s,filter .18s}
button:hover{filter:brightness(1.08);transform:translateY(-1px)}
.error{background:#2c1710;border:1px solid #87401f;color:#ffb08a;padding:11px 13px;border-radius:9px;margin:0 0 15px}
.form-foot{margin-top:24px;padding-top:14px;border-top:1px solid #ffffff12;color:#77736d;font-size:.75rem}
@media(max-width:760px){body{height:auto;min-height:100svh;overflow:auto;padding:0}.layout{width:100%;height:auto;min-height:100svh;
border:0;border-radius:0;grid-template-columns:1fr}.brand-panel{min-height:430px;padding:24px 28px;border-right:0;border-bottom:1px solid #ffffff12}
.product-tag{margin-top:34px}.pitch h1{font-size:clamp(2.3rem,11vw,3.25rem)}.visual{min-height:165px}.mascot{width:175px;max-height:180px}
.form-panel{padding:34px 28px 40px}.secure{margin-bottom:20px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{transition:none!important}}
"""


def auth_page(error=""):
    error_html = '<div class="error">{}</div>'.format(esc(error)) if error else ""
    fields = """<label for="username">Nom d’utilisateur</label>
<input id="username" name="username" autocomplete="username" required>
<label for="password">Mot de passe</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Se connecter</button>"""
    return """<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Connexion · InstaAgent</title>
<style>{css}</style></head><body><div class="layout">
<section class="brand-panel"><div class="logo"><span class="logo-mark">IA</span>InstaAgent</div>
<div class="product-tag">INSTAGRAM COMMERCE AUTOMATION</div>
<div class="pitch"><h1>Automate your growth <span>with InstaAgent.</span></h1>
<p>Turn every Instagram conversation into a better customer experience.</p></div>
<div class="visual"><img class="mascot" src="/auth/mascot.png" alt="Mascotte robot InstaAgent"></div>
<div class="panel-foot">SMARTER CONVERSATIONS · BETTER CUSTOMER EXPERIENCES</div></section>
<section class="form-panel"><div class="secure"><span class="secure-dot"></span>Accès sécurisé propriétaire</div>
<h2>Ravi de vous revoir</h2><p class="sub">Connectez-vous pour gérer votre espace InstaAgent.</p>{error}
<form method="post" action="/login">{fields}</form>
<div class="form-foot">Accès réservé à l’équipe InstaAgent.</div></section>
</div></body></html>""".format(css=AUTH_CSS, error=error_html, fields=fields)


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
