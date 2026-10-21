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
from fastapi.responses import HTMLResponse, RedirectResponse, Response

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
        path = "/register" if db.dashboard_user_count() == 0 else "/login"
        raise HTTPException(status_code=303, headers={"Location": path})
    return user


router = APIRouter(prefix="/dashboard", dependencies=[Depends(auth)])

STATUS_LABEL = {
    "nouvelle": "Nouvelle",
    "confirmee": "Confirmée",
    "livree": "Livrée",
    "annulee": "Annulée",
}

AUTH_CSS = """
:root{--navy:#172238;--pink:#d41463;--ink:#202b3c;--muted:#728096;--line:#e5e9f0}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#f4f6fa;color:var(--ink);
font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;display:grid;place-items:center;padding:24px}
.layout{width:min(980px,100%);min-height:600px;background:#fff;border-radius:24px;overflow:hidden;
box-shadow:0 28px 90px #17223822;display:grid;grid-template-columns:1.05fr .95fr}
.brand-panel{background:linear-gradient(145deg,#172238,#283a58 65%,#d41463);color:#fff;padding:52px 44px;
display:flex;flex-direction:column;justify-content:space-between;position:relative;overflow:hidden}
.brand-panel:after{content:"";position:absolute;width:340px;height:340px;border:1px solid #ffffff22;
border-radius:50%;right:-150px;bottom:-100px;box-shadow:0 0 0 35px #ffffff0b,0 0 0 75px #ffffff08}
.logo{display:flex;align-items:center;gap:12px;font-weight:750;font-size:1.2rem;position:relative;z-index:1}
.logo-mark{width:44px;height:44px;border-radius:14px;background:#fff;color:var(--pink);display:grid;place-items:center;font-weight:900}
.pitch{position:relative;z-index:1}.pitch h1{font-size:2.35rem;line-height:1.12;margin:0 0 14px;letter-spacing:-.04em}
.pitch p{color:#dce4f2;max-width:340px;margin:0}.panel-foot{font-size:.85rem;color:#c7d0df;position:relative;z-index:1}
.form-panel{padding:64px 54px;display:flex;flex-direction:column;justify-content:center}
.form-panel h2{font-size:1.8rem;letter-spacing:-.03em;margin:0 0 5px}.sub{color:var(--muted);margin:0 0 28px}
label{display:block;font-size:.9rem;font-weight:650;margin:17px 0 7px}
input{width:100%;padding:13px 14px;border:1px solid var(--line);border-radius:11px;font:inherit;outline:none}
input:focus{border-color:var(--pink);box-shadow:0 0 0 4px #d4146318}
button{width:100%;margin-top:22px;border:0;border-radius:11px;background:var(--pink);color:white;
padding:14px;font:inherit;font-weight:700;cursor:pointer;box-shadow:0 8px 18px #d4146330}
button:hover{background:#b80f53}.error{background:#fff0f2;border:1px solid #ffd0d8;color:#a31838;
padding:11px 13px;border-radius:10px;margin:0 0 15px}.switch{margin-top:22px;color:var(--muted);text-align:center}
a{color:var(--pink);font-weight:650;text-decoration:none}.switch a:hover{text-decoration:underline}
.note{margin-top:20px;font-size:.82rem;color:var(--muted)}
@media(max-width:720px){.layout{grid-template-columns:1fr;min-height:auto}.brand-panel{min-height:220px;padding:26px 28px}
.pitch h1{font-size:1.65rem}.panel-foot{display:none}.form-panel{padding:34px 28px}}
"""


def auth_page(mode, error=""):
    shop = esc(os.getenv("SHOP_NAME", "Shoes Center"))
    register = mode == "register"
    title = "Créer le compte propriétaire" if register else "Ravi de vous revoir"
    subtitle = ("Configurez votre accès sécurisé au tableau de bord." if register
                else "Connectez-vous pour gérer vos commandes et votre stock.")
    error_html = '<div class="error">{}</div>'.format(esc(error)) if error else ""
    if register:
        fields = """<label for="username">Nom d’utilisateur</label>
<input id="username" name="username" autocomplete="username" required minlength="3" maxlength="40">
<label for="password">Mot de passe</label>
<input id="password" name="password" type="password" autocomplete="new-password" required minlength="12">
<label for="confirm">Confirmer le mot de passe</label>
<input id="confirm" name="confirm" type="password" autocomplete="new-password" required minlength="12">
<button type="submit">Créer mon compte</button>
<p class="note">Le mot de passe doit contenir au moins 12 caractères. L’inscription publique se désactive après la création de ce compte.</p>"""
        switch = '<div class="switch">Vous avez déjà un compte ? <a href="/login">Se connecter</a></div>'
        action = "/register"
    else:
        fields = """<label for="username">Nom d’utilisateur</label>
<input id="username" name="username" autocomplete="username" required>
<label for="password">Mot de passe</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Se connecter</button>"""
        switch = ('<div class="switch"><a href="/register">Créer le premier compte</a></div>'
                  if db.dashboard_user_count() == 0 else "")
        action = "/login"
    return """<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title} · {shop}</title>
<style>{css}</style></head><body><div class="layout">
<section class="brand-panel"><div class="logo"><span class="logo-mark">SC</span>{shop}</div>
<div class="pitch"><h1>La gestion de votre boutique, en toute simplicité.</h1>
<p>Retrouvez vos commandes et votre stock au même endroit.</p></div>
<div class="panel-foot">Un espace réservé à l’équipe de la boutique.</div></section>
<section class="form-panel"><h2>{title}</h2><p class="sub">{subtitle}</p>{error}
<form method="post" action="{action}">{fields}</form>{switch}</section>
</div></body></html>""".format(title=esc(title), shop=shop, css=AUTH_CSS, subtitle=esc(subtitle),
           error=error_html, action=action, fields=fields, switch=switch)


@auth_router.get("/login", response_class=HTMLResponse)
def login_page():
    if db.dashboard_user_count() == 0:
        return RedirectResponse("/register", status_code=303)
    return HTMLResponse(auth_page("login"))


@auth_router.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if not _same_origin(request):
        raise HTTPException(status_code=403, detail="Origine invalide")
    user = db.get_dashboard_user(username)
    if not user or not _password_matches(password, user["password_hash"]):
        return HTMLResponse(auth_page("login", "Nom d’utilisateur ou mot de passe incorrect."),
                            status_code=401)
    response = RedirectResponse("/dashboard/orders", status_code=303)
    _set_session(response, request, user["id"])
    return response


@auth_router.get("/register", response_class=HTMLResponse)
def register_page():
    if db.dashboard_user_count() > 0:
        return RedirectResponse("/login", status_code=303)
    return HTMLResponse(auth_page("register"))


@auth_router.post("/register", response_class=HTMLResponse)
def register(request: Request, username: str = Form(...), password: str = Form(...),
             confirm: str = Form(...)):
    if not _same_origin(request):
        raise HTTPException(status_code=403, detail="Origine invalide")
    username = username.strip().lower()
    valid_username = (3 <= len(username) <= 40 and
                      username.replace("_", "").replace("-", "").isalnum())
    if not valid_username:
        return HTMLResponse(auth_page("register", "Choisissez un nom de 3 à 40 caractères (lettres, chiffres, _ ou -)."),
                            status_code=400)
    if len(password) < 12:
        return HTMLResponse(auth_page("register", "Le mot de passe doit contenir au moins 12 caractères."),
                            status_code=400)
    if password != confirm:
        return HTMLResponse(auth_page("register", "Les mots de passe ne correspondent pas."),
                            status_code=400)
    if not db.create_initial_dashboard_user(username, _hash_password(password)):
        return RedirectResponse("/login", status_code=303)
    user = db.get_dashboard_user(username)
    response = RedirectResponse("/dashboard/orders", status_code=303)
    _set_session(response, request, user["id"])
    return response


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
