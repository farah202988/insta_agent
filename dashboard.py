"""Tableau de bord de la boutique : commandes, stock, conversations à reprendre."""
import os
import secrets
from typing import List
from html import escape as esc

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials

import db

security = HTTPBasic()


def auth(credentials: HTTPBasicCredentials = Depends(security)):
    """Protège le tableau de bord par identifiant + mot de passe (définis dans .env)."""
    user = os.getenv("DASHBOARD_USER", "admin")
    password = os.getenv("DASHBOARD_PASSWORD")
    if not password:
        raise HTTPException(status_code=503, detail="Ajoute DASHBOARD_PASSWORD dans le fichier .env")
    ok_user = secrets.compare_digest(credentials.username.encode(), user.encode())
    ok_pass = secrets.compare_digest(credentials.password.encode(), password.encode())
    if not (ok_user and ok_pass):
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic"})


router = APIRouter(prefix="/dashboard", dependencies=[Depends(auth)])

STATUS_LABEL = {
    "nouvelle": "Nouvelle",
    "confirmee": "Confirmée",
    "livree": "Livrée",
    "annulee": "Annulée",
}

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
<a href="/dashboard/stock" class="{s}">Stock</a></nav></header>
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
