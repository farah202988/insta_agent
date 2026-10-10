"""Base de données de la boutique (SQLite : un simple fichier shop.db, gratuit)."""
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("SHOP_DB_PATH", os.path.join(BASE_DIR, "shop.db"))

# Statuts d'une commande (stockés sans accent, affichés avec accents dans le tableau de bord)
STATUSES = ["nouvelle", "confirmee", "livree", "annulee"]


@contextmanager
def conn():
    c = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)  # autocommit
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


SAMPLE_PRODUCTS = [
    # ref, nom, catégorie, couleur, prix (TND), {pointure: stock}
    ("NK-AF1-BL", "Nike Air Force 1", "basket", "blanc", 289, {"40": 3, "41": 2, "42": 5, "43": 0}),
    ("NK-AF1-NR", "Nike Air Force 1", "basket", "noir", 289, {"41": 1, "42": 2, "43": 4}),
    ("AD-SAM-BL", "Adidas Samba", "basket", "blanc", 259, {"39": 2, "40": 3, "41": 0, "42": 1}),
    ("NB-530-GR", "New Balance 530", "basket", "gris", 249, {"40": 2, "41": 2, "42": 2, "43": 1}),
    ("CL-MOC-NR", "Mocassin cuir classique", "mocassin", "noir", 179, {"41": 3, "42": 3, "43": 2, "44": 1}),
]


def init_db():
    with conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ref TEXT NOT NULL,
                name TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT '',
                color TEXT NOT NULL DEFAULT '',
                size TEXT NOT NULL,
                price INTEGER NOT NULL DEFAULT 0,
                stock INTEGER NOT NULL DEFAULT 0,
                image_data BLOB,
                image_mime TEXT,
                UNIQUE(ref, size)
            );
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_ref TEXT,
                created_at TEXT NOT NULL,
                instagram_id TEXT,
                product_ref TEXT NOT NULL,
                product_name TEXT NOT NULL,
                color TEXT NOT NULL DEFAULT '',
                size TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                total INTEGER NOT NULL,
                customer_name TEXT NOT NULL,
                phone TEXT NOT NULL,
                address TEXT NOT NULL,
                payment TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'nouvelle'
            );
            CREATE TABLE IF NOT EXISTS handoffs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                instagram_id TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                last_message TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                resolved INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        columns = {row[1] for row in c.execute("PRAGMA table_info(products)")}
        if "image_data" not in columns:
            c.execute("ALTER TABLE products ADD COLUMN image_data BLOB")
        if "image_mime" not in columns:
            c.execute("ALTER TABLE products ADD COLUMN image_mime TEXT")
        if c.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
            for ref, name, cat, color, price, sizes in SAMPLE_PRODUCTS:
                for size, stock in sizes.items():
                    c.execute(
                        "INSERT INTO products (ref, name, category, color, size, price, stock) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (ref, name, cat, color, size, price, stock),
                    )


def _size_key(size):
    try:
        return (0, int(size))
    except (ValueError, TypeError):
        return (1, str(size))


# ---------------------------------------------------------------- Produits
def list_products():
    with conn() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT id, ref, name, category, color, size, price, stock FROM products"
        ).fetchall()]
    rows.sort(key=lambda r: (r["name"].lower(), r["color"].lower(), r["ref"], _size_key(r["size"])))
    return rows


def list_product_images():
    """Retourne une photo de référence au plus par produit (référence)."""
    with conn() as c:
        rows = c.execute(
            "SELECT ref, name, category, color, image_data, image_mime FROM products "
            "WHERE image_data IS NOT NULL GROUP BY ref ORDER BY name, color LIMIT 20"
        ).fetchall()
    return [dict(row) for row in rows]


def get_product_image(ref):
    with conn() as c:
        row = c.execute(
            "SELECT image_data, image_mime FROM products WHERE ref = ? "
            "AND image_data IS NOT NULL LIMIT 1", (str(ref),)
        ).fetchone()
    return dict(row) if row else None


def set_product_image(ref, image_data, image_mime):
    with conn() as c:
        c.execute(
            "UPDATE products SET image_data = ?, image_mime = ? WHERE ref = ?",
            (sqlite3.Binary(image_data), image_mime, str(ref)),
        )


def search_products(query):
    """Recherche par mots-clés. Accepte les féminins et pluriels simples (blanche -> blanc)."""
    words = [w for w in str(query).lower().split() if len(w) >= 3]
    found = {}
    scores = {}
    for r in list_products():
        text = "{} {} {} {}".format(r["name"], r["category"], r["color"], r["ref"]).lower()
        score = sum(1 for w in words if w in text or w[:4] in text)
        if words and score == 0:
            continue
        scores[r["ref"]] = score
        p = found.setdefault(
            r["ref"],
            {"id": r["ref"], "name": r["name"], "color": r["color"],
             "price_tnd": r["price"], "sizes_available": []},
        )
        if r["stock"] > 0:
            p["sizes_available"].append(r["size"])
    # on garde les produits qui correspondent au plus grand nombre de mots de la demande
    best = max(scores.values()) if scores else 0
    return [p for ref, p in found.items() if scores[ref] == best][:8]


def get_stock(ref, size):
    with conn() as c:
        row = c.execute(
            "SELECT stock FROM products WHERE ref = ? AND size = ?", (str(ref), str(size))
        ).fetchone()
    return row["stock"] if row else 0


def upsert_variant(ref, name, category, color, size, price, stock):
    with conn() as c:
        c.execute(
            "INSERT INTO products (ref, name, category, color, size, price, stock) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(ref, size) DO UPDATE SET name = excluded.name, "
            "category = excluded.category, color = excluded.color, "
            "price = excluded.price, stock = excluded.stock",
            (ref.strip(), name.strip(), category.strip().lower(), color.strip().lower(),
             str(size).strip(), int(price), int(stock)),
        )


def update_variant(pk, stock, price):
    with conn() as c:
        c.execute(
            "UPDATE products SET stock = ?, price = ? WHERE id = ?",
            (max(0, int(stock)), max(0, int(price)), int(pk)),
        )


def delete_variant(pk):
    with conn() as c:
        c.execute("DELETE FROM products WHERE id = ?", (int(pk),))


# --------------------------------------------------------------- Commandes
def place_order(ref, size, quantity, customer_name, phone, address, payment, instagram_id):
    """Crée la commande et retire le stock, en une seule opération sûre."""
    try:
        quantity = int(quantity)
    except (ValueError, TypeError):
        return {"status": "error", "reason": "quantité invalide"}
    if quantity < 1 or quantity > 20:
        return {"status": "error", "reason": "quantité invalide"}

    with conn() as c:
        c.execute("BEGIN IMMEDIATE")
        try:
            row = c.execute(
                "SELECT * FROM products WHERE ref = ? AND size = ?", (str(ref), str(size))
            ).fetchone()
            if row is None:
                c.execute("ROLLBACK")
                return {"status": "error", "reason": "produit ou pointure introuvable"}
            if row["stock"] < quantity:
                c.execute("ROLLBACK")
                return {"status": "error", "reason": "stock insuffisant",
                        "quantity_in_stock": row["stock"]}

            c.execute("UPDATE products SET stock = stock - ? WHERE id = ?", (quantity, row["id"]))
            total = row["price"] * quantity
            cur = c.execute(
                "INSERT INTO orders (created_at, instagram_id, product_ref, product_name, color, "
                "size, quantity, total, customer_name, phone, address, payment, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'nouvelle')",
                (now(), instagram_id, row["ref"], row["name"], row["color"], row["size"],
                 quantity, total, customer_name, phone, address, payment),
            )
            order_ref = "CMD-{:04d}".format(cur.lastrowid)
            c.execute("UPDATE orders SET order_ref = ? WHERE id = ?", (order_ref, cur.lastrowid))
            c.execute("COMMIT")
            return {"status": "ok", "order_id": order_ref, "total_tnd": total}
        except Exception:
            c.execute("ROLLBACK")
            raise


def list_orders(group="a-traiter"):
    where = {
        "a-traiter": "WHERE status IN ('nouvelle', 'confirmee')",
        "livree": "WHERE status = 'livree'",
        "annulee": "WHERE status = 'annulee'",
        "toutes": "",
    }.get(group, "")
    with conn() as c:
        rows = c.execute("SELECT * FROM orders {} ORDER BY id DESC LIMIT 200".format(where)).fetchall()
    return [dict(r) for r in rows]


def set_order_status(pk, new_status):
    """Change le statut. Une commande annulée remet le stock en rayon (et ne bouge plus ensuite)."""
    if new_status not in STATUSES:
        return False
    with conn() as c:
        c.execute("BEGIN IMMEDIATE")
        try:
            order = c.execute("SELECT * FROM orders WHERE id = ?", (int(pk),)).fetchone()
            if order is None or order["status"] == "annulee" or order["status"] == new_status:
                c.execute("ROLLBACK")
                return False
            if new_status == "annulee":
                c.execute(
                    "UPDATE products SET stock = stock + ? WHERE ref = ? AND size = ?",
                    (order["quantity"], order["product_ref"], order["size"]),
                )
            c.execute("UPDATE orders SET status = ? WHERE id = ?", (new_status, int(pk)))
            c.execute("COMMIT")
            return True
        except Exception:
            c.execute("ROLLBACK")
            raise


# --------------------------------------------------- Conversations à reprendre
def add_handoff(instagram_id, reason, last_message=""):
    with conn() as c:
        c.execute(
            "INSERT INTO handoffs (instagram_id, reason, last_message, created_at) VALUES (?, ?, ?, ?)",
            (str(instagram_id), reason, last_message, now()),
        )


def is_handoff(instagram_id):
    with conn() as c:
        row = c.execute(
            "SELECT 1 FROM handoffs WHERE instagram_id = ? AND resolved = 0 LIMIT 1",
            (str(instagram_id),),
        ).fetchone()
    return row is not None


def list_handoffs():
    with conn() as c:
        rows = c.execute(
            "SELECT * FROM handoffs WHERE resolved = 0 ORDER BY id DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def resolve_handoff(instagram_id):
    with conn() as c:
        c.execute("UPDATE handoffs SET resolved = 1 WHERE instagram_id = ?", (str(instagram_id),))


# ------------------------------------------------------------------ Chiffres
def counts():
    with conn() as c:
        new_orders = c.execute("SELECT COUNT(*) FROM orders WHERE status = 'nouvelle'").fetchone()[0]
        handoffs = c.execute("SELECT COUNT(*) FROM handoffs WHERE resolved = 0").fetchone()[0]
        out = c.execute("SELECT COUNT(*) FROM products WHERE stock = 0").fetchone()[0]
    return {"new_orders": new_orders, "handoffs": handoffs, "out_of_stock": out}
