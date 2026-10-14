import asyncio
import hashlib
import hmac
import os
import threading
import time
from io import BytesIO
from typing import Optional
from urllib.parse import quote

import httpx
from dotenv import load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response
from google import genai
from google.genai import types
from PIL import Image

load_dotenv()

import dashboard  # noqa: E402  (après load_dotenv pour lire le .env)
import db  # noqa: E402
import whatsapp_service  # noqa: E402  (WhatsApp Cloud API de Meta)

try:  # optionnel : notifications Telegram / CallMeBot si notifier.py est présent
    import notifier  # noqa: E402
except ImportError:
    notifier = None

app = FastAPI()
db.init_db()
app.include_router(dashboard.router)

# --- Clés (lues dans le fichier .env) ---
APP_SECRET = os.getenv("IG_APP_SECRET")
VERIFY_TOKEN = os.getenv("IG_VERIFY_TOKEN")
IG_TOKEN = os.getenv("IG_ACCESS_TOKEN")
GEMINI_KEY = os.getenv("GEMINI_API_KEY")

GRAPH_URL = "https://graph.instagram.com/v26.0/me/messages"
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "https://insta-agent-8dox.onrender.com").rstrip("/")

# --- IA : modèles essayés dans l'ordre ---
gemini = genai.Client(api_key=GEMINI_KEY)
MODELS = [
    "gemini-3.8-flash",       # principal
    "gemini-3.5-flash-lite",  # secours 1
    "gemini-3.1-flash-lite",  # secours 2
]

SYSTEM_PROMPT = """Tu es l'assistant de la boutique de chaussures Shoes Center sur Instagram.
Tu réponds en français, en arabe ou en dialecte tunisien, dans la langue du client.
Ton ton est chaleureux, court et naturel (messages courts, adaptés à Instagram).

Ton rôle : aider le client à choisir une paire et prendre sa commande.

Règles absolues :
- Pour tout prix, couleur, pointure ou stock, tu utilises TOUJOURS les outils
  (search_products, check_stock). Tu n'inventes jamais une information.
  Quand tu cherches, traduis la demande en mots-clés français (ex : "sodé" -> "noir").
- Une catégorie générique (ex. « basket ») ou une couleur ne suffit jamais à identifier
  un modèle. Ne présente pas deux produits comme le même modèle uniquement parce qu'ils
  ont la même couleur ou la même catégorie.
- Les prix sont en dinars tunisiens (TND). Paiement à la livraison.
- Pour commander, il te faut : le modèle (id produit), la pointure, la quantité,
  le nom, le téléphone, l'adresse. Demande ce qui manque, une ou deux choses à la fois.
- Avant d'appeler create_order, fais un récapitulatif (produit, pointure, quantité,
  prix total, nom, téléphone, adresse) et attends un "oui" explicite du client.
- Si le produit ou la pointure n'est pas disponible, propose une alternative du catalogue.
- Si le client demande une photo, appelle search_products, puis APPELLE send_product_photo
  avec l'id du produit si has_photo est vrai. Ne dis jamais que tu n'as pas de photo sans
  avoir appelé send_product_photo. Si has_photo est faux, dis simplement qu'aucune photo
  n'est disponible pour ce modèle. Quand send_product_photo répond ok, dis simplement au
  client que tu lui envoies la photo (une phrase courte).
- Si le client est mécontent, demande un remboursement, un retour, ou quelque chose
  que tu ne peux pas faire, utilise handoff_to_human et dis qu'un conseiller va répondre."""

IMAGE_PROMPT = """Le client a joint une image. Les images de référence du catalogue sont
présentées avec leur référence, nom, couleur et catégorie. La dernière image est celle du
client. Cherche une correspondance du modèle, pas seulement une ressemblance de couleur.
Compare les éléments distinctifs : silhouette générale, hauteur de tige, forme de la pointe,
semelle, panneaux et coutures, lacets, languette, col et logos. La couleur et la catégorie
« basket » sont des indices secondaires et ne prouvent jamais que deux chaussures sont le
même modèle. Si deux références ont une couleur similaire mais une forme ou une construction
différente, traite-les comme des modèles différents. Ne choisis une référence que si plusieurs
détails visuels concordent. En cas de doute, dis clairement que tu ne peux pas confirmer le
modèle et demande au client le nom ou une photo plus nette. Si tu identifies une référence,
utilise search_products avec cette référence exacte pour retrouver le bon article, son prix
et ses pointures. N'utilise pas une recherche générique comme « basket rouge » pour décider
du modèle. Ne devine jamais les détails qui ne sont pas visibles."""

FALLBACK_TEXT = "Désolé, un petit souci technique. Un conseiller vous répondra bientôt."

# Mémoire des conversations en RAM (perdue au redémarrage)
histories = {}

# Anti-doublon : si l'IA réessaie après une erreur, elle ne doit pas créer la commande deux fois
_recent_orders = {}
_orders_lock = threading.Lock()
DUPLICATE_WINDOW = 120  # secondes

MODEL_TIMEOUT = 25  # secondes maximum d'attente par modèle avant de passer au suivant


# ---------- Notifications au commerçant ----------
def _notifier_ready():
    return notifier is not None and notifier.is_configured()


def notify_new_order(order, product_id, size, quantity, customer_name, phone, address,
                     payment_method):
    """Prévient le commerçant d'une commande DÉJÀ enregistrée : WhatsApp Cloud API et/ou
    Telegram. Ne lève jamais d'erreur : une notification ratée n'annule jamais la commande."""
    try:
        item = {}
        try:
            item = next((r for r in db.list_products()
                         if r["ref"] == str(product_id) and r["size"] == str(int(size))), {})
        except Exception:
            pass
        name = item.get("name", product_id)
        color = item.get("color", "")
        sent = False

        if whatsapp_service.is_configured():
            summary = whatsapp_service.format_order_summary(
                order["order_id"], quantity, name, color, size, order["total_tnd"],
                customer_name, phone, address)
            whatsapp_service.send_order_notification(summary)
            sent = True

        if _notifier_ready():
            notifier.notify_owner(notifier.order_message(
                order["order_id"], order["total_tnd"], quantity, size, name, color,
                customer_name, phone, address, payment_method))
            sent = True

        if not sent:
            print("NOTIFICATION NON ENVOYÉE : configure WHATSAPP_ACCESS_TOKEN, "
                  "WHATSAPP_PHONE_NUMBER_ID et WHATSAPP_ADMIN_PHONE dans .env")
    except Exception as e:
        print("ERREUR NOTIFICATION :", whatsapp_service.safe_text(e)[:300])


def notify_handoff(sender_id, reason, last_message):
    """Prévient le commerçant qu'un client attend une réponse humaine (Telegram si configuré).
    Le modèle WhatsApp 'nouvelle commande' ne convient pas à ce message."""
    try:
        if _notifier_ready():
            notifier.notify_owner(notifier.handoff_message(sender_id, reason, last_message))
    except Exception as e:
        print("ERREUR NOTIFICATION :", str(e)[:300])


# ---------- Test WhatsApp (protégé par le mot de passe du tableau de bord) ----------
_dashboard_auth = getattr(dashboard, "auth", None)
if _dashboard_auth is not None:
    @app.post("/test/whatsapp", dependencies=[Depends(_dashboard_auth)])
    def test_whatsapp():
        """Envoie le modèle configuré (hello_world pour l'instant) au numéro du commerçant."""
        result = whatsapp_service.send_test()
        whatsapp_service.log_result(result, "TEST WHATSAPP")
        result.update(whatsapp_service.current_template())
        return result


# ---------- Outils donnés à l'IA ----------
def build_tools(sender_id: str, pending_photos: list):
    """Crée les outils liés à ce client (pour savoir qui commande).
    pending_photos : liste remplie par send_product_photo ; les photos sont envoyées
    APRÈS la réponse de l'IA (voir reply_with_ai), pour ne pas bloquer le serveur."""

    def search_products(query: str) -> list:
        """Cherche des chaussures dans le catalogue. query : mots-clés en français
        (modèle, marque, couleur, type comme basket ou mocassin). Retourne les produits
        avec leur id, prix en TND, les pointures disponibles et has_photo (une photo
        catalogue existe)."""
        print("OUTIL search_products :", query)
        return db.search_products(query)

    def check_stock(product_id: str, size: int) -> dict:
        """Vérifie si une pointure d'un produit est disponible. Retourne la quantité en stock."""
        print("OUTIL check_stock :", product_id, size)
        try:
            qty = db.get_stock(product_id, int(size))
        except (ValueError, TypeError):
            return {"error": "pointure invalide"}
        return {"product_id": product_id, "size": size, "quantity_in_stock": qty}

    def send_product_photo(product_id: str) -> dict:
        """Envoie au client Instagram la photo catalogue du produit dont la référence est exacte.
        Utilise d'abord search_products pour obtenir cette référence (id)."""
        print("OUTIL send_product_photo :", product_id)
        photo = db.get_product_image(product_id)
        if not photo or not photo.get("image_data"):
            return {"status": "error", "reason": "aucune photo enregistrée pour ce produit"}
        if product_id not in pending_photos:
            pending_photos.append(product_id)
        return {"status": "ok", "message": "la photo est envoyée au client"}

    def create_order(product_id: str, size: int, quantity: int, customer_name: str,
                     phone: str, address: str, payment_method: str) -> dict:
        """Enregistre la commande. À appeler SEULEMENT après le récapitulatif et le
        'oui' explicite du client. payment_method : 'paiement à la livraison'."""
        print("OUTIL create_order :", product_id, size, quantity, customer_name)
        digits = "".join(ch for ch in str(phone) if ch.isdigit())
        try:
            key = (sender_id, str(product_id), str(int(size)), str(int(quantity)), digits)
        except (ValueError, TypeError):
            key = (sender_id, str(product_id), str(size), str(quantity), digits)
        with _orders_lock:
            previous = _recent_orders.get(key)
            if previous and time.time() - previous[0] < DUPLICATE_WINDOW:
                print("COMMANDE DÉJÀ ENREGISTRÉE (doublon évité) :", previous[1]["order_id"])
                return previous[1]
            try:
                result = db.place_order(product_id, int(size), quantity, customer_name,
                                        phone, address, payment_method, sender_id)
            except Exception as e:
                print("ERREUR BASE :", e)
                return {"status": "error", "reason": "enregistrement impossible"}
            if result.get("status") == "ok":
                _recent_orders[key] = (time.time(), result)
        if result.get("status") == "ok":
            print("=== NOUVELLE COMMANDE :", result["order_id"], "===")
            # La commande est enregistrée : on prévient le commerçant en arrière-plan
            threading.Thread(
                target=notify_new_order,
                args=(result, product_id, size, quantity, customer_name, phone, address,
                      payment_method),
                daemon=True,
            ).start()
        return result

    def handoff_to_human(reason: str) -> dict:
        """Passe la conversation à un conseiller humain (client mécontent, remboursement,
        demande hors catalogue). Le bot ne répondra plus à ce client ensuite."""
        print("=== ALERTE HUMAIN :", sender_id, "| Raison :", reason, "===")
        try:
            saved_history = db.get_conversation_history(sender_id, limit=20)
        except Exception as e:
            print("ERREUR LECTURE MÉMOIRE POUR HANDOFF :", str(e)[:200])
            saved_history = histories.get(sender_id, [])
        last = next((m["text"] for m in reversed(saved_history)
                     if m["role"] == "user"), "")
        db.add_handoff(sender_id, reason, last)
        threading.Thread(
            target=notify_handoff, args=(sender_id, reason, last), daemon=True
        ).start()
        return {"status": "ok"}

    return [search_products, check_stock, send_product_photo, create_order, handoff_to_human]


# ---------- Instagram ----------
async def send_message(recipient_id: str, text: str):
    """Envoie un message à un client Instagram."""
    headers = {"Authorization": f"Bearer {IG_TOKEN}"}
    payload = {"recipient": {"id": recipient_id}, "message": {"text": text}}
    timeout = httpx.Timeout(30, connect=15)
    async with httpx.AsyncClient(timeout=timeout) as client:
        for attempt in range(3):
            try:
                r = await client.post(GRAPH_URL, headers=headers, json=payload)
                print("ENVOI INSTAGRAM :", r.status_code, r.text[:500])
                if r.status_code == 429 or r.status_code >= 500:
                    if attempt < 2:
                        await asyncio.sleep(attempt + 1)
                        continue
                return
            except (httpx.TimeoutException, httpx.NetworkError) as e:
                print("ECHEC CONNEXION INSTAGRAM, tentative", attempt + 1, ":", str(e)[:200])
                if attempt < 2:
                    await asyncio.sleep(attempt + 1)
        print("ENVOI INSTAGRAM ABANDONNE après 3 tentatives")


async def send_photo(recipient_id: str, product_id: str) -> bool:
    """Envoie la photo catalogue d'un produit au client (appel asynchrone : le serveur reste
    libre de répondre à Meta pendant que Meta télécharge l'image)."""
    image_url = "{}/product-images/{}.jpg".format(PUBLIC_BASE_URL, quote(str(product_id), safe=""))
    payload = {
        "recipient": {"id": recipient_id},
        "message": {"attachment": {"type": "image", "payload": {"url": image_url}}}
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30, connect=10)) as client:
            r = await client.post(GRAPH_URL, headers={"Authorization": f"Bearer {IG_TOKEN}"},
                                  json=payload)
        print("ENVOI PHOTO INSTAGRAM :", r.status_code, r.text[:300])
        return r.status_code == 200
    except Exception as e:
        print("ERREUR ENVOI PHOTO INSTAGRAM :", type(e).__name__, str(e)[:200])
        return False


async def send_sender_action(recipient_id: str, action: str):
    """Affiche « vu » ou « en train d'écrire… » chez le client. Ne lève jamais d'erreur."""
    headers = {"Authorization": f"Bearer {IG_TOKEN}"}
    payload = {"recipient": {"id": recipient_id}, "sender_action": action}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(GRAPH_URL, headers=headers, json=payload)
            if r.status_code != 200:
                print("ACTION INSTAGRAM", action, r.status_code, r.text[:200])
    except Exception as e:
        print("ACTION INSTAGRAM IGNORÉE :", type(e).__name__)


async def show_typing(recipient_id: str):
    await send_sender_action(recipient_id, "mark_seen")
    await send_sender_action(recipient_id, "typing_on")


# ---------- IA ----------
async def ask_gemini(contents, tools):
    """Essaie chaque modèle dans l'ordre (25 s maximum chacun) ; 2 tours avec une courte pause."""
    for tour in range(2):
        for model in MODELS:
            started = time.perf_counter()
            try:
                resp = await asyncio.wait_for(
                    gemini.aio.models.generate_content(
                        model=model,
                        contents=contents,
                        config=types.GenerateContentConfig(
                            system_instruction=SYSTEM_PROMPT,
                            tools=tools,  # l'IA appelle les outils automatiquement
                        ),
                    ),
                    timeout=MODEL_TIMEOUT,
                )
                if resp.text:
                    print("MODELE UTILISE : {} ({:.1f} s)".format(model, time.perf_counter() - started))
                    return resp.text
            except asyncio.TimeoutError:
                print("ECHEC {} : trop lent (plus de {} s)".format(model, MODEL_TIMEOUT))
            except Exception as e:
                print("ECHEC {} après {:.1f} s : {}".format(
                    model, time.perf_counter() - started, str(e)[:200]))
        if tour == 0:
            await asyncio.sleep(1)
    return None


async def reply_with_ai(sender_id: str, text: str, image_url: Optional[str] = None):
    """Demande une réponse à l'IA, puis l'envoie au client."""
    if db.is_handoff(sender_id):
        print("Client pris en charge par un humain, le bot ne répond pas :", sender_id)
        return

    t_start = time.perf_counter()
    typing_task = asyncio.create_task(show_typing(sender_id))  # « vu » + « écrit… » tout de suite

    user_text = text or ("Le client a envoyé une image de produit." if image_url else "")
    try:
        history = db.get_conversation_history(sender_id, limit=19)
    except Exception as e:
        print("ERREUR LECTURE MÉMOIRE :", str(e)[:200])
        history = histories.get(sender_id, [])
    history.append({"role": "user", "text": user_text})
    history = history[-20:]
    while history and history[0]["role"] != "user":
        history.pop(0)
    histories[sender_id] = history
    try:
        db.add_conversation_message(sender_id, "user", user_text)
    except Exception as e:
        print("ERREUR SAUVEGARDE MESSAGE CLIENT :", str(e)[:200])

    contents = [
        types.Content(role=m["role"], parts=[types.Part(text=m["text"])])
        for m in history
    ]

    if image_url:
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                image_response = await client.get(image_url)
                image_response.raise_for_status()
            mime_type = image_response.headers.get("content-type", "image/jpeg").split(";")[0]
            if not mime_type.startswith("image/"):
                raise ValueError("La pièce jointe téléchargée n'est pas une image")
            reference_images = db.list_product_images()
            prompt = IMAGE_PROMPT
            if text:
                prompt += "\nMessage accompagnant la photo : " + text
            image_parts = [types.Part(text=prompt)]
            for product in reference_images:
                image_parts.append(types.Part(text=(
                    "Image de référence du catalogue — référence {ref}, {name}, "
                    "couleur {color}, catégorie {category}."
                ).format(**product)))
                image_parts.append(types.Part.from_bytes(
                    data=product["image_data"], mime_type=product["image_mime"] or "image/jpeg"
                ))
            image_parts.append(types.Part(text="Image envoyée par le client à identifier :"))
            image_parts.append(types.Part.from_bytes(data=image_response.content, mime_type=mime_type))
            contents[-1] = types.Content(role="user", parts=image_parts)
        except Exception as e:
            print("IMAGE CLIENT INACCESSIBLE :", str(e)[:200])
            contents[-1] = types.Content(
                role="user",
                parts=[types.Part(text=user_text + " (La photo n'a pas pu être chargée.)")],
            )

    t_ai = time.perf_counter()
    pending_photos = []  # rempli par l'outil send_product_photo
    answer = await ask_gemini(contents, build_tools(sender_id, pending_photos))
    t_answer = time.perf_counter()

    if answer is None:
        answer = FALLBACK_TEXT
    else:
        # Les photos partent ici, après l'IA : le serveur est libre de répondre à Meta
        for ref in pending_photos:
            if not await send_photo(sender_id, ref):
                answer += "\n(Désolé, la photo n'a pas pu être envoyée pour le moment.)"
    history.append({"role": "model", "text": answer})
    history = history[-20:]
    histories[sender_id] = history
    try:
        db.add_conversation_message(sender_id, "model", answer)
    except Exception as e:
        print("ERREUR SAUVEGARDE RÉPONSE BOT :", str(e)[:200])

    await typing_task
    await send_message(sender_id, answer)
    t_end = time.perf_counter()
    print("DURÉES : préparation {:.1f} s | IA {:.1f} s | envoi {:.1f} s | TOTAL {:.1f} s".format(
        t_ai - t_start, t_answer - t_ai, t_end - t_answer, t_end - t_start))


# ---------- Webhook ----------
@app.api_route("/product-images/{ref}.jpg", methods=["GET", "HEAD"])
async def public_product_image(ref: str):
    """Photo de catalogue publique, convertie en JPEG pour que Meta puisse la télécharger."""
    photo = db.get_product_image(ref)
    if not photo or not photo.get("image_data"):
        raise HTTPException(status_code=404, detail="Image introuvable")
    print("PHOTO DEMANDÉE :", ref, photo["image_mime"], len(photo["image_data"]))
    try:
        img = Image.open(BytesIO(bytes(photo["image_data"]))).convert("RGB")
        img.thumbnail((1080, 1080))
        buf = BytesIO()
        img.save(buf, "JPEG", quality=85)
    except Exception as e:
        print("ERREUR CONVERSION IMAGE :", ref, type(e).__name__, str(e)[:200])
        raise HTTPException(status_code=415, detail="Format d'image non supporté")
    return Response(content=buf.getvalue(), media_type="image/jpeg",
                    headers={"Cache-Control": "public, max-age=3600"})


@app.get("/webhook")
async def verify(request: Request):
    p = request.query_params
    if p.get("hub.mode") == "subscribe" and p.get("hub.verify_token") == VERIFY_TOKEN:
        return Response(content=p.get("hub.challenge"), media_type="text/plain")
    raise HTTPException(status_code=403)


@app.post("/webhook")
async def receive(request: Request, background_tasks: BackgroundTasks):
    body = await request.body()

    signature = request.headers.get("X-Hub-Signature-256", "")
    expected = "sha256=" + hmac.new(APP_SECRET.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=403)

    data = await request.json()

    for entry in data.get("entry", []):
        my_id = entry.get("id")

        events = list(entry.get("messaging", []))
        for change in entry.get("changes", []):
            if change.get("field") == "messages":
                events.append(change.get("value", {}))

        for event in events:
            msg = event.get("message", {})
            sender = event.get("sender", {}).get("id")
            text = msg.get("text")
            attachments = msg.get("attachments", [])
            if isinstance(attachments, dict):
                attachments = [attachments]
            image_url = next((
                a.get("payload", {}).get("url")
                for a in attachments
                if isinstance(a, dict) and a.get("type") == "image"
                and isinstance(a.get("payload"), dict) and a.get("payload", {}).get("url")
            ), None)

            if attachments:
                print("PIÈCE JOINTE REÇUE :", [a.get("type", "inconnu") for a in attachments
                      if isinstance(a, dict)], "| URL image détectée :", bool(image_url))

            if (not text and not image_url) or msg.get("is_echo") or sender == my_id:
                continue

            print("Message entrant | Texte :", bool(text), "| Image :", bool(image_url))
            try:
                if not db.allow_incoming_message(sender, limit=20):
                    print("LIMITE ANTI-SPAM ATTEINTE")
                    continue
            except Exception as e:
                # La base étant indisponible, on ne consomme pas le quota Gemini sans contrôle.
                print("ERREUR CONTRÔLE ANTI-SPAM :", str(e)[:200])
                continue
            background_tasks.add_task(reply_with_ai, sender, text or "", image_url)

    return {"status": "ok"}