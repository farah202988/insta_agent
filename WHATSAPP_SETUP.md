# Notifications WhatsApp de nouvelles commandes

L'application envoie une notification après l'enregistrement réussi d'une commande.
Elle utilise l'API WhatsApp Business Platform (Cloud API).

## Configuration requise

Ajoute ces variables dans le fichier `.env` du projet :

```env
WHATSAPP_ACCESS_TOKEN=jeton_d_acces_cloud_api
WHATSAPP_PHONE_NUMBER_ID=id_du_numero_whatsapp_business
WHATSAPP_ADMIN_PHONE=numero_du_destinataire_avec_indicatif_sans_plus
WHATSAPP_TEMPLATE_NAME=new_order_notification
WHATSAPP_TEMPLATE_LANGUAGE=fr
WHATSAPP_API_VERSION=v26.0
```

Dans WhatsApp Manager, crée puis fais approuver un modèle de message nommé
`new_order_notification`, en français, avec un corps contenant une variable, par exemple :

```text
Nouvelle commande reçue : {{1}}
```

La variable reçoit la référence de commande, l'article, la pointure, la quantité, le total,
le nom et le numéro du client ainsi que l'adresse de livraison.

Après configuration, redémarre le serveur. Les réponses de l'API WhatsApp et les erreurs
d'envoi sont consignées dans la console du serveur. N'envoie jamais le jeton d'accès dans
un message ou une capture d'écran.
