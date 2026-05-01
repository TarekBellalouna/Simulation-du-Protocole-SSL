import paho.mqtt.client as mqtt
import crypto_utils

# PHASE 0 : initialisation du vendeur 
print("=== INITIALISATION DU SERVEUR ===")
stock_produits = 10
print(f"Stock initial : {stock_produits} produits.")

# Génération des clés et du certificat
cle_privee, cle_publique = crypto_utils.generer_cles_rsa()
certificat = crypto_utils.creer_certificat_auto_signe(cle_privee, cle_publique)
cert_pem = crypto_utils.exporter_certificat_pem(certificat)

cle_session_aes = None # Stockera la clé AES du client

# Fonctions de réaction aux messages MQTT
def on_connect(client, userdata, flags, rc):
    print("\n[+] Connecté au Broker MQTT !")
    client.subscribe("boutique/serveur") # Le serveur écoute sur ce canal

def on_message(client, userdata, msg):
    global cle_session_aes, stock_produits
    payload = msg.payload

    # PHASE 1 : ClientHello reçu + PHASE 2 : envoi du certificat
    if payload == b"HELLO":
        print("\n[->] Message 'HELLO' reçu du client.")
        print("[<-] Envoi du Certificat X.509 au client...")
        client.publish("boutique/client", b"CERT:" + cert_pem)

    # PHASE 3 : réception de la clé AES chiffrée en RSA, déchiffrement avec clé privée
    elif payload.startswith(b"KEY:"):
        print("\n[->] Clé de session (chiffrée en RSA) reçue.")
        cle_chiffree = payload[4:]
        try:
            cle_session_aes = crypto_utils.dechiffrer_cle_symetrique(cle_privee, cle_chiffree)
            print("[+] Clé AES-256 déchiffrée avec succès. Tunnel sécurisé prêt !")
        except Exception as e:
            print("[-] Erreur lors du déchiffrement de la clé :", e)

    # PHASE 5 : réception et déchiffrement de la commande AES, envoi de la réponse
    elif payload.startswith(b"CMD:"):
        if cle_session_aes is None:
            print("[-] Erreur : Commande reçue mais aucune clé de session établie.")
            return
            
        print("\n[->] Commande d'achat chiffrée (AES) reçue.")
        msg_chiffre = payload[4:]
        commande_claire = crypto_utils.dechiffrer_message_aes(cle_session_aes, msg_chiffre)
        print(f"[+] Message décrypté : '{commande_claire}'")

        # Traitement de l'achat
        if "acheter" in commande_claire.lower() and stock_produits > 0:
            stock_produits -= 1
            reponse = f"Achat confirmé ! Il reste {stock_produits} produits."
        else:
            reponse = "Achat refusé. Stock épuisé ou commande invalide."

        # On chiffre la réponse avant de l'envoyer
        reponse_chiffree = crypto_utils.chiffrer_message_aes(cle_session_aes, reponse)
        print("[<-] Envoi de la confirmation d'achat chiffrée...")
        client.publish("boutique/client", b"REP:" + reponse_chiffree)

# Démarrage du réseau
client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

# En local (sans Docker) pour tester, utiliser "localhost" ou "127.0.0.1"
# Si Docker, mettre le nom du service dans le broker (ex: "mosquitto")
BROKER_ADDRESS = "127.0.0.1" 
client.connect(BROKER_ADDRESS, 1883, 60)

print("En attente de clients...")
client.loop_forever()