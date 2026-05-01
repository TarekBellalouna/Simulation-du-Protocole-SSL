import paho.mqtt.client as mqtt
import crypto_utils
import time

print("=== INITIALISATION DU CLIENT (ACHETEUR) ===")

# Variable globale pour stocker la clé symétrique une fois générée
cle_session_aes = None

# 1. Action lors de la connexion au broker
def on_connect(client, userdata, flags, rc):
    print("\n[+] Connecté au Broker MQTT !")
    # On s'abonne au canal où le serveur nous répondra
    client.subscribe("boutique/client")
    
    # PHASE 1 : Dire Bonjour (déclenche le processus)
    print("[<-] Envoi du message 'HELLO' au serveur...")
    client.publish("boutique/serveur", b"HELLO")

# 2. Réaction aux messages reçus
def on_message(client, userdata, msg):
    global cle_session_aes
    payload = msg.payload

    # PHASE 2 : Réception et vérification du certificat
    if payload.startswith(b"CERT:"):
        print("\n[->] Certificat X.509 (PEM) reçu du serveur.")
        cert_pem = payload[5:]
        
        # Chargement du certificat
        certificat = crypto_utils.charger_certificat_pem(cert_pem)

        # verification du certificat par comparaison des hash
        if not crypto_utils.verifier_certificat(certificat):
            print("[!!!] ALERTE : certificat invalide, connexion abandonnée.")
            client.disconnect()
            return
        
        # extraction de la clé publique
        cle_publique_serveur = certificat.public_key()
        print("[+] Clé publique RSA du serveur extraite avec succès.")

    # PHASE 3 : Génération de la clé AES et envoi chiffré en RSA
        print("\n[+] Génération de la clé de session AES-256...")
        cle_session_aes = crypto_utils.generer_cle_aes()
        # On chiffre la clé AES avec la clé publique RSA du serveur
        cle_aes_chiffree = crypto_utils.chiffrer_cle_symetrique(cle_publique_serveur, cle_session_aes)
        
        print("[<-] Envoi de la clé AES chiffrée (RSA) au serveur...")
        client.publish("boutique/serveur", b"KEY:" + cle_aes_chiffree)

    # PHASE 4 : OPTIONNELLE VOIR SCHEMA
    # corresponds a la vérification des hash de l'ensemble des échanges (
    # client hash les échanges, envoi à serveur qui hash ces propres échanges et vérifie en comparant
    # même processus pour serveur

    # PHASE 5 : réception et déchiffrement de la réponse AES
    # (On attend une petite seconde pour s'assurer que le serveur a bien le temps
    # de recevoir et déchiffrer la clé avant de recevoir la commande)
    # premier échange sécurisé
        time.sleep(1) 
        
        commande = "Je veux acheter 1 produit"
        print(f"\n[<-] Chiffrement et envoi de la commande : '{commande}'")
        commande_chiffree = crypto_utils.chiffrer_message_aes(cle_session_aes, commande)
        client.publish("boutique/serveur", b"CMD:" + commande_chiffree)
    
    # PHASE 5 : réception et déchiffrement de la réponse AES 
    # (si on déjà dans la boucle d'échange sécurisée)
    elif payload.startswith(b"REP:"):
        print("\n[->] Réponse chiffrée (AES) reçue du serveur.")
        reponse_chiffree = payload[4:]
        
        # Déchiffrement de la réponse
        reponse_claire = crypto_utils.dechiffrer_message_aes(cle_session_aes, reponse_chiffree)
        print(f"[+] Message décrypté du Vendeur : '{reponse_claire}'")
        
        print("\n=== TRANSACTION TERMINÉE AVEC SUCCÈS ===")
        # On peut déconnecter le client une fois l'achat terminé
        client.disconnect()

# 3. Démarrage du réseau
client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

# Même règle que pour le serveur : "127.0.0.1" en local pur, 
# ou le nom du conteneur ("mosquitto" par ex) si tu lances ça dans ton Docker Compose.
BROKER_ADDRESS = "127.0.0.1" 
client.connect(BROKER_ADDRESS, 1883, 60)

# Démarre la boucle réseau (elle s'arrêtera quand client.disconnect() sera appelé)
client.loop_forever()