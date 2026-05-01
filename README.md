# Projet RT802 - Simulation de PKI et Échanges Sécurisés (TLS sur MQTT)

Ce projet a été réalisé dans le cadre du module **RT802** (Échanges sécurisés et PKI). L'objectif est de simuler "à la main" les grandes étapes d'un handshake TLS pour sécuriser une communication entre un client (Acheteur) et un serveur (Vendeur) au-dessus d'un réseau non sécurisé (MQTT).

## 🎯 Objectif du projet

Le projet démontre la mise en place d'un tunnel sécurisé de bout en bout garantissant l'**Intégrité** et la **Confidentialité** des échanges commerciaux. 

Le Vendeur possède un stock initial de 10 produits. L'Acheteur doit pouvoir passer une commande chiffrée. Pour cela, nous utilisons les algorithmes suivants selon les contraintes du projet[cite: 9] :
* **RSA (2048 bits) :** Cryptographie asymétrique pour l'échange de la clé de session.
* **AES (256 bits GCM) :** Cryptographie symétrique pour chiffrer les requêtes et réponses commerciales.
* **X.509 & SHA-1 :** Génération d'un certificat auto-signé par le serveur pour prouver son identité. *(Note : SHA-1 est utilisé ici à des fins strictement pédagogiques pour répondre aux consignes)*.

## ⚙️ Cinématique des échanges (Phases)

1. **Phase 0 (Initialisation) :** Le serveur génère ses clés RSA 2048 et son certificat X.509.
2. **Phases 1 & 2 (Hello & Certificat) :** Le client envoie un `HELLO` en clair via MQTT. Le serveur répond avec son certificat PEM. Le client extrait la clé publique RSA du serveur.
3. **Phase 3 (Échange de clé) :** Le client génère une clé de session AES 256, la chiffre avec la clé publique RSA du serveur et lui transmet.
4. **Phases 4 & 5 (Transaction) :** Le client envoie sa commande chiffrée en AES. Le serveur déchiffre, décrémente son stock, et renvoie une confirmation chiffrée en AES.

## 🛠️ Prérequis

Pour faire tourner ce projet en local, vous avez besoin de :
* **Python 3.x**
* Un broker MQTT local, comme **Mosquitto** (écoutant sur `127.0.0.1:1883`).

## 🚀 Installation & Configuration

Clonez ce dépôt sur votre machine locale :
   ```bash
   git clone https://github.com/TarekBellalouna/Simulation-du-Protocole-SSL.git
   
Pour éviter les conflits de dépendances, nous utilisons un environnement virtuel Python. Ouvrez un terminal à la racine du projet et suivez ces étapes :

### 1. Créer l'environnement virtuel
* **Sous Windows :** `python -m venv venv`

### 2. Activer l'environnement virtuel
* **Sous Windows :** `venv\Scripts\activate`

### 3. Installer les dépendances
Une fois l'environnement activé (le préfixe `(venv)` doit apparaître dans votre terminal), installez les librairies requises :
```bash
pip install -r requirements.txt
