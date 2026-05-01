import os
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID
from cryptography import x509

# ==========================================
# PARTIE 1 : ASYMÉTRIQUE (RSA) ET CERTIFICATS
# ==========================================

def generer_cles_rsa():
    """Génère une paire de clés RSA 2048 bits."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def creer_certificat_auto_signe(private_key, public_key):
    """Crée un certificat X.509 auto-signé utilisant SHA-256."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Champagne-Ardenne"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Reims"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Boutique Universite"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Serveur Boutique"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).sign(private_key, hashes.SHA256()) 

    return cert

def exporter_certificat_pem(cert):
    """Exporte le certificat au format PEM (texte)."""
    return cert.public_bytes(serialization.Encoding.PEM)

def charger_certificat_pem(cert_bytes):
    """Charge un certificat reçu au format PEM."""
    return x509.load_pem_x509_certificate(cert_bytes)

def verifier_certificat(certificat):
    """
    Vérifie la signature du certificat.
    Re-hache les infos du certificat et compare au hash signé avec la clé privée.
    Auto-signé ici : prouve l'intégrité, pas l'identité.
    """
    try:
        cle_publique = certificat.public_key()
        cle_publique.verify(
            certificat.signature,
            certificat.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificat.signature_hash_algorithm,
        )
        return True
    except Exception as e:
        print(f"Erreur de vérification : {e}")
        return False

# ==========================================
# PARTIE 2 : SYMÉTRIQUE (AES 256)
# ==========================================

def chiffrer_cle_symetrique(cle_publique, cle_aes):
    """Chiffre la clé AES avec la clé publique RSA."""
    return cle_publique.encrypt(
        cle_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def dechiffrer_cle_symetrique(cle_privee, cle_aes_chiffree):
    """Déchiffre la clé AES avec la clé privée RSA."""
    return cle_privee.decrypt(
        cle_aes_chiffree,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def generer_cle_aes():
    """Génère une clé AES de 256 bits."""
    return AESGCM.generate_key(bit_length=256)

def chiffrer_message_aes(cle_aes, message_texte):
    """Chiffre un texte en utilisant AES-256 GCM."""
    aesgcm = AESGCM(cle_aes)
    nonce = os.urandom(12) 
    donnees_chiffrees = aesgcm.encrypt(nonce, message_texte.encode(), None)
    return nonce + donnees_chiffrees 

def dechiffrer_message_aes(cle_aes, payload_chiffre):
    """Déchiffre un message AES-256 GCM reçu."""
    aesgcm = AESGCM(cle_aes)
    nonce = payload_chiffre[:12] 
    donnees_chiffrees = payload_chiffre[12:]
    message_clair = aesgcm.decrypt(nonce, donnees_chiffrees, None)
    return message_clair.decode()