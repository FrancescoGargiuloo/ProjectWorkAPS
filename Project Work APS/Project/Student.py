import os, json, base64, hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

BASE_DIR = os.path.dirname(__file__)         # ← directory in cui è il file
DID_FOLDER = os.path.join(BASE_DIR, "DID")   # ← sotto-cartella DID

KEYS_FOLDER = os.path.join(BASE_DIR, "keys")
DID_PATH = os.path.join(DID_FOLDER, "student_did.json")

class Student:
    def __init__(self, username, password, first_name=None, last_name=None):
        self.username = username
        self.password = password
        self.first_name = first_name
        self.last_name = last_name
        self.did = f"did:web:{username}.localhost"
        self.priv_path = os.path.join(KEYS_FOLDER, f"{username}_priv.pem")
        self.pub_path = os.path.join(KEYS_FOLDER, f"{username}_pub.pem")

        if not os.path.exists(self.priv_path):
            self._generate_keypair()

        self._update_did_document()

    def _generate_keypair(self):
        """
        Genera una coppia di chiavi RSA e le salva nei file priv.pem e pub.pem.
        Se i file esistono già, non fa nulla.
        Se non esistono, crea la coppia di chiavi e aggiorna il file DID dello studente.
        
        """

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        with open(self.priv_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(self.pub_path, "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    def get_public_key(self):
        """
        Restituisce la chiave pubblica dello studente in formato PEM.
        Se il file pub.pem non esiste, lo genera.
        """
        with open(self.pub_path, "rb") as f:
            return f.read().decode()

    def _update_did_document(self):
        """
        Crea o aggiorna il file DID dello studente con la chiave pubblica corrente.
        """
        did_doc = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": self.did,
            "verificationMethod": [{
                "id": f"{self.did}#key-1",
                "type": "RsaVerificationKey2018",
                "controller": self.did,
                "publicKeyPem": self.get_public_key()
            }]
        }
        filename = self.did.split(":")[-1].replace(".", "_") + "_did.json"
        path = os.path.join(DID_FOLDER, filename)
        with open(path, "w") as f:
            json.dump(did_doc, f, indent=2)

    def sign(self, message: str) -> str:
        """
        Firma un messaggio con la chiave privata dello studente.
        Args:
            message (str): Il messaggio da firmare.
        Returns:
            str: La firma del messaggio in formato base64.
        """
        with open(self.priv_path, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)

        signature = priv.sign(
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()


