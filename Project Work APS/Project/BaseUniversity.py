import os, json, base64, random, string
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

class BaseUniversity:
    def __init__(self, did, priv_key_filename, pub_key_filename, db_name, keys_folder, did_folder, user_manager_cls, blockchain_cls, revocation_registry_cls):
        self.did = did
        self.priv_path = os.path.join(keys_folder, priv_key_filename)
        self.pub_path = os.path.join(keys_folder, pub_key_filename)
        self.did_folder = did_folder
        self.user_manager = user_manager_cls(db_name=db_name)
        self.blockchain = blockchain_cls()
        self.revocation_registry = revocation_registry_cls()
        self._challenges = {}

        # Assicurati che le chiavi siano caricate/generate prima di tentare di usarle
        self._private_key = None
        self._public_key = None
        self._load_or_generate_keypair()

        self._update_did_document()

    def _load_or_generate_keypair(self):  # Nuovo metodo
        if os.path.exists(self.priv_path):
            with open(self.priv_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None  # In un'applicazione reale, proteggi la chiave con una password
                )
            self._public_key = self._private_key.public_key()
            print(f"Chiavi per {self.did} caricate.")
        else:
            self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self._public_key = self._private_key.public_key()
            with open(self.priv_path, "wb") as f:
                f.write(self._private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(self.pub_path, "wb") as f:
                f.write(self._public_key.public_bytes(  # Usa self._public_key qui
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            print(f"Chiavi per {self.did} generate e salvate.")

    def _update_did_document(self):
        with open(self.pub_path, "rb") as f:
            pub_pem = f.read().decode()
        filename = self.did.split(":")[-1].replace(".", "_") + "_did.json"
        path = os.path.join(self.did_folder, filename)
        os.makedirs(self.did_folder, exist_ok=True)
        did_doc = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": self.did,
            "verificationMethod": [{
                "id": f"{self.did}#key-1",
                "type": "RsaVerificationKey2018",
                "controller": self.did,
                "publicKeyPem": pub_pem
            }]
        }
        with open(path, "w") as f:
            json.dump(did_doc, f, indent=2)

    def resolve_did(self, did: str) -> dict:
        filename = did.split(":")[-1].replace(".", "_") + "_did.json"
        path = os.path.join(self.did_folder, filename)
        if not os.path.exists(path):
            raise Exception(f"DID document non trovato per {did}")
        with open(path, "r") as f:
            return json.load(f)

    def register_student(self, user_id, username, password, first_name, last_name, public_key_pem):
        success = self.user_manager.first_login(user_id, username, password, first_name, last_name)
        if success:
            return self.user_manager.update_user_did_and_public_key(user_id, "", public_key_pem)
        return False

    def authenticate_student(self, username, password):
        return self.user_manager.authenticate_user(username, password)

    def assign_did_to_student(self, user_id, new_did, public_key_pem):
        return self.user_manager.update_user_did_and_public_key(user_id, new_did, public_key_pem)

    def generate_challenge(self, user_id: str) -> str:
        user_data = self.user_manager.get_user_by_id(user_id)
        if not user_data or not user_data.get("did"):
            print(f"Errore in generate_challenge: DID non trovato per l'utente con ID {user_id}")
            return None
        student_did = user_data["did"]
        challenge_value = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        self._challenges[student_did] = {
            "value": challenge_value,
            "expires_at": datetime.now() + timedelta(minutes=5)
        }
        return challenge_value

    def verify_challenge_response(self, user_id: str, signature_b64: str):
        user_data = self.user_manager.get_user_by_id(user_id)
        if not user_data:
            return {"status": "error", "message": f"Utente con ID {user_id} non trovato nel DB dell'università."}
        student_did = user_data.get("did")
        if not student_did:
            return {"status": "error", "message": f"DID non assegnato all'utente con ID {user_id} nel DB."}
        student_public_key_pem = user_data.get("public_key_pem")
        if not student_public_key_pem:
            return {"status": "error", "message": f"Chiave pubblica non trovata per il DID: {student_did} nel DB."}
        challenge_data = self._challenges.get(student_did)
        if not challenge_data:
            return {"status": "error", "message": "Nessun challenge attivo trovato per questo DID."}
        if datetime.now() > challenge_data["expires_at"]:
            del self._challenges[student_did]
            return {"status": "error", "message": "Challenge scaduto."}

        try:
            public_key = serialization.load_pem_public_key(student_public_key_pem.encode())
            public_key.verify(
                base64.b64decode(signature_b64),
                challenge_data["value"].encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            del self._challenges[student_did]
            return {"status": "ok", "message": "Challenge verificato con successo."}
        except InvalidSignature:
            del self._challenges[student_did]
            return {"status": "error", "message": "Firma non valida."}
        except Exception as e:
            del self._challenges[student_did]
            return {"status": "error", "message": f"Errore durante la verifica: {e}"}

    # METODO AGGIUNTO QUI
    def get_public_key(self):
        """Restituisce la chiave pubblica dell'università in formato PEM."""
        if self._public_key:
            return self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        return None
    
    def revocate_credential(self, erasmus_credential):
        """Metodo da implementare nelle sottoclassi per revocare una credenziale Erasmus."""
        raise NotImplementedError("Questo metodo deve essere implementato dalla sottoclasse.")

    