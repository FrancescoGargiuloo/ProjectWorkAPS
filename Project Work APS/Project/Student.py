import os, json, base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime, timezone
from MerkleTree import build_merkle_proof, hash_leaf_with_salt, generate_deterministic_salt
import hashlib

BASE_DIR = os.path.dirname(__file__)
DID_FOLDER = os.path.join(BASE_DIR, "DID")
CREDENTIAL_FOLDER = os.path.join(BASE_DIR, "credential")
KEYS_FOLDER = os.path.join(BASE_DIR, "keys")


class Student:
    """
    Rappresenta uno studente, gestendo la generazione di chiavi,
    documenti DID, la firma di messaggi e la generazione di presentazioni selettive.
    """
    def __init__(self, username, password, user_id, first_name=None, last_name=None):
        """
        Inizializza l'oggetto Student.
        :param username: Username dello studente.
        :param password: Password dello studente (usata per scopi interni, es. derivazione chiave per crittografia).
        :param first_name: Nome dello studente.
        :param last_name: Cognome dello studente.
        """
        self.username = username
        self.password = password
        self.first_name = first_name
        self.last_name = last_name
        self.user_id = user_id
        self.did = f"did:web:{username}.{user_id}.localhost"

        # Directory dedicata per ogni studente
        self.wallet_dir = os.path.join(BASE_DIR, f"wallet-{username}")
        self.keys_dir = os.path.join(self.wallet_dir, "keys")
        self.did_dir = os.path.join(self.wallet_dir, "did")
        self.credential_dir = os.path.join(self.wallet_dir, "credentials")

        os.makedirs(self.keys_dir, exist_ok=True)
        os.makedirs(self.did_dir, exist_ok=True)
        os.makedirs(self.credential_dir, exist_ok=True)

        self.priv_path = os.path.join(self.keys_dir, f"{username}_priv.pem")
        self.pub_path = os.path.join(self.keys_dir, f"{username}_pub.pem")
        self._trusted_dids = self.get_trusted_did()

        if not os.path.exists(self.priv_path):
            self._generate_keypair()

        self._update_did_document()

    def _generate_keypair(self):
        """
        Genera una coppia di chiavi RSA (privata e pubblica) e le salva in formato PEM.
        Le chiavi vengono generate solo se non esistono già.
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        with open(self.priv_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption() # Per semplicità, nessuna crittografia della chiave privata
            ))

        with open(self.pub_path, "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print(f"Nuove chiavi generate per lo studente {self.username}.")

    def get_public_key(self):
        """
        Restituisce la chiave pubblica dello studente in formato PEM.
        :return: La chiave pubblica in formato stringa PEM.
        """
        if not os.path.exists(self.pub_path):
            self._generate_keypair()
        with open(self.pub_path, "rb") as f:
            return f.read().decode()

    def _update_did_document(self):
        """
        Crea o aggiorna il file DID dello studente con la chiave pubblica corrente.
        Il nome del file DID è basato sul DID dello studente.
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
        path = os.path.join(self.did_dir, filename)
        with open(path, "w") as f:
            json.dump(did_doc, f, indent=2)
        print(f"Documento DID per {self.username} salvato in {path}")


    def sign(self, message: str) -> str:
        """
        Firma un messaggio con la chiave privata dello studente.
        :param message: Il messaggio da firmare.
        :return: La firma del messaggio in formato base64.
        :raises Exception: Se la chiave privata non può essere caricata.
        """
        try:
            with open(self.priv_path, "rb") as f:
                priv = serialization.load_pem_private_key(f.read(), password=None) # Nessuna password per semplicità
        except FileNotFoundError:
            raise Exception(f"Chiave privata non trovata per {self.username}. Impossibile firmare.")
        except Exception as e:
            raise Exception(f"Errore nel caricamento della chiave privata per {self.username}: {e}")

        signature = priv.sign(
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def get_trusted_did(self) -> list:
        """
        Returns a hardcoded list of trusted DIDs.
        This removes the need for explicit add_trusted_did calls in main.py.
        """
        return ["did:web:unisa.it", "did:web:rennes.it"]

    def load_erasmus_credential(self):
        """
        Carica la credenziale Erasmus dallo storage locale dello studente.
        :return: La credenziale Erasmus come dizionario, o None se non trovata/errore.
        """
        path = os.path.join(self.credential_dir, f"{self.username}_erasmus_credential.json")
        try:
            with open(path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"❌ Credenziale Erasmus non trovata per {self.username}.")
            return None
        except json.JSONDecodeError:
            print(f"❌ Errore di parsing della credenziale Erasmus per {self.username}.")
            return None

    def load_academic_credential(self):
        """
        Carica la credenziale Accademica dallo storage locale dello studente.
        :return: La credenziale Accademica come dizionario, o None se non trovata/errore.
        """
        path = os.path.join(self.credential_dir, f"{self.username}_academic_credential.json")
        try:
            with open(path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"❌ Credenziale Accademica non trovata per {self.username}.")
            return None
        except json.JSONDecodeError:
            print(f"❌ Errore di parsing della credenziale Accademica per {self.username}.")
            return None


    def get_wallet_path(self):
        """
        Restituisce il percorso della cartella wallet dello studente.
        """
        return self.wallet_dir

    def generate_selective_presentation_automated(self, revealed_fields=None):
        if revealed_fields is None:
            revealed_fields = {}

        academic_cred = self.load_academic_credential()
        if not academic_cred:
            print("Impossibile generare la presentazione selettiva: Credenziale non trovata.")
            return None
        exam_ids_to_include = list(academic_cred["credentialSubject"]["exams"].keys())

        disclosed_claims = {
            "exams": {},
            "credentialStatus": academic_cred["credentialSubject"]["credentialStatus"]
        }

        for exam_id in exam_ids_to_include:
            exam_data = academic_cred["credentialSubject"]["exams"][exam_id]
            fields_to_reveal = revealed_fields.get(exam_id, ["grade"])
            disclosed_claims["exams"][exam_id] = {}

            for field in fields_to_reveal:
                if field in exam_data:
                    disclosed_claims["exams"][exam_id][field] = exam_data[field]
                else:
                    print(f"Field {field} not found in exam_data keys: {list(exam_data.keys())}")

        proofs = {"exams": {}, "credentialStatus": {}}

        all_leaves = []
        leaf_mapping = {}

        # Esami ordinati
        for exam_id, exam_data in sorted(academic_cred["credentialSubject"]["exams"].items()):
            for field, value in sorted(exam_data.items()):
                salt = generate_deterministic_salt(exam_id, field, value, self)
                leaf_hash = hash_leaf_with_salt(exam_id, field, value, salt)
                all_leaves.append(leaf_hash)
                leaf_mapping[leaf_hash] = (exam_id, field, value, salt)

        # CredentialStatus ordinato
        for field, value in sorted(academic_cred["credentialSubject"]["credentialStatus"].items()):
            salt = generate_deterministic_salt("credentialStatus", field, value, self)
            leaf_hash = hash_leaf_with_salt("credentialStatus", field, value, salt)
            all_leaves.append(leaf_hash)
            leaf_mapping[leaf_hash] = ("credentialStatus", field, value, salt)

        # Proofs esami
        for exam_id in exam_ids_to_include:
            if exam_id not in academic_cred["credentialSubject"]["exams"]:
                continue

            proofs["exams"][exam_id] = {}
            exam_data = academic_cred["credentialSubject"]["exams"][exam_id]
            fields_to_reveal = revealed_fields.get(exam_id, ["grade"])

            for field, value in sorted(exam_data.items()):
                salt = generate_deterministic_salt(exam_id, field, value, self)
                target_leaf_hash = hash_leaf_with_salt(exam_id, field, value, salt)
                proof = build_merkle_proof(target_leaf_hash, all_leaves)

                if field in fields_to_reveal:
                    proofs["exams"][exam_id][field] = {"proof": proof}
                else:
                    proofs["exams"][exam_id][field] = {
                        "proof": proof,
                        "leafHash": target_leaf_hash
                    }

        # Proofs credentialStatus
        for field, value in sorted(academic_cred["credentialSubject"]["credentialStatus"].items()):
            salt = generate_deterministic_salt("credentialStatus", field, value, self)
            target_leaf_hash = hash_leaf_with_salt("credentialStatus", field, value, salt)
            proof = build_merkle_proof(target_leaf_hash, all_leaves)
            proofs["credentialStatus"][field] = {"proof": proof}

        # VP finale
        presentation_credential_subject = {
            "id": academic_cred["credentialSubject"]["id"],
            "givenName": academic_cred["credentialSubject"]["givenName"],
            "familyName": academic_cred["credentialSubject"]["familyName"],
            "homeUniversity": academic_cred["credentialSubject"]["homeUniversity"],
            "disclosedClaims": disclosed_claims,
            "proofs": proofs,
        }

        vp_to_sign = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://consorzio-universita-europee.eu/presentations/v1"
            ],
            "type": ["VerifiablePresentation"],
            "holder": self.did,
            "verifiableCredential": {
                "@context": academic_cred["@context"],
                "type": academic_cred["type"],
                "issuer": academic_cred["issuer"],
                "issuanceDate": academic_cred["issuanceDate"],
                "expirationDate": academic_cred["expirationDate"],
                "credentialSubject": presentation_credential_subject,
                "credentialStatus": academic_cred["credentialStatus"],
                "evidence": academic_cred["evidence"],
                "proof": academic_cred["proof"]
            }
        }

        nonce = base64.b64encode(os.urandom(16)).decode()
        created = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        signature = self.sign(json.dumps(vp_to_sign, sort_keys=True))

        vp = vp_to_sign.copy()
        vp["proof"] = {
            "type": "RsaSignature2023",
            "created": created,
            "verificationMethod": f"{self.did}#key-1",
            "nonce": nonce,
            "jws": signature
        }

        output_path = os.path.join(self.credential_dir, f"{self.username}_vp.json")
        with open(output_path, "w") as f:
            json.dump(vp, f, indent=2)

        print(f"\n✅ Verifiable Presentation salvata in: {output_path}")
        return vp