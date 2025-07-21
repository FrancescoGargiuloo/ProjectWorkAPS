import os, json, base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime, timezone
from MerkleTree import hash_leaf, build_merkle_proof
import uuid

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

    def generate_selective_presentation_automated(self, reveal_fields: dict = None):
        """
        Genera una presentazione selettiva in modo automatizzato.
        Permette di specificare quali campi rivelare da ciascun esame.
        Se reveal_fields non è specificato, rivela un set predefinito (es. tutti i voti e crediti).

        :param reveal_fields: Un dizionario che specifica quali campi rivelare per ogni esame.
                              Formato: { "examId": {"field1": True, "field2": False}, ... }
                              Se un campo non è presente o è False, il suo valore non verrà rivelato,
                              ma la Merkle proof del suo hash verrà inclusa.
        :return: La Verifiable Presentation generata come dizionario, o None se fallisce.
        """
        academic_cred = self.load_academic_credential()
        if not academic_cred:
            print("Impossibile generare la presentazione selettiva: Credenziale Accademica non trovata.")
            return None

        original_exams = academic_cred["credentialSubject"]["exams"]

        # 1. Calcolo tutte le foglie Merkle per tutti i campi di tutti gli esami
        leaves = []
        leaf_lookup = {}  # Mappa hash della foglia all'oggetto foglia {hash: {examId, field, value}}
        for exam in original_exams:
            # Assicurati che ogni esame abbia un ID.
            exam_id = exam.get("examId", str(uuid.uuid4()))
            if "examId" not in exam:
                exam["examId"] = exam_id

            for field in ["name", "grade", "credits", "date"]:
                if field in exam:
                    leaf_obj = {"examId": exam_id, "field": field, "value": exam[field]}
                    h = hash_leaf(leaf_obj)
                    leaves.append(h)
                    leaf_lookup[h] = leaf_obj

        # 2. Calcolo tutte le Merkle Proof per tutte le foglie
        full_proofs = {}  # { examId: { field: { "proof": [...], "value": "..." (solo se visibile) } } }
        for h, leaf in leaf_lookup.items():
            exam_id = leaf["examId"]
            field = leaf["field"]
            proof = build_merkle_proof(h, leaves)

            if exam_id not in full_proofs:
                full_proofs[exam_id] = {}

            full_proofs[exam_id][field] = {
                "proof": proof,
                "value": leaf["value"]
            }

        # 3. Determina quali campi rivelare in base a 'reveal_fields' o a un set predefinito
        selected_claims = {}
        if reveal_fields is None:
            # Set di rivelazione predefinito: rivela nome, voto e crediti di tutti gli esami.
            for exam in original_exams:
                exam_id = exam["examId"] # Ora sappiamo che ha un ID
                selected_claims[exam_id] = {"name": exam.get("name")} # Nome sempre incluso se esame incluso
                if "grade" in exam:
                    selected_claims[exam_id]["grade"] = exam["grade"]
                if "credits" in exam:
                    selected_claims[exam_id]["credits"] = exam["credits"]
                # Non rivelare 'date' per impostazione predefinita
        else:
            # Usa la configurazione di rivelazione fornita
            for exam in original_exams:
                exam_id = exam["examId"]
                if exam_id in reveal_fields:
                    selected_claims[exam_id] = {}
                    for field, should_reveal in reveal_fields[exam_id].items():
                        if should_reveal and field in exam:
                            selected_claims[exam_id][field] = exam[field]
                        elif not should_reveal and field in exam:
                            # Se non deve essere rivelato, rimuovi il valore e metti l'hash della foglia
                            leaf_obj = {"examId": exam_id, "field": field, "value": exam[field]}
                            leaf_hash = hash_leaf(leaf_obj)
                            if exam_id in full_proofs and field in full_proofs[exam_id]:
                                full_proofs[exam_id][field].pop("value", None) # Rimuovi il valore rivelato
                                full_proofs[exam_id][field]["leafHash"] = leaf_hash # Includi solo l'hash della foglia
                    if "name" in exam and "name" not in selected_claims[exam_id]:
                        selected_claims[exam_id]["name"] = exam["name"]


        if not selected_claims:
            print("⚠️ Nessun esame selezionato per la presentazione. Presentazione non generata.")
            return None

        # 4. Costruisci il credentialSubject per la presentazione
        presentation_credential_subject = {
            "id": academic_cred["credentialSubject"]["id"],
            "givenName": academic_cred["credentialSubject"]["givenName"],
            "familyName": academic_cred["credentialSubject"]["familyName"],
            "homeUniversity": academic_cred["credentialSubject"]["homeUniversity"],
            "disclosedClaims": selected_claims, # I claims che lo studente ha scelto di rivelare
            "proofs": full_proofs # Tutte le Merkle proofs, con o senza valore a seconda della selezione
        }

        # 5. Crea la Verifiable Presentation senza il campo 'proof' (che verrà aggiunto dopo la firma)
        vp_to_sign = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://consorzio-universita-europee.eu/presentations/v1"
            ],
            "type": ["VerifiablePresentation"],
            "holder": self.did,
            "verifiableCredential": {
                **academic_cred,
                "credentialSubject": presentation_credential_subject
            }
        }

        nonce = base64.b64encode(os.urandom(16)).decode()
        created = datetime.now(timezone.utc).isoformat() + "Z"

        # 6. Firma tutta la presentazione
        to_sign = json.dumps(vp_to_sign, sort_keys=True)
        signature = self.sign(to_sign)

        # 7. Aggiungi la prova con la firma alla Verifiable Presentation
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
    
    def get_wallet_path(self):
        """
        Restituisce il percorso della cartella wallet dello studente.
        """
        return self.wallet_dir
    
