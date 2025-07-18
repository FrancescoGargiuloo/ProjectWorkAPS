import os, json, base64, hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime
from MerkleTree import hash_leaf, merkle_root, build_merkle_proof
BASE_DIR = os.path.dirname(__file__)         # ← directory in cui è il file
DID_FOLDER = os.path.join(BASE_DIR, "DID")   # ← sotto-cartella DID
CREDENTIAL_FOLDER = os.path.join(BASE_DIR, "credential")
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

    def generate_selective_presentation_from_terminal(self):
        cred_path = os.path.join(CREDENTIAL_FOLDER, f"{self.username}_academic_credential.json")
        if not os.path.exists(cred_path):
            print("❌ Credenziale accademica non trovata.")
            return None

        with open(cred_path, "r") as f:
            academic_cred = json.load(f)

        original_exams = academic_cred["credentialSubject"]["exams"]

        # 1. Calcolo tutte le foglie
        leaves = []
        leaf_lookup = {}  # hash → (examId, field, value)
        for exam in original_exams:
            for field in ["name", "grade", "credits", "date"]:
                if field in exam:
                    leaf_obj = {"examId": exam["examId"], "field": field, "value": exam[field]}
                    h = hash_leaf(leaf_obj)
                    leaves.append(h)
                    leaf_lookup[h] = leaf_obj

        # 2. Calcolo tutte le Merkle Proof
        full_proofs = {}  # { examId: { field: { "proof": [...], "value": "..." (solo se visibile) } } }
        for h, leaf in leaf_lookup.items():
            exam_id = leaf["examId"]
            field = leaf["field"]
            proof = build_merkle_proof(h, leaves)

            if exam_id not in full_proofs:
                full_proofs[exam_id] = {}

            full_proofs[exam_id][field] = {
                "proof": proof,
                "value": leaf["value"]  # verrà rimosso se il campo è nascosto (eccetto grade)
            }

        # 3. Chiedo cosa mostrare
        selected_claims = {}

        print("\n==== [ Selezione Esami e Attributi da Mostrare ] ====")
        for exam in original_exams:
            exam_id = exam["examId"]
            name = exam["name"]
            print(f"\n📝 Esame: {name} (ID: {exam_id})")

            include = input(f"→ Vuoi includere l'esame '{name}' nella presentazione? (s/N): ").strip().lower()
            if include != 's':
                continue

            selected_claims[exam_id] = {"name": name}

            for field in ["grade", "credits", "date"]:
                if field in exam:
                    if field == "grade":
                        # grade è obbligatorio
                        selected_claims[exam_id][field] = exam[field]
                    else:
                        show = input(f"   - Mostrare '{field}'? (s/N): ").strip().lower()
                        if show == "s":
                            selected_claims[exam_id][field] = exam[field]
                        else:
                            # Se il campo è nascosto, rimuovi il "value" dalla proof e aggiungi "leafHash"
                            if exam_id in full_proofs and field in full_proofs[exam_id]:
                                leaf_obj = {"examId": exam_id, "field": field, "value": exam[field]}
                                leaf_hash = hash_leaf(leaf_obj)
                                full_proofs[exam_id][field].pop("value", None)
                                full_proofs[exam_id][field]["leafHash"] = leaf_hash

        if not selected_claims:
            print("⚠️ Nessun esame selezionato. Presentazione non generata.")
            return None

        # 4. Sostituisco solo credentialSubject
        academic_cred["credentialSubject"] = {
            "disclosedClaims": selected_claims,
            "proofs": full_proofs
        }

        # 5. Creo la presentazione senza proof
        vp_to_sign = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://consorzio-universita-europee.eu/presentations/v1"
            ],
            "type": ["VerifiablePresentation"],
            "holder": self.did,
            "verifiableCredential": academic_cred
        }

        nonce = base64.b64encode(os.urandom(16)).decode()
        created = datetime.utcnow().isoformat() + "Z"

        # 6. Firma tutta la presentazione (senza proof)
        to_sign = json.dumps(vp_to_sign, sort_keys=True)
        signature = self.sign(to_sign)

        # 7. Aggiungo la prova con la firma
        vp = vp_to_sign.copy()
        vp["proof"] = {
            "type": "RsaSignature2023",
            "created": created,
            "verificationMethod": f"{self.did}#key-1",
            "nonce": nonce,
            "jws": signature
        }

        output_path = os.path.join(CREDENTIAL_FOLDER, f"{self.username}_vp.json")
        with open(output_path, "w") as f:
            json.dump(vp, f, indent=2)

        print(f"\n✅ Verifiable Presentation salvata in: {output_path}")
        return vp
