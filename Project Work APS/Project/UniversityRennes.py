import os
import json
import base64
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

from Blockchain import Blockchain
from RevocationRegistry import RevocationRegistry
from MerkleTree import hash_leaf, merkle_root

BASE_DIR = os.path.dirname(__file__)
KEYS_FOLDER = os.path.join(BASE_DIR, "keys")
DID_FOLDER = os.path.join(BASE_DIR, "DID")
CREDENTIAL_FOLDER = os.path.join(BASE_DIR, "credential")
os.makedirs(CREDENTIAL_FOLDER, exist_ok=True)
os.makedirs(KEYS_FOLDER, exist_ok=True)
os.makedirs(DID_FOLDER, exist_ok=True)

DID_PATH = os.path.join(DID_FOLDER, "rennes_did.json")
EXAM = os.path.join(BASE_DIR, "exams.json")

class UniversityRennes:
    def __init__(self, did="did:web:rennes.it"):
        self.did = did
        self.priv_path = os.path.join(KEYS_FOLDER, "rennes_priv.pem")
        self.pub_path = os.path.join(KEYS_FOLDER, "rennes_pub.pem")
        self.blockchain = Blockchain()
        self.revocation_registry = RevocationRegistry()

        if not os.path.exists(self.priv_path):
            self._generate_keypair()

        self._update_did_document()

    def _generate_keypair(self):
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

    def _update_did_document(self):
        with open(self.pub_path, "rb") as f:
            pub_pem = f.read().decode()

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

        with open(DID_PATH, "w") as f:
            json.dump(did_doc, f, indent=2)

    def resolve_did(self, did: str) -> dict:
        """
        Finta risoluzione DID per esempio: cerca localmente un file DID nel filesystem.
        """
        filename = did.split(":")[-1].replace(".", "_") + "_did.json"
        path = os.path.join(DID_FOLDER, filename)  # Cartella dove le università si scambiano i DID document
        if not os.path.exists(path):
            raise Exception(f"DID document non trovato per {did}")
        with open(path, "r") as f:
            return json.load(f)

    def verify_erasmus_credential(self, credential: dict) -> bool:
        issuer_did = credential.get("issuer")
        proof = credential.get("proof", {})
        jws = proof.get("jws")
        verification_method = proof.get("verificationMethod")
        status = credential.get("credentialStatus", {})
        
        # 1. Verifica che il DID sia trusted
        if issuer_did not in self.get_trusted_dids():
            print("❌ DID emittente non è nella lista trusted.")
            return False

        try:
            # 2. Verifica della firma
            did_doc = self.resolve_did(issuer_did)
            pub_key_pem = None
            for vm in did_doc.get("verificationMethod", []):
                if vm["id"] == verification_method:
                    pub_key_pem = vm["publicKeyPem"]
                    break

            if not pub_key_pem:
                print("❌ verificationMethod non trovato.")
                return False

            public_key = serialization.load_pem_public_key(pub_key_pem.encode())

            unsigned_cred = credential.copy()
            unsigned_cred.pop("proof", None)
            unsigned_cred.pop("evidence", None)
            payload = json.dumps(unsigned_cred, sort_keys=True).encode()

            public_key.verify(
                base64.b64decode(jws),
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("✅ Firma valida.")

            # 3. Verifica stato di revoca
            namespace = status.get("namespace")
            revocation_list = status.get("revocationList")
            revocation_key = status.get("revocationKey")

            is_revoked = self.revocation_registry.is_revoked(namespace, revocation_list, revocation_key)
            if is_revoked is None:
                print("⚠️ Stato di revoca non trovato. Credenziale potenzialmente non valida.")
                return False
            elif is_revoked:
                print("❌ Credenziale revocata.")
                return False
            else:
                print("✅ Credenziale NON revocata.")
                return True

        except InvalidSignature:
            print("❌ Firma non valida.")
            return False
        except Exception as e:
            print(f"❌ Errore nella verifica: {e}")
            return False


    def get_trusted_dids(self):
        return ["did:web:unisa.it"]

    def generate_academic_credential(self, student, exams: list):
        issuance_date = datetime.utcnow().isoformat() + "Z"
        credential_id = f"urn:uuid:{student.username}-academic-cred"

        # Genera foglie a livello di campo (coerente con selective disclosure)
        leaves = []
        for exam in exams:
            for field in ["name", "grade", "credits", "date"]:
                if field in exam:
                    leaf_obj = {"examId": exam["examId"], "field": field, "value": exam[field]}
                    h = hash_leaf(leaf_obj)
                    leaves.append(h)

        # Calcola la Merkle Root
        root = merkle_root(leaves)

        # Firma la root
        priv_key = serialization.load_pem_private_key(open(self.priv_path, "rb").read(), password=None)
        jws_signature = base64.b64encode(priv_key.sign(
            root.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )).decode()

        # Salva su blockchain
        tx_hash = self.blockchain.add_block({"merkleRoot": root, "student": self.did})

        # Costruisci la credenziale
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://consorzio-universita.example/credentials/v1"
            ],
            "type": ["VerifiableCredential", "AcademicCredential"],
            "issuer": self.did,
            "issuanceDate": issuance_date,
            "credentialSchema": {
                "id": "https://consorzio.example/schema/academic-v1",
                "type": "JsonSchema"
            },
            "credentialSubject": {
                "id": student.did,
                "givenName": student.first_name or "N/A",
                "familyName": student.last_name or "N/A",
                "homeUniversity": "Università di Salerno",
                "exams": exams
            },
            "credentialStatus": {
                "id": f"https://consorzio-univ.it/creds/{student.username}-academic-status",
                "type": "ConsortiumRevocationRegistry2024",
                "registry": "0xRegistryAddresRennes",
                "namespace": "0x9876543210FEDCBA09876543210FEDCBA0987654",
                "revocationList": "0x456789ABCDEF456789ABCDEF456789ABCDEF1234",
                "revocationKey": self.revocation_registry.generate_revocation_key(credential_id)
            },
            "evidence": {
                "type": "BlockchainRecord",
                "description": "Merkle Root firmata e registrata su blockchain",
                "transactionHash": tx_hash,
                "network": "ConsorzioReteUniversitaria"
            },
            "proof": {
                "type": "RsaSignature2023",
                "created": issuance_date,
                "proofPurpose": "assertionMethod",
                "verificationMethod": f"{self.did}#key-1",
                "jws": jws_signature
            }
        }

        filepath = os.path.join(CREDENTIAL_FOLDER, f"{student.username}_academic_credential.json")
        with open(filepath, "w") as f:
            json.dump(credential, f, indent=2)

        print(f"🎓 Academic Credential emessa e salvata: {filepath}")


    def collect_exam_data(self, file_path=EXAM):
        """
        Carica i dati degli esami da un file JSON.

        Args:
            file_path (str): Il percorso del file JSON da cui caricare i dati.

        Returns:
            list: Una lista di dizionari, ognuno rappresentante un esame.
                  Ritorna una lista vuota se il file non esiste o è vuoto/non valido.
        """
        if not os.path.exists(file_path):
            print(f"⚠️ Il file {file_path} non trovato. Restituisco lista esami vuota.")
            return []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if "exams" in data and isinstance(data["exams"], list):
                    print(f"✔️ Esami caricati con successo da {file_path}.")
                    return data["exams"]
                else:
                    print(
                        f"⚠️ Formato JSON non valido in {file_path}: 'exams' key non trovata o non è una lista. Restituisco lista vuota.")
                    return []
        except json.JSONDecodeError as e:
            print(f"❌ Errore durante il parsing del file JSON {file_path}: {e}. Restituisco lista vuota.")
            return []
        except Exception as e:
            print(
                f"❌ Si è verificato un errore inaspettato durante la lettura del file {file_path}: {e}. Restituisco lista vuota.")
            return []
