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

        if issuer_did not in self.get_trusted_dids():
            print("❌ DID emittente non trusted.")
            return False

        try:
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

            # Rimuovi proof ed evidence prima di verificare
            unsigned_credential = credential.copy()
            unsigned_credential.pop("proof", None)
            unsigned_credential.pop("evidence", None)

            payload = json.dumps(unsigned_credential, sort_keys=True).encode()

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
            return True

        except InvalidSignature:
            print("❌ Firma non valida.")
            return False
        except Exception as e:
            print(f"❌ Errore nella verifica: {e}")
            return False

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

        leaf_hashes = [hash_leaf(exam) for exam in exams]
        root = merkle_root(leaf_hashes)

        priv_key = serialization.load_pem_private_key(open(self.priv_path, "rb").read(), password=None)
        jws_signature = base64.b64encode(priv_key.sign(
            root.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )).decode()

        tx_hash = self.blockchain.add_block({"merkleRoot": root, "student": student.did})

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
                "registry": "0xABCDEF1234567890ABCDEF1234567890ABCDEF12",
                "namespace": "0x9876543210FEDCBA09876543210FEDCBA0987654",
                "revocationList": "0x456789ABCDEF456789ABCDEF456789ABCDEF1234",
                "revocationKey": hashlib.sha256(credential_id.encode()).hexdigest()
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
