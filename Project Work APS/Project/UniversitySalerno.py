from BaseUniversity import BaseUniversity
from DatabaseManager import UserManager
from Blockchain import Blockchain
from RevocationRegistry import RevocationRegistry
import os, json, base64
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import hashlib
from MerkleTree import hash_leaf, verify_merkle_proof, reconstruct_merkle_root

BASE_DIR = os.path.dirname(__file__)
UNISA_DIR = os.path.join(BASE_DIR, "unisa")


class UniversitySalerno(BaseUniversity):
    def __init__(self):
        super().__init__(
            did="did:web:unisa.it",
            priv_key_filename="unisa_priv.pem",
            pub_key_filename="unisa_pub.pem",
            db_name="unisa_users",
            keys_folder=os.path.join(UNISA_DIR, "keys"),
            did_folder=os.path.join(UNISA_DIR, "did"),
            trusted_did_folder = os.path.join(UNISA_DIR, "trusted_dids"),
            user_manager_cls=UserManager,
            blockchain_cls=Blockchain,
            revocation_registry_cls=RevocationRegistry,
            folder = UNISA_DIR
        )

    def generate_erasmus_credential(self, student):
        """
        Genera una credenziale Erasmus per uno studente.
        La credenziale viene firmata e il suo hash registrato sulla blockchain.
        Controlla se la credenziale esiste già prima di generarne una nuova.
        :param student: L'oggetto studente per cui generare la credenziale.
        """
        filepath = os.path.join(student.get_wallet_path(), "credentials", f"{student.username}_erasmus_credential.json")

        if os.path.exists(filepath):
            print(f"⚠️ Credenziale Erasmus per lo studente {student.username} esiste già. Saltando la generazione.")
            return None

        issuance_date = datetime.now(timezone.utc).isoformat() + "Z"
        expiration_date = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat() + "Z"

        credential_id = student.user_id
        revocation_namespace = "unisa"
        category_id = "Erasmus2025"
        revocation_list_id = self.revocation_registry.generate_list_id(revocation_namespace, category_id)
        revocation_key = self.revocation_registry.generate_revocation_key(credential_id)

        credential_data = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://consorzio-universita.example/credentials/v1"
            ],
            "type": ["VerifiableCredential", "EligibilityCredential"],
            "issuer": self.did,
            "issuanceDate": issuance_date,
            "expirationDate": expiration_date,
            "credentialSubject": {
                "id": student.did,
                "givenName": student.first_name or "N/A",
                "familyName": student.last_name or "N/A",
                "homeUniversity": "Universita di Salerno",
                "erasmusStatus": "Eligible",
                "destinationUniversity": "Universita de Rennes",
                "academicYear": "2025/2026"
            },
            "credentialStatus": {
                "id": f"https://unisa.it/status/{revocation_list_id}",
                "type": "ConsortiumRevocationRegistry2024",
                "registry": "0xRegistryAddressUnisa",
                "namespace": revocation_namespace,
                "revocationList": revocation_list_id,
                "revocationKey": revocation_key
            }
        }

        vc_hash = hashlib.sha256(json.dumps(credential_data, sort_keys=True).encode()).hexdigest()

        tx_hash = self.blockchain.add_block({
            "credentialHash": vc_hash,
            "type": "EligibilityCredential",
            "studentDID": student.did,
            "issuer": self.did
        })

        credential_data["evidence"] = {
            "type": "BlockchainRecord",
            "description": "Hash della credenziale ancorato su blockchain",
            "transactionHash": tx_hash,
            "network": "ConsorzioReteUniversitaria"
        }

        priv_key = serialization.load_pem_private_key(open(self.priv_path, "rb").read(), password=None)
        signature = base64.b64encode(priv_key.sign(
            json.dumps(credential_data, sort_keys=True).encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )).decode()

        credential_data["proof"] = {
            "type": "RsaSignature2023",
            "created": issuance_date,
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"{self.did}#key-1",
            "jws": signature
        }

        self.revocation_registry.create_revocation_entry(
            namespace=revocation_namespace,
            list_id=revocation_list_id,
            revocation_key=revocation_key
        )

        with open(filepath, "w") as f:
            json.dump(credential_data, f, indent=2)

        print(f"✅ Credenziale Erasmus salvata in: {filepath}")

    def verify_selective_presentation(self, presentation: dict, student) -> bool:
        """
        Verifica una presentazione selettiva includendo:
        - Firma della VP
        - Consistenza dei DID tra student, VP e VC
        - Scadenza, revoca, Merkle proofs e Merkle root.
        """
        try:
            # 1. DID atteso dallo studente
            expected_student_did = student.did
            if not expected_student_did:
                print("❌ DID dello studente mancante nell'oggetto student.")
                return False

            # 2. Estrazione DID dalla VP e dalla VC
            vp_holder_did = presentation.get("holder")
            vc = presentation.get("verifiableCredential")
            vc_holder_did = vc.get("credentialSubject", {}).get("id")

            # 3. Verifica coerenza tra tutti i DID
            if vp_holder_did != expected_student_did:
                print(f"❌ DID mismatch: VP holder {vp_holder_did} ≠ Student {expected_student_did}")
                return False
            if vc_holder_did and vc_holder_did != expected_student_did:
                print(f"❌ DID mismatch: VC subject {vc_holder_did} ≠ Student {expected_student_did}")
                return False
            print("✅ DID coerenti tra student, VP e VC.")

            # 4. Verifica firma della VP
            vp_proof = presentation["proof"]
            jws = vp_proof["jws"]
            verification_method = vp_proof["verificationMethod"]

            did_doc = self.resolve_did_student(vp_holder_did)
            pub_key_pem = None
            for vm in did_doc.get("verificationMethod", []):
                if vm["id"] == verification_method:
                    pub_key_pem = vm["publicKeyPem"]
                    break

            if not pub_key_pem:
                print("❌ verificationMethod dello studente non trovato.")
                return False

            public_key = serialization.load_pem_public_key(pub_key_pem.encode())
            unsigned_presentation = presentation.copy()
            unsigned_presentation.pop("proof", None)
            payload = json.dumps(unsigned_presentation, sort_keys=True).encode()

            public_key.verify(
                base64.b64decode(jws),
                payload,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            print("✅ Firma della presentazione valida.")

            # 5. Verifica scadenza credenziale
            expiration_str = vc.get("expirationDate")
            if expiration_str:
                expiration_date = datetime.fromisoformat(expiration_str.rstrip("Z"))
                now = datetime.now(tz=timezone.utc)
                if expiration_date.tzinfo is None:
                    expiration_date = expiration_date.replace(tzinfo=timezone.utc)
                if now > expiration_date:
                    print("❌ La credenziale è scaduta.")
                    return False
                print("✅ Credenziale valida temporalmente.")
            else:
                print("ℹ️ Nessuna data di scadenza specificata.")

            # 6. Verifica Merkle Root on-chain
            tx_hash = vc["evidence"]["transactionHash"]
            on_chain_root = self.blockchain.get_merkle_root(tx_hash)
            if not on_chain_root:
                print("❌ Merkle Root non trovata on-chain.")
                return False
            print(f"✅ Merkle Root on-chain: {on_chain_root}")

            # 7. Verifica stato di revoca
            status = vc["credentialStatus"]
            is_revoked = self.revocation_registry.is_revoked(
                namespace=status["namespace"],
                list_id=status["revocationList"],
                revocation_key=status["revocationKey"]
            )
            if is_revoked:
                print("❌ La credenziale è stata revocata.")
                return False
            print("✅ Credenziale non revocata.")

            # 8. Verifica Merkle Proofs dei campi rivelati
            revealed = vc["credentialSubject"]["proofs"]
            for exam_id, fields in revealed.items():
                for field, data in fields.items():
                    leaf_hash = (
                        hash_leaf({"examId": exam_id, "field": field, "value": data["value"]})
                        if "value" in data else data.get("leafHash")
                    )
                    if not leaf_hash or not verify_merkle_proof(leaf_hash, data["proof"], on_chain_root):
                        print(f"❌ Merkle proof non valida per {exam_id}.{field}")
                        return False
            print("✅ Merkle proofs verificate.")

            # 9. Verifica ricostruzione Merkle Root
            reconstructed = reconstruct_merkle_root(revealed)
            if reconstructed != on_chain_root:
                print("❌ Root ricostruita ≠ root on-chain.")
                return False
            print("✅ Merkle Root ricostruita correttamente.")

            print("🎓 Verifica completata. Presentazione valida.")
            return True

        except InvalidSignature:
            print("❌ Firma della presentazione non valida.")
            return False
        except Exception as e:
            print(f"❌ Errore durante la verifica: {e}")
            return False
