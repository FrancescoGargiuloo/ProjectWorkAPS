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
CREDENTIAL_FOLDER = os.path.join(BASE_DIR, "credential")


class UniversitySalerno(BaseUniversity):
    def __init__(self):
        super().__init__(
            did="did:web:unisa.it",
            priv_key_filename="university_priv.pem",
            pub_key_filename="university_pub.pem",
            db_name="unisa_users",
            keys_folder=os.path.join(BASE_DIR, "keys"),
            did_folder=os.path.join(BASE_DIR, "DID"),
            user_manager_cls=UserManager,
            blockchain_cls=Blockchain,
            revocation_registry_cls=RevocationRegistry
        )


    def generate_erasmus_credential(self, student):
        """
        Genera una credenziale Erasmus per uno studente.
        La credenziale viene firmata e il suo hash registrato sulla blockchain.
        :param student: L'oggetto studente per cui generare la credenziale.
        """
        issuance_date = datetime.now(timezone.utc).isoformat() + "Z"
        expiration_date = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat() + "Z"

        credential_id = f"urn:uuid:{student.username}-erasmus-cred"
        revocation_namespace = "unisa"
        category_id = "erasmus2025"
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
        self.revocation_registry.create_revocation_entry(
            namespace=revocation_namespace,
            list_id=revocation_list_id,
            revocation_key=revocation_key
        )

        filename = f"{student.username}_erasmus_credential.json"
        filepath = os.path.join(CREDENTIAL_FOLDER, filename)
        with open(filepath, "w") as f:
            json.dump(credential_data, f, indent=2)

        print(f"Credenziale Erasmus salvata")

    def verify_selective_presentation(self, presentation: dict) -> bool:
        """
        Verifica una presentazione selettiva, inclusa la firma della presentazione,
        lo stato di revoca della credenziale e le Merkle Proofs per i campi rivelati.
        Nota: Questa implementazione assume che la presentazione contenga una VC
        con un campo 'proofs' all'interno di 'credentialSubject' per i dati rivelati.
        :param presentation: La presentazione verificabile da verificare.
        :return: True se la presentazione è valida, False altrimenti.
        """
        try:
            # === MODIFICA QUI: Ricarica la blockchain per avere lo stato più aggiornato ===
            self.blockchain = Blockchain() # Reinicializza per ricaricare da shared_blockchain.json
            print("🔄 Blockchain ricaricata prima della verifica della presentazione.")
            # =========================================================================

            # 1. Verifica firma della Verifiable Presentation
            student_did = presentation["holder"]
            vp_proof = presentation["proof"]
            jws = vp_proof["jws"]
            verification_method = vp_proof["verificationMethod"]

            did_doc = self.resolve_did(student_did)
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
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("✅ Firma della presentazione valida.")

            # 4. Estrai la VC dalla presentazione
            vc = presentation["verifiableCredential"]

            # 5. Recupera la Merkle Root dalla blockchain
            tx_hash = vc["evidence"]["transactionHash"]
            on_chain_root = self.blockchain.get_merkle_root(tx_hash)
            if not on_chain_root:
                print("❌ Merkle Root non trovata sulla blockchain.")
                return False
            print(f"✅ Merkle Root recuperata: {on_chain_root}")

            # 6. Verifica lo stato di revoca
            status = vc["credentialStatus"]
            is_revoked = self.revocation_registry.is_revoked(
                namespace=status["namespace"],
                list_id=status["revocationList"],
                revocation_key=status["revocationKey"]
            )
            if is_revoked:
                print("❌ La credenziale è stata revocata.")
                return False
            print("✅ Credenziale NON revocata.")

            # 7. Verifica delle Merkle Proof fornite per ogni campo rivelato
            revealed = vc["credentialSubject"]["proofs"]
            for exam_id, fields in revealed.items():
                for field, data in fields.items():
                    if "value" in data:
                        leaf_obj = {"examId": exam_id, "field": field, "value": data["value"]}
                        leaf_hash = hash_leaf(leaf_obj)
                    elif "leafHash" in data:
                        leaf_hash = data["leafHash"]
                    else:
                        print(f"❌ Mancano 'value' e 'leafHash' per {exam_id}.{field}")
                        return False

                    proof = data["proof"]
                    if not verify_merkle_proof(leaf_hash, proof, on_chain_root):
                        print(f"❌ Merkle proof non valida per {exam_id}.{field}")
                        return False

            print("✅ Tutte le Merkle proof sono valide.")

            # 8. Ricostruzione della Merkle Root completa e confronto con on-chain
            reconstructed = reconstruct_merkle_root(revealed)
            if reconstructed != on_chain_root:
                print("❌ La Merkle Root ricostruita non coincide con quella on-chain.")
                return False
            print("✅ Merkle Root ricostruita corrisponde alla root on-chain.")

            # 9. Tutto ok
            print("🎓 Verifica completata. Presentazione valida.")
            return True

        except InvalidSignature:
            print("❌ Firma della presentazione non valida.")
            return False
        except Exception as e:
            print(f"❌ Errore durante la verifica: {e}")
            return False
