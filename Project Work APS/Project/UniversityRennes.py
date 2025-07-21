import os, json, base64
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from BaseUniversity import BaseUniversity
from DatabaseManager import UserManager
from Blockchain import Blockchain
from RevocationRegistry import RevocationRegistry
from MerkleTree import hash_leaf, merkle_root

BASE_DIR = os.path.dirname(__file__)
RENNES_DIR = os.path.join(BASE_DIR, "rennes")
EXAM = os.path.join(BASE_DIR, "exams.json")


class UniversityRennes(BaseUniversity):
    def __init__(self):
        super().__init__(
            did="did:web:rennes.it",
            priv_key_filename="rennes_priv.pem",
            pub_key_filename="rennes_pub.pem",
            db_name="rennes_users",
            keys_folder=os.path.join(RENNES_DIR, "keys"),
            did_folder=os.path.join(RENNES_DIR, "did"),
            trusted_did_folder = os.path.join(RENNES_DIR, "trusted_dids"),
            user_manager_cls=UserManager,
            blockchain_cls=Blockchain,
            revocation_registry_cls=RevocationRegistry,
            folder=RENNES_DIR
        )

    def verify_erasmus_credential(self, credential: dict) -> bool:
        """
        Verifica una credenziale Erasmus emessa da un'altra università (es. Salerno).
        Controlla la firma della credenziale, il suo stato di revoca e la validità temporale.
        :param credential: La credenziale Erasmus da verificare.
        :return: True se la credenziale è valida e non revocata, False altrimenti.
        """
        issuer_did = credential.get("issuer")
        proof = credential.get("proof", {})
        jws = proof.get("jws")
        verification_method = proof.get("verificationMethod")
        status = credential.get("credentialStatus", {})

        # 1. Verifica che il DID dell'emittente sia trusted
        if issuer_did not in self.get_trusted_dids():
            print("❌ DID emittente non è nella lista trusted.")
            return False

        try:
            # 2. Verifica della firma della credenziale
            did_doc = self.resolve_did(issuer_did)
            pub_key_pem = None
            for vm in did_doc.get("verificationMethod", []):
                if vm["id"] == verification_method:
                    pub_key_pem = vm["publicKeyPem"]
                    break

            if not pub_key_pem:
                print("❌ verificationMethod non trovato nel DID dell'emittente.")
                return False

            public_key = serialization.load_pem_public_key(pub_key_pem.encode())

            # Ricostruisce la credenziale senza proof per la verifica della firma
            unsigned_cred = credential.copy()
            unsigned_cred.pop("proof", None)
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
            print("✅ Firma della credenziale Erasmus valida.")

            # --- Inizio del controllo di validità temporale (aggiunto) ---
            expiration_str = credential.get("expirationDate")
            if expiration_str:
                try:
                    expiration_date = datetime.fromisoformat(expiration_str)
                except ValueError:
                    try:
                        if expiration_str.endswith('Z'):
                            expiration_date = datetime.fromisoformat(expiration_str[:-1])
                        else:
                            raise
                    except ValueError:
                        print(f"❌ Formato data di scadenza non valido: {expiration_str}. Processo interrotto.")
                        return False

                now = datetime.now(tz=timezone.utc)
                if expiration_date.tzinfo is None:
                    expiration_date = expiration_date.replace(tzinfo=timezone.utc)

                if now > expiration_date:
                    print("❌ La credenziale è scaduta. Processo interrotto.")
                    return False
                else:
                    print("✅ La credenziale è ancora valida temporalmente.")
            else:
                print("Nessuna data di scadenza specificata per questa credenziale.")
            # --- Fine del controllo di validità temporale ---

            # 3. Verifica stato di revoca
            namespace = status.get("namespace")
            revocation_list = status.get("revocationList")
            revocation_key = status.get("revocationKey")

            is_revoked = self.revocation_registry.is_revoked(namespace, revocation_list, revocation_key)
            if is_revoked is None:
                print("⚠️ Stato di revoca non trovato. Credenziale potenzialmente non valida.")
                return False
            elif is_revoked:
                print("❌ La credenziale è stata revocata.")
                return False
            else:
                print("✅ Credenziale NON revocata.")
                return True

        except InvalidSignature:
            print("❌ Firma della credenziale Erasmus non valida.")
            return False
        except Exception as e:
            print(f"❌ Errore nella verifica della credenziale Erasmus: {e}")
            return False

    def get_trusted_dids(self):
        """
        Restituisce una lista di DID di emittenti considerati affidabili da Rennes.
        :return: Lista di stringhe DID.
        """
        return ["did:web:unisa.it"]


    def generate_academic_credential(self, student, exams: list):
        """
        Genera una credenziale accademica per uno studente, basata sui suoi esami.
        La credenziale include una Merkle Root degli esami firmata e registrata sulla blockchain.
        :param student: L'oggetto studente per cui generare la credenziale.
        :param exams: Una lista di dizionari, ognuno rappresentante un esame.
        """
        filepath = os.path.join(student.get_wallet_path(), "credentials", f"{student.username}_academic_credential.json")

        if os.path.exists(filepath):
            print(f"⚠️ Credenziale Erasmus per lo studente {student.username} esiste già. Saltando la generazione.")
            return None

        issuance_date = datetime.now(timezone.utc).isoformat() + "Z"
        expiration_date = (datetime.now(timezone.utc) + timedelta(days=730)).isoformat() + "Z"
        credential_id = f"urn:uuid:{student.username}-academic-cred"
        revocation_namespace = "rennes"
        category_id = "anno2025"
        revocation_list_id = self.revocation_registry.generate_list_id(revocation_namespace, category_id)
        revocation_key = self.revocation_registry.generate_revocation_key(credential_id)
        # Genera foglie Merkle a livello di campo per ogni esame
        leaves = []
        for exam in exams:
            for field in ["name", "grade", "credits", "date"]:
                if field in exam:
                    leaf_obj = {"examId": exam["examId"], "field": field, "value": exam[field]}
                    h = hash_leaf(leaf_obj)
                    leaves.append(h)

        # Calcola la Merkle Root da tutte le foglie degli esami
        root = merkle_root(leaves)

        # Firma la Merkle Root con la chiave privata di Rennes
        priv_key = serialization.load_pem_private_key(open(self.priv_path, "rb").read(), password=None)
        jws_signature = base64.b64encode(priv_key.sign(
            root.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )).decode()
        # Registra la Merkle Root sulla blockchain
        tx_hash = self.blockchain.add_block({
                    "merkleRoot": root,
                    "type": "AcademicCredential",
                    "studentDID": student.did,
                    "issuer": self.did
                })
        # Costruisci la credenziale accademica
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://consorzio-universita.example/credentials/v1"
            ],
            "type": ["VerifiableCredential", "AcademicCredential"],
            "issuer": self.did,
            "issuanceDate": issuance_date,
            "expirationDate": expiration_date,
            "credentialSubject": {
                "id": student.did,
                "givenName": student.first_name or "N/A",
                "familyName": student.last_name or "N/A",
                "homeUniversity": "Universita' di Salerno",
                "exams": exams
            },
            "credentialStatus": {
                "id": f"https://consorzio-univ.it/creds/{student.username}-academic-status",
                "type": "ConsortiumRevocationRegistry2024",
                "registry": "0xRegistryAddresRennes",
                "namespace": revocation_namespace,
                "revocationList": revocation_list_id,
                "revocationKey": revocation_key
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

        self.revocation_registry.create_revocation_entry(
            namespace=revocation_namespace,
            list_id=revocation_list_id,
            revocation_key=revocation_key
        )
        
        filepath = os.path.join(student.get_wallet_path(), "credentials", f"{student.username}_academic_credential.json")
        with open(filepath, "w") as f:
            json.dump(credential, f, indent=2)

        print(f"🎓 Academic Credential emessa e salvata: {filepath}")

    def collect_exam_data(self, file_path=EXAM):
        """
        Carica i dati degli esami da un file JSON.
        :param file_path (str): Il percorso del file JSON da cui caricare i dati.
        :return: Una lista di dizionari, ognuno rappresentante un esame.
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
