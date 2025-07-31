import os, json, base64
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from BaseUniversity import BaseUniversity
from DatabaseManager import UserManager
from Blockchain import Blockchain
from RevocationRegistry import RevocationRegistry
from MerkleTree import merkle_root, hash_leaf_with_salt, generate_deterministic_salt

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

    def verify_erasmus_credential(self, credential: dict, student) -> bool:
        """
        Verifica una credenziale Erasmus emessa da un'altra università (es. Salerno).
        Controlla la firma della credenziale, il suo stato di revoca, la validità temporale
        e che il DID dello studente corrisponda a quello nella credenziale.
        :param credential: La credenziale Erasmus da verificare.
        :param student: Oggetto studente con attributo 'did' da confrontare.
        :return: True se la credenziale è valida e non revocata, False altrimenti.
        """
        issuer_did = credential.get("issuer")
        proof = credential.get("proof", {})
        jws = proof.get("jws")
        verification_method = proof.get("verificationMethod")
        status = credential.get("credentialStatus", {})

        # Controllo che il DID dello studente corrisponda a quello nella credenziale
        credential_subject = credential.get("credentialSubject", {})
        credential_student_did = credential_subject.get("id")
        if credential_student_did != student.did:
            print(
                f"❌ DID dello studente non corrisponde: credenziale {credential_student_did} vs studente {student.did}")
            return False

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

            # --- Inizio del controllo di validità temporale ---
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

    def generate_academic_credential(self, student, exams: list):
        """
        Genera una credenziale accademica per uno studente.
        """
        filepath = os.path.join(student.get_wallet_path(), "credentials",
                                f"{student.username}_academic_credential.json")

        if os.path.exists(filepath):
            print(f"⚠️ Credenziale Erasmus per lo studente {student.username} esiste già. Saltando la generazione.")
            return None

        issuance_date = datetime.now(timezone.utc).isoformat() + "Z"
        expiration_date = (datetime.now(timezone.utc) + timedelta(days=730)).isoformat() + "Z"
        credential_id = student.user_id
        revocation_namespace = "rennes"
        category_id = "Academic2025"
        revocation_list_id = self.revocation_registry.generate_list_id(revocation_namespace, category_id)
        revocation_key = self.revocation_registry.generate_revocation_key(credential_id)

        credential_status = {
            "id": f"https://consorzio-univ.it/creds/{student.username}-academic-status",
            "type": "ConsortiumRevocationRegistry2024",
            "registry": "0xRegistryAddresRennes",
            "namespace": revocation_namespace,
            "revocationList": revocation_list_id,
            "revocationKey": revocation_key
        }

        # Esami dict
        exams_dict = {}
        for exam in exams:
            exam_id = exam.get("examId")
            if "examId" not in exam:
                exam["examId"] = exam_id
            exams_dict[exam_id] = {k: v for k, v in exam.items() if k != "examId"}

        leaves = []

        # Esami ordinati
        for exam_id, exam_data in sorted(exams_dict.items()):
            for field, value in sorted(exam_data.items()):
                salt = generate_deterministic_salt(exam_id, field, value, student)
                leaf_hash = hash_leaf_with_salt(exam_id, field, value, salt)
                leaves.append(leaf_hash)

        # CredentialStatus ordinato
        for field, value in sorted(credential_status.items()):
            salt = generate_deterministic_salt("credentialStatus", field, value, student)
            leaf_hash = hash_leaf_with_salt("credentialStatus", field, value, salt)
            leaves.append(leaf_hash)

        root = merkle_root(leaves)

        priv_key = serialization.load_pem_private_key(open(self.priv_path, "rb").read(), password=None)
        jws_signature = base64.b64encode(priv_key.sign(
            root.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )).decode()

        tx_hash = self.blockchain.add_block({
            "merkleRoot": root,
            "type": "AcademicCredential",
            "issuer": self.did
        })

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
                "exams": exams_dict,
                "credentialStatus": credential_status
            },
            "credentialStatus": credential_status,
            "evidence": {
                "type": "BlockchainRecord",
                "description": "Merkle Root registrata su blockchain",
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

        with open(filepath, "w") as f:
            json.dump(credential, f, indent=2)

        print(f"🎓 Academic Credential emessa e salvata: {filepath}")
        return credential
