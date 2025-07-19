import os, json, base64, random, string
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from DatabaseManager import UserManager
from Blockchain import Blockchain
from RevocationRegistry import RevocationRegistry
import hashlib
from MerkleTree import hash_leaf, verify_merkle_proof, reconstruct_merkle_root
BASE_DIR = os.path.dirname(__file__)
KEYS_FOLDER = os.path.join(BASE_DIR, "keys")
DID_FOLDER = os.path.join(BASE_DIR, "DID")
CREDENTIAL_FOLDER = os.path.join(BASE_DIR, "credential")


class UniversitySalerno:
    """
    Rappresenta l'Università di Salerno, gestendo la generazione di chiavi,
    documenti DID, registrazione e autenticazione degli studenti,
    generazione di credenziali Erasmus e verifica di presentazioni selettive.
    """
    def __init__(self, did="did:web:unisa.it"):
        """
        Inizializza l'Università di Salerno.
        :param did: Decentralized Identifier dell'università.
        """
        self.did = did
        self.priv_path = os.path.join(KEYS_FOLDER, "university_priv.pem")
        self.pub_path = os.path.join(KEYS_FOLDER, "university_pub.pem")
        self.user_manager = UserManager(db_name="unisa_users")
        self.blockchain = Blockchain() # L'istanza della blockchain
        self.revocation_registry = RevocationRegistry()
        self._challenges = {}

        if not os.path.exists(self.priv_path):
            self._generate_keypair()
        self._update_did_document()

    def _generate_keypair(self):
        """
        Genera una coppia di chiavi RSA (privata e pubblica) e le salva in formato PEM.
        Le chiavi vengono generate solo se non esistono già.
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        os.makedirs(KEYS_FOLDER, exist_ok=True)

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
        """
        Aggiorna il documento DID dell'università con la chiave pubblica generata.
        Il documento DID viene salvato in un file JSON nella cartella DID.
        """
        with open(self.pub_path, "rb") as f:
            pub_pem = f.read().decode()

        filename = self.did.split(":")[-1].replace(".", "_") + "_did.json"
        path = os.path.join(DID_FOLDER, filename)

        os.makedirs(DID_FOLDER, exist_ok=True)
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
        """
        Risolve un DID cercando il suo documento DID corrispondente nel filesystem locale.
        :param did: Il DID da risolvere.
        :return: Il documento DID come dizionario.
        :raises Exception: Se il documento DID non viene trovato.
        """
        filename = did.split(":")[-1].replace(".", "_") + "_did.json"
        path = os.path.join(DID_FOLDER, filename)
        if not os.path.exists(path):
            raise Exception(f"DID document non trovato per {did}")
        with open(path, "r") as f:
            return json.load(f)

    # === INTERFACCIA PUBBLICA ===

    def register_student(self, user_id, username, password, first_name, last_name, public_key_pem):
        """
        Registra un nuovo studente nel DB interno dell'università, includendo la chiave pubblica.
        :param user_id: ID univoco dello studente.
        :param username: Username dello studente.
        :param password: Password dello studente.
        :param first_name: Nome dello studente.
        :param last_name: Cognome dello studente.
        :param public_key_pem: Chiave pubblica PEM dello studente.
        :return: True se la registrazione e l'aggiornamento avvengono con successo, False altrimenti.
        """
        success = self.user_manager.first_login(user_id, username, password, first_name, last_name)
        if success:
            return self.user_manager.update_user_did_and_public_key(user_id, "", public_key_pem)
        return False

    def authenticate_student(self, username, password):
        """
        Autentica uno studente con username e password.
        :param username: Nome utente dello studente.
        :param password: Password dello studente.
        :return: Dati dell'utente (incluso 'id', 'did', 'public_key_pem' se presenti) se l'autenticazione ha successo, altrimenti None.
        """
        return self.user_manager.authenticate_user(username, password)

    def assign_did_to_student(self, user_id, new_did, public_key_pem):
        """
        Assegna un nuovo DID e la chiave pubblica a uno studente esistente.
        :param user_id: ID dell'utente studente.
        :param new_did: Nuovo DID da assegnare.
        :param public_key_pem: Chiave pubblica PEM dello studente.
        :return: True se l'aggiornamento ha avuto successo, False altrimenti.
        """
        return self.user_manager.update_user_did_and_public_key(user_id, new_did, public_key_pem)

    def get_user_by_did(self, did):
        """
        Recupera un utente in base al suo DID dal DB interno dell'università.
        :param did: DID dell'utente.
        :return: Un oggetto utente se trovato, altrimenti None.
        """
        return self.user_manager.get_user_by_did(did)

    # === CHALLENGE-RESPONSE ===

    def generate_challenge(self, user_id: str) -> str:
        """
        Genera una challenge per uno studente autenticato tramite il suo user_id.
        Il DID dello studente viene recuperato dal DB dell'università.
        :param user_id: ID dell'utente studente (autenticato).
        :return: Una stringa che rappresenta la challenge generata, o None se il DID non è trovato.
        """
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
        """
        Verifica la risposta a una challenge generata per uno studente.
        Recupera il DID e la chiave pubblica dello studente dal DB dell'università
        usando il user_id autenticato.
        :param user_id: ID dell'utente studente (autenticato).
        :param signature_b64: Firma in base64 della challenge inviata dallo studente.
        :return: Risultato della verifica come dizionario con status e messaggio.
        """
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
            if student_did in self._challenges:
                del self._challenges[student_did]
            return {"status": "error", "message": "Firma non valida."}
        except Exception as e:
            if student_did in self._challenges:
                del self._challenges[student_did]
            return {"status": "error", "message": f"Errore durante la verifica: {e}"}

    def generate_erasmus_credential(self, student):
        """
        Genera una credenziale Erasmus per uno studente.
        La credenziale viene firmata e il suo hash registrato sulla blockchain.
        :param student: L'oggetto studente per cui generare la credenziale.
        """
        issuance_date = datetime.utcnow().isoformat() + "Z"
        expiration_date = (datetime.utcnow() + timedelta(days=365)).isoformat() + "Z"

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
