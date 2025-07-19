import os, json, base64, random, string
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

from DatabaseManager import UserManager
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


DID_PATH = os.path.join(DID_FOLDER, "rennes_did.json")  # This global is now overridden by dynamic path generation
EXAM = os.path.join(BASE_DIR, "exams.json")


class UniversityRennes:
    """
    Rappresenta l'Università di Rennes, gestendo la generazione di chiavi,
    documenti DID, la verifica di credenziali Erasmus, l'emissione di credenziali
    accademiche e la raccolta dei dati degli esami.
    """

    def __init__(self, did="did:web:rennes.it"):
        """
        Inizializza l'Università di Rennes.
        :param did: Decentralized Identifier dell'università.
        """
        self.did = did
        self.priv_path = os.path.join(KEYS_FOLDER, "rennes_priv.pem")
        self.pub_path = os.path.join(KEYS_FOLDER, "rennes_pub.pem")
        self.blockchain = Blockchain()
        self.revocation_registry = RevocationRegistry()
        self.user_manager = UserManager(db_name="rennes_users")
        self._challenges = {}

        if not os.path.exists(self.priv_path):
            self._generate_keypair()

        self._update_did_document()

    def _generate_keypair(self):
        """
        Genera una coppia di chiavi RSA (privata e pubblica) per l'università di Rennes
        e le salva in formato PEM.
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

    def _update_did_document(self):
        """
        Aggiorna il documento DID dell'università di Rennes con la chiave pubblica generata.
        Il documento DID viene salvato in un file JSON nella cartella DID.
        Il nome del file è generato dinamicamente per corrispondere alla logica di resolve_did.
        """
        with open(self.pub_path, "rb") as f:
            pub_pem = f.read().decode()

        # Generate filename dynamically to match resolve_did logic
        filename = self.did.split(":")[-1].replace(".", "_") + "_did.json"
        path = os.path.join(DID_FOLDER, filename)

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

        with open(path, "w") as f:  # Use the dynamically generated path
            json.dump(did_doc, f, indent=2)


    def authenticate_student(self, username, password):
        """
        Autentica uno studente con username e password.
        :param username: Nome utente dello studente.
        :param password: Password dello studente.
        :return: Dati dell'utente (incluso 'id', 'did', 'public_key_pem' se presenti) se l'autenticazione ha successo, altrimenti None.
        """
        return self.user_manager.authenticate_user(username, password)


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

    def assign_did_to_student(self, user_id, new_did, public_key_pem):
        """
        Assegna un nuovo DID e la chiave pubblica a uno studente esistente.
        :param user_id: ID dell'utente studente.
        :param new_did: Nuovo DID da assegnare.
        :param public_key_pem: Chiave pubblica PEM dello studente.
        :return: True se l'aggiornamento ha avuto successo, False altrimenti.
        """
        return self.user_manager.update_user_did_and_public_key(user_id, new_did, public_key_pem)

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

    def verify_erasmus_credential(self, credential: dict) -> bool:
        """
        Verifica una credenziale Erasmus emessa da un'altra università (es. Salerno).
        Controlla la firma della credenziale e il suo stato di revoca.
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

            # Ricostruisce la credenziale senza proof ed evidence per la verifica della firma
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
            print("✅ Firma della credenziale Erasmus valida.")

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

    def generate_academic_credential(self, student, exams: list):
        """
        Genera una credenziale accademica per uno studente, basata sui suoi esami.
        La credenziale include una Merkle Root degli esami firmata e registrata sulla blockchain.
        :param student: L'oggetto studente per cui generare la credenziale.
        :param exams: Una lista di dizionari, ognuno rappresentante un esame.
        """
        issuance_date = datetime.utcnow().isoformat() + "Z"
        credential_id = f"urn:uuid:{student.username}-academic-cred"

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

        # Salva la Merkle Root e il DID dello studente sulla blockchain
        tx_hash = self.blockchain.add_block({"merkleRoot": root, "student": student.did})

        # Costruisci la credenziale accademica
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
                "homeUniversity": "Universita' di Salerno",
                "exams": exams  # Gli esami completi sono inclusi qui
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
