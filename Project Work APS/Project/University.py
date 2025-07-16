import os, json, base64, random, string
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from Database import UserManager  # Assicurati che UserManager gestisca public_key_pem
from Blockchain import Blockchain
from RevocationRegistry import RevocationRegistry
import hashlib

BASE_DIR = os.path.dirname(__file__)
KEYS_FOLDER = os.path.join(BASE_DIR, "keys")
DID_FOLDER = os.path.join(BASE_DIR, "DID")
DID_PATH = os.path.join(DID_FOLDER, "university_did.json")
CREDENTIAL_FOLDER = os.path.join(BASE_DIR, "credential")


class University:
    def __init__(self, did="did:web:unisa.it"):
        self.did = did
        self.priv_path = os.path.join(KEYS_FOLDER, "university_priv.pem")
        self.pub_path = os.path.join(KEYS_FOLDER, "university_pub.pem")
        self.user_manager = UserManager()  # Istanzia il UserManager
        self.blockchain = Blockchain()
        self.revocation_registry = RevocationRegistry()
        self._challenges = {}  # Inizializza il dizionario dei challenge

        if not os.path.exists(self.priv_path):
            self._generate_keypair()
        self._update_did_document()

    def _generate_keypair(self):
        """
        Genera una coppia di chiavi RSA e le salva in formato PEM.
        Se le chiavi esistono già, non fa nulla.
        :return: None
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
        Aggiorna il documento DID dell'università con la chiave pubblica.
        Se il file non esiste, lo crea con la chiave pubblica generata.
        :return: None
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
        filename = did.split(":")[-1].replace(".", "_") + "_did.json"
        path = os.path.join(DID_FOLDER, filename)
        if not os.path.exists(path):
            raise Exception(f"DID document non trovato per {did}")
        with open(path, "r") as f:
            return json.load(f)

    # === INTERFACCIA PUBBLICA ===

    def register_student(self, user_id, username, password, first_name, last_name, public_key_pem):
        """
        Registra un nuovo studente nel DB dell'università, includendo la chiave pubblica.
        :param user_id: ID univoco dello studente.
        :param username: Username dello studente.
        :param password: Password dello studente.
        :param first_name: Nome dello studente.
        :param last_name: Cognome dello studente.
        :param public_key_pem: Chiave pubblica PEM dello studente.
        :return: True se la registrazione e l'aggiornamento avvengono con successo, False altrimenti.
        """
        # La registrazione iniziale con first_login non include DID e public_key_pem
        # Lo user_manager gestisce la creazione dell'utente base
        success = self.user_manager.first_login(user_id, username, password, first_name, last_name)
        if success:
            # Dopo la creazione dell'utente, aggiorniamo il suo DID e la sua chiave pubblica
            # (Il DID sarà assegnato dalla Student class nel main, per ora lo lasciamo vuoto o un placeholder)
            return self.user_manager.update_user_did_and_public_key(user_id, "", public_key_pem)  # DID vuoto per ora
        return False

    def authenticate_student(self, username, password):
        """
        Autentica uno studente con username e password.
        :param username: Nome utente dello studente
        :param password: Password dello studente
        :return: Dati dell'utente (incluso 'id', 'did', 'public_key_pem' se presenti) se l'autenticazione ha successo, altrimenti None.
        """
        return self.user_manager.authenticate_user(username, password)

    def assign_did_to_student(self, user_id, new_did, public_key_pem):  # Aggiunto public_key_pem
        """
        Assegna un nuovo DID e la chiave pubblica a uno studente esistente.
        :param user_id: ID dell'utente studente
        :param new_did: Nuovo DID da assegnare
        :param public_key_pem: Chiave pubblica PEM dello studente
        :return: True se l'aggiornamento ha avuto successo, False altrimenti
        """
        # Questo metodo ora chiamerà il manager per aggiornare sia DID che chiave pubblica
        return self.user_manager.update_user_did_and_public_key(user_id, new_did, public_key_pem)

    def get_user_by_did(self, did):
        """
        Recupera un utente in base al suo DID.
        :param did: DID dell'utente
        :return: Un oggetto utente se trovato, altrimenti None
        """
        return self.user_manager.get_user_by_did(did)

    # === CHALLENGE-RESPONSE ===

    def generate_challenge(self, user_id: str) -> str:
        """
        Genera una challenge per uno studente autenticato tramite il suo user_id.
        Il DID dello studente viene recuperato dal DB dell'università.
        :param user_id: ID dell'utente studente (autenticato)
        :return: Una stringa che rappresenta la challenge generata, o None se il DID non è trovato.
        """
        user_data = self.user_manager.get_user_by_id(user_id)
        if not user_data or not user_data.get("did"):
            print(f"Errore in generate_challenge: DID non trovato per l'utente con ID {user_id}")
            return None  # O sollevare un'eccezione

        student_did = user_data["did"]  # Recupera il DID dal DB dell'università
        challenge_value = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        self._challenges[student_did] = {  # Il challenge è associato al DID
            "value": challenge_value,
            "expires_at": datetime.now() + timedelta(minutes=5)
        }
        return challenge_value

    def verify_challenge_response(self, user_id: str, signature_b64: str):
        """
        Verifica la risposta a una challenge generata per uno studente.
        Recupera il DID e la chiave pubblica dello studente dal DB dell'università
        usando il user_id autenticato.

        :param user_id: ID dell'utente studente (autenticato)
        :param signature_b64: Firma in base64 della challenge inviata dallo studente
        :return: Risultato della verifica come dizionario con status e messaggio
        """
        # 1. Recupera i dati dello studente dal DB dell'università usando l'user_id
        user_data = self.user_manager.get_user_by_id(user_id)
        if not user_data:
            return {"status": "error", "message": f"Utente con ID {user_id} non trovato nel DB dell'università."}

        student_did = user_data.get("did")
        if not student_did:
            return {"status": "error", "message": f"DID non assegnato all'utente con ID {user_id} nel DB."}

        student_public_key_pem = user_data.get("public_key_pem")
        if not student_public_key_pem:
            return {"status": "error", "message": f"Chiave pubblica non trovata per il DID: {student_did} nel DB."}

        # 2. Recupera il challenge associato a questo DID
        challenge_data = self._challenges.get(student_did)
        if not challenge_data:
            return {"status": "error", "message": "Nessun challenge attivo trovato per questo DID."}

        # 3. Controlla la scadenza del challenge
        if datetime.now() > challenge_data["expires_at"]:
            del self._challenges[student_did]  # Rimuovi il challenge scaduto
            return {"status": "error", "message": "Challenge scaduto."}

        # 4. Verifica la firma
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
            # Se la verifica ha successo, il challenge è stato usato e va rimosso
            del self._challenges[student_did]
            return {"status": "ok", "message": "Challenge verificato con successo."}
        except InvalidSignature:
            # Se la firma non è valida, il challenge è comunque "usato" (fallito) e va rimosso
            if student_did in self._challenges:
                del self._challenges[student_did]
            return {"status": "error", "message": "Firma non valida."}
        except Exception as e:
            # In caso di altri errori, rimuovi il challenge
            if student_did in self._challenges:
                del self._challenges[student_did]
            return {"status": "error", "message": f"Errore durante la verifica: {e}"}

    def generate_erasmus_credential(self, student):
        """
        Genera una credenziale Erasmus per uno studente.
        La firma è calcolata solo sui dati principali della credenziale (escludendo proof e evidence).
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
        # Firma della credenziale (senza proof/evidence)
        priv_key = serialization.load_pem_private_key(open(self.priv_path, "rb").read(), password=None)
        signature = base64.b64encode(priv_key.sign(
            json.dumps(credential_data, sort_keys=True).encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )).decode()

        # Aggiunta della proof
        credential_data["proof"] = {
            "type": "RsaSignature2023",
            "created": issuance_date,
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"{self.did}#key-1",
            "jws": signature
        }

        # Calcolo hash della VC con proof (senza evidence)
        vc_hash = hashlib.sha256(json.dumps(credential_data, sort_keys=True).encode()).hexdigest()

        # Aggiungi l'hash alla blockchain
        tx_hash = self.blockchain.add_block({
            "credentialHash": vc_hash,
            "type": "EligibilityCredential",
            "studentDID": student.did,
            "issuer": self.did
        })

        # Aggiungo evidence
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