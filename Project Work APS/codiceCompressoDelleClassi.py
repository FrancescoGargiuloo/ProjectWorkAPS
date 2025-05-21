from datetime import datetime, timedelta
import json
import uuid
import base64
import random
import string
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature




class UniversityIssuer:
    """Gestisce l'emissione e la verifica di credenziali verificabili"""

    def __init__(self, issuer_did, key_path=None):
        """
        Inizializza l'issuer con il suo DID

        Args:
            issuer_did (str): Il DID dell'emittente (l'università)
            key_path (str, optional): Percorso al file .pem della chiave privata
        """
        self.issuer_did = issuer_did
        self._private_key_path = key_path or UNIVERSITY_PRIVATE_KEY_PATH

        # Se il file della chiave privata non esiste, ne generiamo uno nuovo
        if not os.path.exists(self._private_key_path):
            self._generate_and_save_key()

        self.challenges = {}  # Dizionario per tenere traccia dei challenge generati
        self.db_manager = DatabaseManager()

    def _generate_and_save_key(self):
        """Genera una chiave privata RSA e la salva in un file .pem"""
        # Genera una nuova chiave RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Serializza la chiave privata in formato PEM
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # In produzione usare BestAvailableEncryption
        )

        # Crea la directory se non esiste
        os.makedirs(os.path.dirname(self._private_key_path), exist_ok=True)

        # Salva la chiave privata in un file
        with open(self._private_key_path, 'wb') as f:
            f.write(pem)

        print(f"Chiave privata dell'università generata e salvata in: {self._private_key_path}")

    def _load_private_key(self):
        """Carica la chiave privata dal file .pem"""
        try:
            with open(self._private_key_path, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None  # In produzione utilizzare una password
                )
            return private_key
        except Exception as e:
            print(f"Errore nel caricamento della chiave privata: {e}")
            return None

    def _sign(self, data):
        """
        Firma digitalmente i dati utilizzando la chiave privata dell'università

        Args:
            data (str): I dati da firmare

        Returns:
            str: Firma digitale in formato base64
        """
        # Carica la chiave privata
        private_key = self._load_private_key()
        if not private_key:
            raise Exception("Impossibile caricare la chiave privata dell'università")

        # Firma i dati con RSA
        signature = private_key.sign(
            str(data).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Restituisce la firma in formato base64
        return base64.b64encode(signature).decode()

    def get_public_key_pem(self):
        """
        Ottiene la chiave pubblica in formato PEM

        Returns:
            str: Chiave pubblica in formato PEM
        """
        private_key = self._load_private_key()
        if not private_key:
            raise Exception("Impossibile caricare la chiave privata dell'università")

        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return pem.decode()

    def verify_signature(self, student_public_key_pem, data, signature):
        """
        Verifica una firma utilizzando la chiave pubblica dello studente

        Args:
            student_public_key_pem (str): Chiave pubblica dello studente in formato PEM
            data (str): I dati originali
            signature (str): La firma da verificare in formato base64

        Returns:
            bool: True se la firma è valida, False altrimenti
        """
        try:
            # Carica la chiave pubblica dello studente
            public_key = serialization.load_pem_public_key(
                student_public_key_pem.encode()
            )

            # Verifica la firma
            public_key.verify(
                base64.b64decode(signature),
                str(data).encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Se non viene lanciata un'eccezione, la firma è valida
            return True
        except InvalidSignature:
            # La firma non è valida
            return False
        except Exception as e:
            print(f"Errore nella verifica della firma: {e}")
            return False

    def generate_challenge(self, student_did):
        """
        Genera un challenge casuale per il processo di autenticazione

        Args:
            student_did (str): Il DID dello studente

        Returns:
            str: Il challenge generato
        """
        # Genera un nonce casuale come challenge
        challenge = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

        # Memorizza il challenge associato al DID dello studente
        self.challenges[student_did] = {
            "value": challenge,
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(minutes=5)).isoformat()
        }

        return challenge

    def verify_challenge_response(self, student_did, signature, student_public_key_pem=None):
        """
        Verifica la firma del challenge fornito dallo studente

        Args:
            student_did (str): Il DID dello studente
            signature (str): La firma del challenge
            student_public_key_pem (str, optional): Chiave pubblica dello studente in formato PEM

        Returns:
            dict: Risultato della verifica
        """
        # Verifica che esista un challenge per lo studente
        if student_did not in self.challenges:
            return {"status": "error", "message": "Nessun challenge trovato per questo studente"}

        challenge_data = self.challenges[student_did]
        challenge = challenge_data["value"]

        # Verifica che il challenge non sia scaduto
        expires_at = datetime.fromisoformat(challenge_data["expires_at"])
        if datetime.now() > expires_at:
            return {"status": "error", "message": "Challenge scaduto"}

        # Se viene fornita la chiave pubblica, verifica effettivamente la firma
        if student_public_key_pem:
            if self.verify_signature(student_public_key_pem, challenge, signature):
                # Rimuovi il challenge dopo l'uso
                self.challenges.pop(student_did)
                return {"status": "ok", "message": "Challenge verificato con successo"}
            else:
                return {"status": "error", "message": "Firma del challenge non valida"}
        else:
            # Simulazione della verifica per compatibilità retroattiva
            # Rimuovi il challenge dopo l'uso
            self.challenges.pop(student_did)
            return {"status": "ok", "message": "Challenge verificato con successo (simulazione)"}

    def accept_application(self, student_did, application_data, signature, student_public_key_pem=None):
        """
        Accetta una candidatura Erasmus firmata dallo studente

        Args:
            student_did (str): Il DID dello studente
            application_data (dict): I dati della candidatura
            signature (str): La firma dei dati
            student_public_key_pem (str, optional): Chiave pubblica dello studente in formato PEM

        Returns:
            dict: Risposta dell'accettazione
        """
        # Se viene fornita la chiave pubblica, verifica effettivamente la firma
        if student_public_key_pem:
            data_str = str(application_data)
            if not self.verify_signature(student_public_key_pem, data_str, signature):
                return {
                    "status": "rejected",
                    "message": "Firma della candidatura non valida",
                    "timestamp": datetime.now().isoformat()
                }

        # Se la verifica è andata a buon fine o non è stata richiesta, accetta la candidatura
        return {
            "status": "accepted",
            "message": "Candidatura accettata con successo",
            "timestamp": datetime.now().isoformat()
        }

    def issue_credential(self, student_did, student_data, application_data):
        """
        Emette una credenziale verificabile per lo studente

        Args:
            student_did (str): Il DID dello studente
            student_data (dict): I dati dello studente (nome, matricola, ecc.)
            application_data (dict): I dati della candidatura Erasmus

        Returns:
            dict: La credenziale verificabile
        """
        # Genera un ID univoco per la credenziale
        credential_id = f"urn:uuid:{uuid.uuid4()}"

        # Data di emissione e scadenza
        issuance_date = datetime.now().isoformat()
        expiration_date = (datetime.now() + timedelta(days=365)).isoformat()  # Validità di un anno

        # Creazione della credenziale verificabile
        credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": credential_id,
            "type": ["VerifiableCredential", "ErasmusAcceptanceCredential"],
            "issuer": self.issuer_did,
            "issuanceDate": issuance_date,
            "expirationDate": expiration_date,
            "credentialSubject": {
                "id": student_did,
                "name": student_data.get("name", ""),
                "studentId": student_data.get("studentId", ""),
                "erasmusApplication": {
                    "university": application_data.get("university", ""),
                    "motivation": application_data.get("motivation", ""),
                    "status": "ACCEPTED",
                    "programYear": datetime.now().year
                }
            }
        }

        # Ottieni l'impronta digitale (hash) della credenziale da firmare
        credential_json = json.dumps(credential, sort_keys=True)

        # Firma la credenziale
        proof = {
            "type": "RsaSignature2018",
            "created": issuance_date,
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"{self.issuer_did}#keys-1",
            "proofValue": self._sign(credential_json)
        }

        # Aggiungi la prova alla credenziale
        credential["proof"] = proof

        # Salva la credenziale nel database
        self._save_credential(credential)

        return credential

    def _save_credential(self, credential):
        """
        Salva una credenziale nel database

        Args:
            credential (dict): La credenziale da salvare

        Returns:
            bool: True se il salvataggio ha successo, False altrimenti
        """
        db = self.db_manager._load_db()
        db["credentials"].append(credential)
        return self.db_manager._save_db(db)

    def get_credentials_by_did(self, student_did):
        """
        Recupera tutte le credenziali di uno studente

        Args:
            student_did (str): Il DID dello studente

        Returns:
            list: Lista di credenziali
        """
        db = self.db_manager._load_db()
        return [cred for cred in db["credentials"] if cred["credentialSubject"]["id"] == student_did]

    def revoke_credential(self, credential_id):
        """
        Revoca una credenziale

        Args:
            credential_id (str): ID della credenziale

        Returns:
            bool: True se la revoca ha successo, False altrimenti
        """
        db = self.db_manager._load_db()

        for cred in db["credentials"]:
            if cred["id"] == credential_id:
                # Aggiungi informazioni sulla revoca
                cred["revoked"] = True
                cred["revocationDate"] = datetime.now().isoformat()
                return self.db_manager._save_db(db)

        return False

