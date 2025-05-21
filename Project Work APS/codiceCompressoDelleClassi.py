from datetime import datetime, timedelta
import json
import uuid
import base64
import hashlib
import random
import string
import os
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet

# Configurazione
DB_FILE = "verifiable_credentials_db.json"
DB_BACKUP_FOLDER = "db_backups"
KEY_FOLDER = "keys"
UNIVERSITY_PRIVATE_KEY_PATH = os.path.join(KEY_FOLDER, "university_private_key.pem")
DB_ENCRYPTION_KEY_PATH = os.path.join(KEY_FOLDER, "db_encryption.key")

# Assicurati che le cartelle esistano
for folder in [DB_BACKUP_FOLDER, KEY_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)


class PasswordManager:
    """Gestisce le operazioni di hashing e verifica delle password"""

    @staticmethod
    def generate_salt():
        """Genera un salt casuale per l'hashing delle password"""
        return base64.b64encode(os.urandom(32)).decode('utf-8')

    @staticmethod
    def hash_password(password, salt):
        """
        Crea un hash della password utilizzando PBKDF2HMAC

        Args:
            password (str): La password in chiaro
            salt (str): Il salt in formato base64

        Returns:
            str: Hash della password in formato base64
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=base64.b64decode(salt),
            iterations=100000,
        )

        key = kdf.derive(password.encode('utf-8'))
        return base64.b64encode(key).decode('utf-8')

    @staticmethod
    def verify_password(stored_hash, password, salt):
        """
        Verifica se una password corrisponde all'hash memorizzato

        Args:
            stored_hash (str): L'hash memorizzato in formato base64
            password (str): La password in chiaro da verificare
            salt (str): Il salt in formato base64

        Returns:
            bool: True se la password è corretta, False altrimenti
        """
        calculated_hash = PasswordManager.hash_password(password, salt)
        return calculated_hash == stored_hash


class DatabaseManager:
    """Gestisce le operazioni di base sul database JSON"""

    def __init__(self, db_file=DB_FILE):
        """
        Inizializza il gestore del database

        Args:
            db_file (str): Percorso del file JSON del database
        """
        self.db_file = db_file
        self.encryption_key = self._load_or_create_encryption_key()
        self._init_db()

    def _load_or_create_encryption_key(self):
        """Carica o crea una chiave di crittografia per il database"""
        if os.path.exists(DB_ENCRYPTION_KEY_PATH):
            with open(DB_ENCRYPTION_KEY_PATH, 'rb') as key_file:
                return key_file.read()
        else:
            # Genera una nuova chiave
            key = Fernet.generate_key()
            with open(DB_ENCRYPTION_KEY_PATH, 'wb') as key_file:
                key_file.write(key)
            return key

    def _encrypt_db(self, db_data):
        """Cripta i dati del database"""
        fernet = Fernet(self.encryption_key)
        return fernet.encrypt(json.dumps(db_data).encode())

    def _decrypt_db(self, encrypted_data):
        """Decripta i dati del database"""
        fernet = Fernet(self.encryption_key)
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data)

    def _init_db(self):
        """Inizializza il database se non esiste"""
        if not os.path.exists(self.db_file):
            db_structure = {
                "users": [],
                "credentials": [],
                "metadata": {
                    "created_at": datetime.now().isoformat(),
                    "version": "1.0"
                }
            }
            self._save_db(db_structure)

    def _create_backup(self):
        """Crea un backup del database prima di effettuare modifiche"""
        if os.path.exists(self.db_file):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(DB_BACKUP_FOLDER, f"db_backup_{timestamp}.json")
            try:
                with open(self.db_file, 'rb') as src, open(backup_file, 'wb') as dst:
                    dst.write(src.read())
                return True
            except Exception as e:
                print(f"Errore durante il backup del database: {e}")
                return False
        return False

    def _load_db(self):
        """Carica il database dal file JSON"""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'rb') as file:
                    encrypted_data = file.read()
                    return self._decrypt_db(encrypted_data)
            except Exception as e:
                print(f"Errore durante il caricamento del database: {e}")
                # Tenta di recuperare un backup
                self._restore_from_latest_backup()
        return {
            "users": [],
            "credentials": [],
            "metadata": {
                "created_at": datetime.now().isoformat(),
                "version": "1.0"
            }
        }

    def _save_db(self, db_data):
        """Salva il database nel file JSON"""
        try:
            encrypted_data = self._encrypt_db(db_data)
            with open(self.db_file, 'wb') as file:
                file.write(encrypted_data)
            return True
        except Exception as e:
            print(f"Errore durante il salvataggio del database: {e}")
            return False

    def _restore_from_latest_backup(self):
        """Recupera il database dall'ultimo backup disponibile"""
        backups = [os.path.join(DB_BACKUP_FOLDER, f) for f in os.listdir(DB_BACKUP_FOLDER) if
                   f.startswith("db_backup_")]
        if not backups:
            print("Nessun backup trovato")
            return False

        # Ordina i backup per data (il più recente per primo)
        backups.sort(reverse=True)
        latest_backup = backups[0]

        try:
            with open(latest_backup, 'rb') as backup_file, open(self.db_file, 'wb') as db_file:
                db_file.write(backup_file.read())
            print(f"Database ripristinato dal backup: {latest_backup}")
            return True
        except Exception as e:
            print(f"Errore durante il ripristino del backup: {e}")
            return False


class UserManager(DatabaseManager):
    """Gestisce le operazioni relative agli utenti"""

    def __init__(self, db_file=DB_FILE):
        """
        Inizializza il gestore degli utenti

        Args:
            db_file (str): Percorso del file JSON del database
        """
        super().__init__(db_file)

    def add_user(self, nome, cognome, password, email=None, role="student"):
        """
        Aggiunge un nuovo utente al database

        Args:
            nome (str): Nome dell'utente
            cognome (str): Cognome dell'utente
            password (str): Password in chiaro (verrà hashata)
            email (str, optional): Email dell'utente
            role (str, optional): Ruolo dell'utente (default: "student")

        Returns:
            dict: Informazioni dell'utente aggiunto o None se l'operazione fallisce
        """
        # Controllo se esiste già un utente con lo stesso nome e cognome
        existing_user = self.get_user_by_name(nome, cognome)
        if existing_user:
            print(f"Utente {nome} {cognome} già esistente")
            return None

        # Genera un ID univoco per l'utente
        user_id = str(uuid.uuid4())

        # Genera un DID per l'utente
        did = f"did:example:{user_id}"

        # Genera un salt e hash della password
        salt = PasswordManager.generate_salt()
        hashed_password = PasswordManager.hash_password(password, salt)

        # Crea il record utente
        user = {
            'id': user_id,
            'nome': nome,
            'cognome': cognome,
            'salt': salt,
            'hash_password': hashed_password,
            'did': did,
            'email': email,
            'role': role,
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'status': 'active'
        }

        # Carica il database e aggiungi l'utente
        self._create_backup()
        db = self._load_db()
        db["users"].append(user)

        # Salva il database aggiornato
        if self._save_db(db):
            # Rimuovi il campo della password prima di restituire l'utente
            user_copy = user.copy()
            user_copy.pop('hash_password')
            user_copy.pop('salt')
            return user_copy

        return None

    def get_user_by_id(self, user_id):
        """
        Recupera un utente dal database per ID

        Args:
            user_id (str): ID dell'utente

        Returns:
            dict: Dati dell'utente o None se non trovato
        """
        db = self._load_db()

        for user in db["users"]:
            if user["id"] == user_id:
                # Rimuovi i campi sensibili
                user_copy = user.copy()
                user_copy.pop('hash_password')
                user_copy.pop('salt')
                return user_copy

        return None

    def get_user_by_did(self, did):
        """
        Recupera un utente dal database per DID

        Args:
            did (str): DID dell'utente

        Returns:
            dict: Dati dell'utente o None se non trovato
        """
        db = self._load_db()

        for user in db["users"]:
            if user["did"] == did:
                # Rimuovi i campi sensibili
                user_copy = user.copy()
                user_copy.pop('hash_password')
                user_copy.pop('salt')
                return user_copy

        return None


    def authenticate_user(self, nome, cognome, password):
        """
        Verifica le credenziali dell'utente

        Args:
            nome (str): Nome dell'utente
            cognome (str): Cognome dell'utente
            password (str): Password in chiaro

        Returns:
            dict: Dati dell'utente se l'autenticazione ha successo, None altrimenti
        """
        db = self._load_db()

        for user in db["users"]:
            if user["nome"].lower() == nome.lower() and user["cognome"].lower() == cognome.lower():
                # Verifica la password
                if PasswordManager.verify_password(user["hash_password"], password, user["salt"]):
                    # Aggiorna l'ultimo accesso
                    self._update_last_login(user["id"])

                    # Rimuovi i campi sensibili
                    user_copy = user.copy()
                    user_copy.pop('hash_password')
                    user_copy.pop('salt')
                    user_copy["last_login"] = datetime.now().isoformat()
                    return user_copy

        return None

    def _update_last_login(self, user_id):
        """
        Aggiorna la data dell'ultimo login

        Args:
            user_id (str): ID dell'utente

        Returns:
            bool: True se l'aggiornamento ha successo, False altrimenti
        """
        db = self._load_db()

        for user in db["users"]:
            if user["id"] == user_id:
                user["last_login"] = datetime.now().isoformat()
                return self._save_db(db)

        return False

    def update_user(self, user_id, field, value):
        """
        Aggiorna un campo dell'utente

        Args:
            user_id (str): ID dell'utente
            field (str): Nome del campo da aggiornare
            value: Nuovo valore

        Returns:
            bool: True se l'aggiornamento ha successo, False altrimenti
        """
        if field in ["id", "salt", "hash_password", "created_at"]:
            print(f"Il campo {field} non può essere aggiornato")
            return False

        self._create_backup()
        db = self._load_db()

        for user in db["users"]:
            if user["id"] == user_id:
                user[field] = value
                return self._save_db(db)

        return False

    def update_password(self, user_id, old_password, new_password):
        """
        Aggiorna la password dell'utente

        Args:
            user_id (str): ID dell'utente
            old_password (str): Vecchia password
            new_password (str): Nuova password

        Returns:
            bool: True se l'aggiornamento ha successo, False altrimenti
        """
        db = self._load_db()

        for user in db["users"]:
            if user["id"] == user_id:
                # Verifica la vecchia password
                if not PasswordManager.verify_password(user["hash_password"], old_password, user["salt"]):
                    print("La vecchia password non è corretta")
                    return False

                # Genera un nuovo salt e hash per la nuova password
                salt = PasswordManager.generate_salt()
                hashed_password = PasswordManager.hash_password(new_password, salt)

                # Aggiorna la password
                user["salt"] = salt
                user["hash_password"] = hashed_password

                return self._save_db(db)

        return False





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


# Esempio di utilizzo
if __name__ == "__main__":
    # Inizializza il sistema
    user_manager = UserManager()
    university = UniversityIssuer("