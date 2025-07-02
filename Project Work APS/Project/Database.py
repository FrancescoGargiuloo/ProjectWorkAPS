import os
import json
from datetime import datetime
from cryptography.fernet import Fernet
from PasswordManager import PasswordManager

BASE_DIR = os.path.dirname(__file__)
DB_FOLDER = os.path.join(BASE_DIR, "database")
KEY_FOLDER = os.path.join(BASE_DIR, "keys")
os.makedirs(DB_FOLDER, exist_ok=True)
os.makedirs(KEY_FOLDER, exist_ok=True)

DB_FILE = os.path.join(DB_FOLDER, "user_db.json")
DB_ENCRYPTION_KEY_PATH = os.path.join(KEY_FOLDER, "db_encryption.key")


class DatabaseManager:
    def __init__(self, db_file=DB_FILE):
        self.db_file = db_file
        self.encryption_key = self._load_or_create_encryption_key()
        self._init_db()

    def _load_or_create_encryption_key(self):
        if os.path.exists(DB_ENCRYPTION_KEY_PATH):
            with open(DB_ENCRYPTION_KEY_PATH, 'rb') as key_file:
                return key_file.read()
        else:
            key = Fernet.generate_key()
            with open(DB_ENCRYPTION_KEY_PATH, 'wb') as key_file:
                key_file.write(key)
            return key

    def _encrypt_db(self, db_data):
        fernet = Fernet(self.encryption_key)
        return fernet.encrypt(json.dumps(db_data).encode())

    def _decrypt_db(self, encrypted_data):
        fernet = Fernet(self.encryption_key)
        return json.loads(fernet.decrypt(encrypted_data))

    def _init_db(self):
        if not os.path.exists(self.db_file) or os.path.getsize(self.db_file) == 0:
            empty_db = {"users": []}
            self._save_db(empty_db)

    def _load_db(self):
        try:
            with open(self.db_file, 'rb') as file:
                encrypted_data = file.read()
                return self._decrypt_db(encrypted_data)
        except Exception as e:
            print(f"[!] Errore durante il caricamento del DB: {e}")
            return {"users": []}

    def _save_db(self, db_data):
        try:
            encrypted_data = self._encrypt_db(db_data)
            with open(self.db_file, 'wb') as file:
                file.write(encrypted_data)
            return True
        except Exception as e:
            print(f"[!] Errore salvataggio DB: {e}")
            return False


class UserManager(DatabaseManager):
    def __init__(self, db_file=DB_FILE):
        super().__init__(db_file)

    def first_login(self, user_id, username, password, first_name, last_name):
        """
        Registra un nuovo utente nel database.

        Args:
            user_id (str): ID univoco dell'utente
            username (str): Nome utente
            password (str): Password in chiaro
            did (str): DID dell'utente
            first_name (str): Nome dell'utente
            last_name (str): Cognome dell'utente

        Returns:
            bool: True se l'inserimento ha avuto successo, False altrimenti
        """
        db = self._load_db()
        if any(u["id"] == user_id or u["username"] == username for u in db["users"]):
            print("⚠️ Utente già registrato.")
            return False

        salt = PasswordManager.generate_salt()
        hash_pw = PasswordManager.hash_password(password, salt)

        db["users"].append({
            "id": user_id,
            "username": username,
            "hash_password": hash_pw,
            "salt": salt,
            "first_name": first_name,
            "last_name": last_name,
            "did": "",
            "created_at": datetime.now().isoformat()
        })
        return self._save_db(db)
    
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
    
    def authenticate_user(self, username, password):
        """
        Verifica le credenziali dell'utente

        Args:
            username (str): Username dell'utente
            password (str): Password in chiaro

        Returns:
            dict: Dati dell'utente se l'autenticazione ha successo, None altrimenti
        """
        db = self._load_db()
        for user in db["users"]:
            if user["username"] == username:
                if PasswordManager.verify_password(user["hash_password"], password, user["salt"]):
                    return user
        return None

    def update_user_did(self, user_id, new_did):
        """
        Aggiorna il DID di un utente.

        Args:
            user_id (str): ID dell'utente
            new_did (str): Nuovo DID da assegnare

        Returns:
            bool: True se l'aggiornamento ha avuto successo, False altrimenti
        """
        db = self._load_db()
        for user in db["users"]:
            if user["id"] == user_id:
                user["did"] = new_did
                return self._save_db(db)
        return False

    def get_user_by_did(self, did):
        db = self._load_db()
        for user in db["users"]:
            if user["did"] == did:
                return user
        return None
