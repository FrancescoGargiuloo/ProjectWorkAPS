# Database.py (la tua classe UserManager)

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

    # Aggiungi public_key_pem come parametro con valore predefinito
    def first_login(self, user_id, username, password, first_name, last_name, public_key_pem=""):
        """
        Registra un nuovo utente nel database, inclusa la chiave pubblica.
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
            "did": "",  # Il DID verrà assegnato in un passo successivo tramite update_user_did_and_public_key
            "public_key_pem": public_key_pem,  # Salva la chiave pubblica
            "created_at": datetime.now().isoformat()
        })
        return self._save_db(db)

    def get_user_by_id(self, user_id):
        """
        Recupera un utente dal database per ID
        Ora restituisce anche 'did' e 'public_key_pem'.
        """
        db = self._load_db()
        for user in db["users"]:
            if user["id"] == user_id:
                user_copy = user.copy()
                user_copy.pop('hash_password')
                user_copy.pop('salt')
                return user_copy
        return None

    def get_user_by_did(self, did):
        """
        Recupera un utente dal database per DID
        Ora restituisce anche 'id' e 'public_key_pem'.
        """
        db = self._load_db()
        for user in db["users"]:
            if user["did"] == did:
                user_copy = user.copy()
                user_copy.pop('hash_password')
                user_copy.pop('salt')
                return user_copy
        return None

    def authenticate_user(self, username, password):
        """
        Verifica le credenziali dell'utente e restituisce i suoi dati completi.
        """
        db = self._load_db()
        for user in db["users"]:
            if user["username"] == username:
                if PasswordManager.verify_password(user["hash_password"], password, user["salt"]):
                    return user  # Restituisce l'intero oggetto utente
        return None

    # Nuovo metodo per aggiornare sia il DID che la chiave pubblica
    def update_user_did_and_public_key(self, user_id, new_did, public_key_pem):
        """
        Aggiorna il DID e la chiave pubblica di un utente.
        """
        db = self._load_db()
        for user in db["users"]:
            if user["id"] == user_id:
                user["did"] = new_did
                user["public_key_pem"] = public_key_pem
                return self._save_db(db)
        return False

    def update_user_did(self, user_id, new_did):  # Mantieni questo per compatibilità se usato altrove
        """
        Aggiorna solo il DID di un utente (meno preferibile rispetto a update_user_did_and_public_key).
        """
        db = self._load_db()
        for user in db["users"]:
            if user["id"] == user_id:
                user["did"] = new_did
                return self._save_db(db)
        return False