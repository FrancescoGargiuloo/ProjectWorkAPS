from datetime import datetime
import json
import os
from cryptography.fernet import Fernet
from PasswordManager import PasswordManager

# Configurazione
DB_FILE = "dbVerifier.json"
KEY_FOLDER = "keys"
DB_ENCRYPTION_KEY_PATH = os.path.join(KEY_FOLDER, "db_encryption.key")


class DatabaseManager:
    """Gestisce le operazioni di base sul database JSON"""

    def __init__(self, db_file=DB_FILE):
        """
        Inizializza il gestore del database

        Args:
            db_file (str): Percorso del file JSON del database
        """
        # Crea le cartelle se non esistono
        os.makedirs(KEY_FOLDER, exist_ok=True)
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
        """Inizializza il database se non esiste o è vuoto"""
        if not os.path.exists(self.db_file) or os.path.getsize(self.db_file) == 0:
            db_structure = {
                "users": [],  # Ogni utente con: id, username, hash_password, salt, did
            }
            success = self._save_db(db_structure)
            if not success:
                print("Errore durante l'inizializzazione del database.")


    def _load_db(self):
        """Carica il database dal file JSON"""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'rb') as file:
                    encrypted_data = file.read()
                    return self._decrypt_db(encrypted_data)
            except Exception as e:
                print(f"Errore durante il caricamento del database: {e}")
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


class UserManager(DatabaseManager):
    """Gestisce le operazioni relative agli utenti"""

    def __init__(self, db_file=DB_FILE):
        """
        Inizializza il gestore degli utenti

        Args:
            db_file (str): Percorso del file JSON del database
        """
        super().__init__(db_file)


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
            if user["username"].lower() == username.lower():
                # Verifica la password
                if PasswordManager.verify_password(user["hash_password"], password, user["salt"]):
                    # Rimuovi i campi sensibili
                    user_copy = user.copy()
                    user_copy.pop('hash_password')
                    user_copy.pop('salt')
                    user_copy["last_login"] = datetime.now().isoformat()
                    return user_copy

        return None

    def first_login(self, user_id, username, password):
        """
        Registra un nuovo utente nel database.

        Args:
            user_id (str): ID univoco dell'utente
            username (str): Nome utente
            password (str): Password in chiaro
            did (str): DID dell'utente

        Returns:
            bool: True se l'inserimento ha avuto successo, False altrimenti
        """
        db = self._load_db()

        # Verifica se esiste già un utente con stesso username o ID
        for user in db["users"]:
            if user["id"] == user_id or user["username"].lower() == username.lower():
                print("Utente già esistente.")
                return False
        salt = PasswordManager.generate_salt()

        # Genera hash della password
        hash_password = PasswordManager.hash_password(password, salt)

        new_user = {
            "id": user_id,
            "username": username,
            "hash_password": hash_password,
            "salt": salt,
            "did": "",
            "created_at": datetime.now().isoformat()
        }

        db["users"].append(new_user)
        return self._save_db(db)

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

        print(f"Utente con ID '{user_id}' non trovato.")
        return False



