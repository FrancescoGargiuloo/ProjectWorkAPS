import os
import json
from datetime import datetime
from cryptography.fernet import Fernet
from PasswordManager import PasswordManager  # Assumendo che questa classe esista e sia corretta

BASE_DIR = os.path.dirname(__file__)
DB_FOLDER = os.path.join(BASE_DIR, "database")
KEY_FOLDER = os.path.join(BASE_DIR, "keys")
os.makedirs(DB_FOLDER, exist_ok=True)
os.makedirs(KEY_FOLDER, exist_ok=True)


class DatabaseManager:
    """
    Gestisce il caricamento, il salvataggio e la crittografia/decrittografia
    di un database JSON. Ogni istanza gestisce un DB e una chiave di crittografia unici.
    """

    def __init__(self, db_name="user_db"):
        """
        Inizializza il DatabaseManager.
        :param db_name: Il nome base del file del database (es. "unisa_users", "rennes_users").
                        Questo nome verrà usato per il file .json del DB e per il file .key di crittografia.
        """
        self.db_file = os.path.join(DB_FOLDER, f"{db_name}.json")
        self.encryption_key_path = os.path.join(KEY_FOLDER, f"{db_name}_encryption.key")
        self.encryption_key = self._load_or_create_encryption_key()
        self._init_db()

    def _load_or_create_encryption_key(self):
        """
        Carica la chiave di crittografia dal percorso specifico del DB.
        Se non esiste o se la chiave esistente è invalida, ne genera una nuova e la salva.
        :return: La chiave di crittografia.
        """
        if os.path.exists(self.encryption_key_path):
            try:
                with open(self.encryption_key_path, 'rb') as key_file:
                    key = key_file.read()
                # Test the key to ensure it's valid Fernet key
                Fernet(key)  # This will raise an error if the key is malformed
                print(f"✔️ Chiave di crittografia caricata da {self.encryption_key_path}")
                return key
            except Exception as e:
                print(
                    f"⚠️ Errore durante il caricamento o la validazione della chiave esistente ({self.encryption_key_path}): {e}. Genero una nuova chiave.")
                # If loading or validating fails, proceed to generate a new key

        # Generate a new key if file doesn't exist or existing key was invalid
        key = Fernet.generate_key()
        with open(self.encryption_key_path, 'wb') as key_file:
            key_file.write(key)
        print(f"🔑 Nuova chiave di crittografia generata e salvata in {self.encryption_key_path}")
        return key

    def _encrypt_db(self, db_data):
        """
        Cripta i dati del database.
        :param db_data: Dizionario contenente i dati del DB.
        :return: Dati criptati in bytes.
        """
        fernet = Fernet(self.encryption_key)
        return fernet.encrypt(json.dumps(db_data).encode())

    def _decrypt_db(self, encrypted_data):
        """
        Decripta i dati del database.
        :param encrypted_data: Dati criptati in bytes.
        :return: Dizionario contenente i dati del DB decriptati.
        """
        fernet = Fernet(self.encryption_key)
        return json.loads(fernet.decrypt(encrypted_data))

    def _init_db(self):
        """
        Inizializza il file del database se non esiste o è vuoto.
        Crea una struttura base con una lista 'users' vuota.
        """
        if not os.path.exists(self.db_file) or os.path.getsize(self.db_file) == 0:
            empty_db = {"users": []}
            self._save_db(empty_db)

    def _load_db(self):
        """
        Carica e decripta il database.
        :return: Dizionario contenente i dati del DB, o una struttura vuota in caso di errore.
        """
        try:
            with open(self.db_file, 'rb') as file:
                encrypted_data = file.read()
                return self._decrypt_db(encrypted_data)
        except Exception as e:
            print(f"[!] Errore durante il caricamento del DB {self.db_file}: {e}")
            return {"users": []}

    def _save_db(self, db_data):
        """
        Cripta e salva il database.
        :param db_data: Dizionario contenente i dati del DB da salvare.
        :return: True se il salvataggio ha successo, False altrimenti.
        """
        try:
            encrypted_data = self._encrypt_db(db_data)
            with open(self.db_file, 'wb') as file:
                file.write(encrypted_data)
            return True
        except Exception as e:
            print(f"[!] Errore salvataggio DB {self.db_file}: {e}")
            return False


class UserManager(DatabaseManager):
    """
    Gestisce le operazioni specifiche degli utenti sul database.
    Eredita le funzionalità di gestione del DB da DatabaseManager.
    """

    def __init__(self, db_name="user_db"):
        """
        Inizializza l'UserManager.
        :param db_name: Il nome del database da gestire per gli utenti.
        """
        super().__init__(db_name)  # Passa db_name al costruttore del genitore

    def first_login(self, user_id, username, password, first_name, last_name, public_key_pem=""):
        """
        Registra un nuovo utente nel database, inclusa la chiave pubblica.
        :param user_id: ID univoco dell'utente.
        :param username: Username dell'utente.
        :param password: Password dell'utente.
        :param first_name: Nome dell'utente.
        :param last_name: Cognome dell'utente.
        :param public_key_pem: Chiave pubblica PEM dell'utente (opzionale, default vuoto).
        :return: True se la registrazione ha successo, False altrimenti.
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
        Recupera un utente dal database per ID.
        :param user_id: ID dell'utente.
        :return: Dizionario con i dati dell'utente (senza hash_password e salt) se trovato, altrimenti None.
        """
        db = self._load_db()
        for user in db["users"]:
            if user["id"] == user_id:
                user_copy = user.copy()
                user_copy.pop('hash_password')
                user_copy.pop('salt')
                return user_copy
        return None

    def get_user_by_username(self, username):
        """
        Recupera un utente dal database per username, senza autenticazione di password.
        Utile per verificare l'esistenza dell'username.
        :param username: Username dell'utente.
        :return: Dizionario con i dati dell'utente (incluso hash_password e salt) se trovato, altrimenti None.
        """
        db = self._load_db()
        for user in db["users"]:
            if user["username"] == username:
                return user
        return None

    def get_user_by_did(self, did):
        """
        Recupera un utente dal database per DID.
        :param did: DID dell'utente.
        :return: Dizionario con i dati dell'utente (senza hash_password e salt) se trovato, altrimenti None.
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
        :param username: Username dell'utente.
        :param password: Password dell'utente.
        :return: Dizionario con tutti i dati dell'utente se l'autenticazione ha successo, altrimenti None.
        """
        db = self._load_db()
        for user in db["users"]:
            if user["username"] == username:
                if PasswordManager.verify_password(user["hash_password"], password, user["salt"]):
                    return user  # Restituisce l'intero oggetto utente
        return None

    def update_user_did_and_public_key(self, user_id, new_did, public_key_pem):
        """
        Aggiorna il DID e la chiave pubblica di un utente.
        :param user_id: ID dell'utente.
        :param new_did: Nuovo DID da assegnare.
        :param public_key_pem: Nuova chiave pubblica PEM da assegnare.
        :return: True se l'aggiornamento ha successo, False altrimenti.
        """
        db = self._load_db()
        for user in db["users"]:
            if user["id"] == user_id:
                user["did"] = new_did
                user["public_key_pem"] = public_key_pem
                return self._save_db(db)
        return False

    def update_user_did(self, user_id, new_did):
        """
        Aggiorna solo il DID di un utente.
        (Meno preferibile rispetto a update_user_did_and_public_key se anche la chiave deve essere aggiornata).
        :param user_id: ID dell'utente.
        :param new_did: Nuovo DID da assegnare.
        :return: True se l'aggiornamento ha successo, False altrimenti.
        """
        db = self._load_db()
        for user in db["users"]:
            if user["id"] == user_id:
                user["did"] = new_did
                return self._save_db(db)
        return False
