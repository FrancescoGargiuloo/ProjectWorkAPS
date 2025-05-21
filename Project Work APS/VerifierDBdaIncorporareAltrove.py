import secrets
import time

# Percorso del file JSON
DB_FILE = "dbVerifier.json"


# Funzioni di utilità per la gestione delle password
def generate_salt():
    """Genera un salt casuale"""
    return secrets.token_hex(16)


def hash_password(password, salt):
    """Crea un hash della password utilizzando il salt"""
    return hashlib.sha256((password + salt).encode()).hexdigest()


# Funzioni di utilità per la gestione del database
def load_db():
    """Carica il database dal file JSON"""
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r') as file:
                return json.load(file)
        except json.JSONDecodeError:
            print("Errore nel parsing del file JSON. Inizializzazione di un nuovo database.")
            return {"users": []}
    else:
        return {"users": []}


def save_db(db):
    """Salva il database nel file JSON"""
    with open(DB_FILE, 'w') as file:
        json.dump(db, file, indent=2)


# Inizializzazione del database
def init_db():
    """Inizializza il database se non esiste"""
    if not os.path.exists(DB_FILE):
        db = {"users": []}
        save_db(db)


# CRUD Operations
def add_user(nome, cognome, password):
    """Aggiunge un nuovo utente al database"""
    db = load_db()

    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    # Genera un ID univoco per l'utente
    user_id = str(uuid.uuid4())[:8]

    # Genera un DID (esempio semplificato)
    did = f"did:example:{user_id}"

    # Crea il record utente
    user = {
        'id': user_id,
        'nome': nome,
        'cognome': cognome,
        'salt': salt,
        'hash_password': hashed_password,
        'did': did,
        'created_at': time.time()
    }

    db["users"].append(user)
    save_db(db)

    return user_id


def get_user_by_id(user_id):
    """Recupera un utente dal database per ID"""
    db = load_db()

    for user in db["users"]:
        if user["id"] == user_id:
            return user

    return None


def authenticate_user(nome, cognome, password):
    """Verifica le credenziali dell'utente"""
    user = get_user_by_name(nome, cognome)

    if user:
        if user["hash_password"] == hash_password(password, user["salt"]):
            return user

    return None


def delete_user(user_id):
    """Elimina un utente dal database"""
    db = load_db()
    initial_count = len(db["users"])

    db["users"] = [user for user in db["users"] if user["id"] != user_id]

    if len(db["users"]) < initial_count:
        save_db(db)
        return True

    return False

