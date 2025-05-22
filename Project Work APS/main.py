from holder import Student
from issuer import UniversityIssuer
from resolver import DIDWebResolver
import json
from DatabaseManager import UserManager
if __name__ == "__main__":

    # Inizializza il gestore degli utenti
    user_manager = UserManager()

    # Richiesta di login all'utente, supposto già autenticato
    print("Per poter accedere, inserisca nome, cognome e password:")
    nome = input("Nome: ")
    cognome = input("Cognome: ")
    password = input("Password: ")
    # inizializza lo studente

    student = Student(nome, cognome, password)

    # Percorsi delle chiavi
    student_key_path = "rsa.key"
    student_public_key_path = "rsa_pub.key"
    university_key_path = "university_private_key.pem"

    # Autenticazione dell'utente tramite il database
    # authenticated_user = user_manager.authenticate_user(nome, cognome, password)

    #if not authenticated_user:
    #    print("Accesso negato. Credenziali non valide.")
    #    exit(0)

    #print(f"Login riuscito! Benvenuto {authenticated_user['nome']} {authenticated_user['cognome']}")

    # Simulazione associazione del DID Web per lo studente
    did_web = "did:web:localhost:8443"
    try:
        # Prova a risolvere il DID usando il resolver (controlla che il documento DID sia accessibile)
        did_doc = DIDWebResolver.resolve(did_web)
        # Se ok, assegna il DID all'oggetto studente
        print("DID associato correttamente.")
    except Exception as e:
        # Se fallisce la risoluzione, stampa errore e termina
        print("Errore nella risoluzione del DID:", e)
        exit(1)

    # associare il DID dello studente, una volta verificato, nel DB dell'uni

    # Crea un oggetto UniversityIssuer con il DID dell'issuer e il percorso alla chiave privata
    issuer = UniversityIssuer(did_web, key_path=university_key_path)

    # Ottiene la chiave pubblica dello studente per la verifica
    student_public_key = student.get_public_key_pem()
    print("\nChiave pubblica dello studente recuperata da:", student_public_key_path)

    # Dati della candidatura Erasmus da inviare firmati
    erasmus_data = {
        "university": "UniRoma",
        "motivation": "Voglio crescere."
    }

    # Trasforma i dati in stringa per firmarli
    data_str = str(erasmus_data)

    # Lo studente firma i dati
    signature = student.sign(data_str)

    # Invio candidatura all'issuer con dati, DID studente, firma e chiave pubblica
    response = issuer.accept_application(student.did, erasmus_data, signature, student_public_key)
    print("Risposta:", response)

    # Step 1: l'issuer genera un challenge (nonce) da far firmare allo studente
    challenge = issuer.generate_challenge(student.did)
    print("Challenge per lo studente:", challenge)

    # Lo studente firma il challenge ricevuto dall'issuer
    challenge_signature = student.sign(challenge)

    # Step 2: l'issuer verifica la firma sul challenge firmato dallo studente
    result = issuer.verify_challenge_response(student.did, challenge_signature, student_public_key)
    print("Verifica challenge:", result)

    # Se il challenge è stato verificato correttamente
    if result["status"] == "ok":
        # Step 3: lo studente può inviare la candidatura firmata come prima
        erasmus_data = {
            "university": "UniRoma",
            "motivation": "Voglio crescere."
        }
        data_str = str(erasmus_data)
        signature = student.sign(data_str)
        response = issuer.accept_application(student.did, erasmus_data, signature, student_public_key)
        print("Risposta candidatura:", response)

        # NUOVO STEP: Emissione della credenziale verificabile
        print("\n=== Emissione della Credenziale Verificabile ===")
        credential = issuer.issue_credential(student.did, student_data, erasmus_data)

        # Stampa la credenziale in formato JSON formattato
        print("Credenziale emessa:")
        print(json.dumps(credential, indent=2))

        # Lo studente memorizza la credenziale nel suo wallet
        student.store_credential(credential)
        print(f"Credenziale memorizzata nel wallet dello studente {student_data['name']}")

        # Esempio di recupero della credenziale dal wallet
        erasmus_credentials = student.get_credential_by_type("ErasmusAcceptanceCredential")
        print(f"Numero di credenziali Erasmus nel wallet: {len(erasmus_credentials)}")
    else:
        # Se la verifica challenge fallisce, blocca la candidatura
        print("Autenticazione fallita.")
