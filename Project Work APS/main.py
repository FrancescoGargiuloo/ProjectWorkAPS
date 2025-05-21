from holder import Student
from issuer import UniversityIssuer
from resolver import DIDWebResolver
import json

if __name__ == "__main__":
    # Dizionario utenti validi con username e password
    valid_users = {
        "mario": {"password": "ciao123", "data": {"name": "Mario Rossi", "studentId": "1234567"}},
        "lucia": {"password": "password456", "data": {"name": "Lucia Bianchi", "studentId": "7654321"}}
    }

    # Richiesta di login all'utente
    print("Per poter accedere, inserisca username e password:")
    username = input("Username: ")
    password = input("Password: ")

    # Percorsi delle chiavi
    student_key_path = "rsa.key"
    student_public_key_path = "rsa_pub.key"  # Percorso specifico per la chiave pubblica
    university_key_path = "university_private_key.pem"

    # Crea un oggetto Student con username, password e percorso alle chiavi
    student = Student(username, password, key_path=student_key_path, public_key_path=student_public_key_path)

    # Verifica che username e password corrispondano a quelli validi
    if username not in valid_users or valid_users[username]["password"] != password:
        print("Accesso negato.")  # Se non validi, blocca l'accesso
        exit(0)

    # Recupera i dati dello studente
    student_data = valid_users[username]["data"]

    print("Login riuscito!")

    # Simulazione associazione del DID Web per lo studente
    did_web = "did:web:localhost:8443"
    try:
        # Prova a risolvere il DID usando il resolver (controlla che il documento DID sia accessibile)
        did_doc = DIDWebResolver.resolve(did_web)
        # Se ok, assegna il DID all'oggetto studente
        student.did = did_web
        print("DID associato correttamente.")
    except Exception as e:
        # Se fallisce la risoluzione, stampa errore e termina
        print("Errore nella risoluzione del DID:", e)
        exit(1)

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
