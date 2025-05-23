from holder import Student
from issuer import UniversityIssuer
from resolver import DIDWebResolver
from DatabaseManager import UserManager

if __name__ == "__main__":
    # === Autenticazione utente ===
    user_manager = UserManager()

    print("== Login Utente ==")
    username = input("Username: ").strip()
    password = input("Password: ").strip()

    authenticated_user = user_manager.authenticate_user(username, password)
    if not authenticated_user:
        print("Accesso negato. Credenziali non valide.")
        exit(1)

    user_id = authenticated_user["id"]

    # === Inizializza lo studente ===
    student = Student(username)  # Gestisce creazione/lettura chiavi in automatico

    # === Risoluzione del DID ===
    did_web = "did:web:localhost:8443"

    try:
        result = DIDWebResolver.resolve(did_web)
        did_document = result["document"]
        student_public_key = result["publicKey"]
        print(f"DID risolto correttamente: {did_web}")
        print("Chiave pubblica dello studente caricata.")
    except Exception as e:
        print("Errore nella risoluzione del DID:", e)
        exit(1)

    # === Associa DID allo studente se mancante ===
    if not authenticated_user.get("did"):
        print("Associando DID allo studente...")
        update_success = user_manager.update_user_did(user_id, did_web)
        if update_success:
            print("DID associato correttamente al profilo dello studente.")
        else:
            print("Errore durante l'associazione del DID.")
            exit(1)


    # === Inizializza l'issuer ===
    issuer = UniversityIssuer(did_web)

    # === Dati candidatura Erasmus ===
    erasmus_data = {
        "university": "UniRoma",
        "motivation": "Voglio crescere."
    }
    signature = student.sign(erasmus_data)

    # === Invio candidatura firmata ===
    response = issuer.accept_application(erasmus_data, signature, student_public_key)
    print("Risposta candidatura:", response)

    # === Autenticazione Challenge ===
    challenge = issuer.generate_challenge(student.did)
    print("Challenge generato:", challenge)

    challenge_signature = student.sign(challenge)

    result = issuer.verify_challenge_response(student.did, challenge_signature, student_public_key)
    print("Risultato verifica challenge:", result)

    if result["status"] == "ok":
        print("\nAutenticazione challenge completata con successo.")
        print("Lo studente può procedere con la candidatura ufficiale.")
    else:
        print("\nAutenticazione challenge fallita. Bloccare il processo.")
        exit(1)
