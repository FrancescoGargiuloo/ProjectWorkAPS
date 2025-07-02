from Student import Student
from University import University
import uuid
import json

def pre_game():
    print("==== [ SETUP UNIVERSITÀ ] ====")
    university = University()

    print("\n==== [ LOGIN O REGISTRAZIONE STUDENTE ] ====")
    username = input("Inserisci username: ").strip()
    password = input("Inserisci password: ").strip()

    # Prova ad autenticare lo studente
    user_data = university.authenticate_student(username, password)

    if not user_data:
        print("Utente non trovato o password errata. Registrazione in corso...")

        first_name = input("Inserisci il tuo nome: ").strip()
        last_name = input("Inserisci il tuo cognome: ").strip()

        # Genero ID univoco per il nuovo utente
        user_id = str(uuid.uuid4())
        success = university.register_student(user_id, username, password, first_name, last_name)

        if not success:
            print("Errore durante la registrazione.")
            return

        # Creo lo studente (genera chiavi e DID)
        student = Student(username=username, password=password,
                        first_name=first_name, last_name=last_name)
        print(f"Utente '{username}' registrato con DID: {student.did}")

        # Salvo il DID nel database cifrato
        university.assign_did_to_student(user_id, student.did)
    else:
        print("Autenticazione riuscita.")
        student = Student(
            username=username,
            password=password,
            first_name=user_data.get("first_name"),
            last_name=user_data.get("last_name")
        )


    print("\n==== [ CHALLENGE-RESPONSE ] ====")

    # Università genera un challenge legato al DID
    challenge = university.generate_challenge(student.did)
    print(f"Challenge generato: {challenge}")

    # Lo studente firma il challenge con la propria chiave privata
    signature = student.sign(challenge)
    print(f"Firma generata: {signature[:32]}...")

    # L'università verifica la firma del challenge
    verification = university.verify_challenge_response(
        student_did=student.did,
        signature_b64=signature,
        student_public_key_pem=student.get_public_key()
    )

    if verification["status"] == "ok":
        print("Verifica Challenge-Response riuscita.")
    else:
        print(f"Verifica fallita: {verification['message']}")
    
    while True:
        print("\n==== [ MENU ] ====")
        print("1. Esci")
        print("2. Richiedi credenziale Erasmus")
        choice = input("Seleziona un'opzione: ").strip()

        if choice == "1":
            break
        elif choice == "2":
            university.generate_erasmus_credential(student)
        else:
            print("Opzione non valida.")

if __name__ == "__main__":
    pre_game()
