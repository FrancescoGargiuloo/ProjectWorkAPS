from Student import Student
from University import University
import uuid
import json, os
from UniversityRennes import UniversityRennes

BASE_DIR = os.path.dirname(__file__)
CRED_FOLDER = os.path.join(BASE_DIR, "credential")
def pre_game():
    print("==== [ UNIVERSITÀ ] ====")
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


def load_erasmus_credential(username):
    path = os.path.join(CRED_FOLDER, f"{username}_erasmus_credential.json")
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print("❌ Erasmus Credential non trovata.")
        return None

def collect_exam_data():
    exams = []
    print("\nInserisci gli esami superati. Premi ENTER senza nome per terminare.")
    while True:
        name = input("Nome esame: ").strip()
        if not name:
            break
        exam = {
            "examId": input("ID esame: ").strip(),
            "name": name,
            "credits": int(input("Crediti: ").strip()),
            "grade": int(input("Voto: ").strip()),
            "date": input("Data (YYYY-MM-DD): ").strip()
        }
        exams.append(exam)
        print("✔️ Esame aggiunto.")
    return exams

def rennes():
    print("==== [ UNIVERSITÉ DE RENNES ] ====")
    university = UniversityRennes()

    username = input("Username studente: ").strip()
    first_name = input("Nome: ").strip()
    last_name = input("Cognome: ").strip()
    did = f"did:web:{username}.localhost"

    student = Student(username=username, password="*", first_name=first_name, last_name=last_name)
    student.did = did  # Forziamo il DID per simulare

    # 1. Carica Erasmus Credential
    erasmus_cred = load_erasmus_credential(username)
    if not erasmus_cred:
        return

    # 2. Verifica firma Erasmus VC
    if not university.verify_erasmus_credential(erasmus_cred):
        print("❌ Erasmus Credential NON valida.")
        return

    print("✅ Erasmus Credential verificata con successo.")

    # 3. Inserimento esami e generazione Academic VC
    exams = collect_exam_data()
    if not exams:
        print("⚠️ Nessun esame inserito.")
        return

    university.generate_academic_credential(student, exams)
if __name__ == "__main__":
    pre_game()
    print("\n==== FASE PRE GAME COMPLETATA ====")
    print("LO STUDENTE SI PRESENTA ALL'UNIVERSITà OSPITANTE E COMPLETA IL PERCORSO DI STUDIO")
    while True:
        print("\n==== [ MENU ] ====")
        print("1. Esci")
        print("2. Richiedi Attestazione Voti")
        choice = input("Seleziona un'opzione: ").strip()

        if choice == "1":
            break
        elif choice == "2":
            rennes()
        else:
            print("Opzione non valida.")
