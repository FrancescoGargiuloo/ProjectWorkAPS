# Importo le librerie che mi servono per lavorare
import os
import json
import uuid
from Student import Student
from UniversitySalerno import UniversitySalerno
from UniversityRennes import UniversityRennes

# Qui definisco le cartelle dove verranno salvati i file di database, chiavi, credenziali e DIDs
BASE_DIR = os.path.dirname(__file__)
DB_FOLDER = os.path.join(BASE_DIR, "database")
KEY_FOLDER = os.path.join(BASE_DIR, "keys")
DID_FOLDER = os.path.join(BASE_DIR, "DID")

# Creo le cartelle, se non esistono già (così evito errori dopo)
os.makedirs(DB_FOLDER, exist_ok=True)
os.makedirs(KEY_FOLDER, exist_ok=True)
os.makedirs(DID_FOLDER, exist_ok=True)

# Questa lista mi serve per sapere quali studenti ho registrato, utile per fare la pulizia finale
REGISTERED_STUDENTS_FOR_CLEANUP = []


# --- Funzione per eliminare un file, se esiste ---
def _delete_file_if_exists(file_path):
    """Cancello il file solo se esiste (evito errori inutili)."""
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"Eliminato: {file_path}")


# --- Pulizia totale dei dati generati ---
def cleanup_all_data():
    """
    Cancello tutti i file creati dal programma: database, chiavi, DIDs, credenziali ecc.
    """
    print("\n" + "=" * 50)
    print("==== FASE DI PULIZIA DATI ====")
    print("=" * 50)

    # Cancello database degli studenti
    _delete_file_if_exists(os.path.join(DB_FOLDER, "unisa_users.json"))
    _delete_file_if_exists(os.path.join(DB_FOLDER, "rennes_users.json"))

    # Cancello registro revoche e blockchain simulata
    _delete_file_if_exists(os.path.join(BASE_DIR, "revocation_registry.json"))
    _delete_file_if_exists(os.path.join(BASE_DIR, "shared_blockchain.json"))

    # Cancello le chiavi di cifratura dei database (se ci sono)
    _delete_file_if_exists(os.path.join(KEY_FOLDER, "unisa_users_encryption.key"))
    _delete_file_if_exists(os.path.join(KEY_FOLDER, "rennes_users_encryption.key"))

    # Cancello chiavi e DIDs delle università
    _delete_file_if_exists(os.path.join(KEY_FOLDER, "unisa_priv.pem"))
    _delete_file_if_exists(os.path.join(KEY_FOLDER, "unisa_pub.pem"))
    _delete_file_if_exists(os.path.join(DID_FOLDER, "unisa_it_did.json"))

    _delete_file_if_exists(os.path.join(KEY_FOLDER, "rennes_priv.pem"))
    _delete_file_if_exists(os.path.join(KEY_FOLDER, "rennes_pub.pem"))
    _delete_file_if_exists(os.path.join(DID_FOLDER, "rennes_it_did.json"))

    # Cancello tutto quello che riguarda gli studenti registrati
    for student_data in REGISTERED_STUDENTS_FOR_CLEANUP:
        username = student_data["username"]
        user_id = student_data["user_id"]

        # Cancello chiavi dello studente
        _delete_file_if_exists(os.path.join(KEY_FOLDER, f"{username}_priv.pem"))
        _delete_file_if_exists(os.path.join(KEY_FOLDER, f"{username}_pub.pem"))

        # Cancello il file DID dello studente
        did_filename = f"{username.replace('.', '_')}_{user_id}_localhost_did.json"
        _delete_file_if_exists(os.path.join(DID_FOLDER, did_filename))

    print("\n✅ Pulizia completata.")
    print("=" * 50)


# --- FASE 0: Inizializzazione delle università ---
def phase_0_initialization():
    """
    Creo gli oggetti delle università di Salerno e Rennes
    """
    print("\n" + "=" * 50)
    print("==== FASE 0: INIZIALIZZAZIONE ====")
    print("=" * 50)
    salerno_university = UniversitySalerno()
    rennes_university = UniversityRennes()
    print("✅ Università inizializzate correttamente.")
    return salerno_university, rennes_university


# --- FASE 1: Creazione e registrazione degli studenti ---
def phase_1_student_creation(university_salerno, university_rennes):
    """
    Registro 5 studenti finti sia a Salerno che a Rennes
    """
    print("\n" + "=" * 50)
    print("==== FASE 1: CREAZIONE E REGISTRAZIONE STUDENTI ====")
    print("=" * 50)

    students_data = [
        {"username": "mario.rossi", "password": "Password1!", "first_name": "Mario", "last_name": "Rossi"},
        {"username": "anna.bianchi", "password": "Password2!", "first_name": "Anna", "last_name": "Bianchi"},
        {"username": "luca.verdi", "password": "Password3!", "first_name": "Luca", "last_name": "Verdi"},
    ]

    registered_student_objects = []

    for i, data in enumerate(students_data):
        username = data["username"]
        password = data["password"]
        first_name = data["first_name"]
        last_name = data["last_name"]
        user_id = str(uuid.uuid4())

        print(f"\n➡️ Registro lo studente {i + 1}: {username}")
        student_obj = Student(username, password, user_id, first_name, last_name)

        # Registrazione a Salerno
        if university_salerno.register_student(user_id, username, password, first_name, last_name, student_obj.get_public_key()):
            university_salerno.assign_did_to_student(user_id, student_obj.did, student_obj.get_public_key())
            print(f"✅ {username} registrato a UniSA")
        else:
            print(f"❌ Errore a UniSA per {username}")
            continue

        # Registrazione anche a Rennes
        if university_rennes.register_student(user_id, username, password, first_name, last_name, student_obj.get_public_key()):
            university_rennes.assign_did_to_student(user_id, student_obj.did, student_obj.get_public_key())
            print(f"✅ {username} registrato a Rennes")
        else:
            print(f"❌ Errore a Rennes per {username}")
            continue

        registered_student_objects.append(student_obj)
        REGISTERED_STUDENTS_FOR_CLEANUP.append({
            "username": username,
            "user_id": user_id,
            "first_name": first_name,
            "last_name": last_name
        })

    print("\n✅ Tutti gli studenti registrati.")
    return registered_student_objects


# --- FASE 2: Autenticazione con challenge-response ---
def phase_2_enrollment_and_data(students, university_salerno):
    """
    Gli studenti fanno login usando il meccanismo di challenge-response con UniSA
    """
    print("\n" + "=" * 50)
    print("==== FASE 2: AUTENTICAZIONE CON UNISA ====")
    print("=" * 50)

    authenticated_students = []

    for student in students:
        print(f"\n➡️ Autenticazione di {student.username}...")

        user_data = university_salerno.authenticate_student(student.username, student.password)
        if not user_data:
            print(f"❌ Password sbagliata o utente non esistente")
            continue

        if student.did != user_data.get("did"):
            print(f"❌ DID non corrisponde per {student.username}")
            continue

        challenge = university_salerno.generate_challenge(student.user_id)
        if not challenge:
            print(f"❌ Errore nel generare challenge")
            continue

        signature = student.sign(challenge)
        result = university_salerno.verify_challenge_response(student.user_id, signature)

        if result["status"] == "ok":
            print(f"✅ Autenticazione riuscita per {student.username}")
            authenticated_students.append(student)
        else:
            print(f"❌ Verifica fallita: {result['message']}")

    print("\n✅ FASE 2 completata.")
    return authenticated_students


# --- FASE 3: Richiesta credenziale Erasmus ---
def phase_3_issue_erasmus_credential_unisa(authenticated_students, university_salerno):
    """
    Gli studenti autenticati chiedono la credenziale Erasmus a UniSA
    """
    print("\n" + "=" * 50)
    print("==== FASE 3: CREDENZIALE ERASMUS ====")
    print("=" * 50)

    for student in authenticated_students:
        print(f"\n➡️ {student.username} richiede credenziale Erasmus")
        university_salerno.generate_erasmus_credential(student)
        print(f"✅ Credenziale Erasmus generata")

    print("\n✅ FASE 3 completata.")


# --- FASE 4: Richiesta attestato voti da Rennes ---
def phase_4_request_grades_rennes(authenticated_students, university_rennes, university_salerno):
    """
    Ogni studente invia la credenziale Erasmus a Rennes e riceve attestato voti
    """
    print("\n" + "=" * 50)
    print("==== FASE 4: RICHIESTA VOTI A RENNES ====")
    print("=" * 50)

    all_exams_data = university_rennes.collect_exam_data()
    if not all_exams_data:
        print("❌ Nessun voto trovato.")
        return

    for student in authenticated_students:
        print(f"\n➡️ {student.username} si autentica con Rennes")

        challenge = university_rennes.generate_challenge(student.user_id)
        signature = student.sign(challenge)
        result = university_rennes.verify_challenge_response(student.user_id, signature)
        if result["status"] != "ok":
            print("❌ Verifica fallita.")
            continue

        erasmus_cred = student.load_erasmus_credential()
        if not erasmus_cred:
            print("❌ Nessuna credenziale Erasmus trovata")
            continue

        if not university_rennes.verify_erasmus_credential(erasmus_cred):
            print("❌ Erasmus non valida. Revoca inviata a UniSA.")
            university_salerno.revocate_credential(erasmus_cred)
            continue

        university_rennes.generate_academic_credential(student, all_exams_data)
        print("✅ Credenziale accademica generata")

    print("\n✅ FASE 4 completata.")


# --- FASE 5: Presentazione selettiva ---
def phase_5_selective_presentation(authenticated_students, university_salerno, university_rennes):
    """
    Ogni studente genera una presentazione selettiva e la manda a UniSA
    """
    print("\n" + "=" * 50)
    print("==== FASE 5: PRESENTAZIONE SELETTIVA ====")
    print("=" * 50)

    for student in authenticated_students:
        print(f"\n➡️ Generazione presentazione per {student.username}")
        try:
            student.generate_selective_presentation_automated(university_salerno.did)
            print("✅ Presentazione generata")

            with open(os.path.join(student.get_wallet_path(),"credentials", f"{student.username}_vp.json")) as f:
                presentation = json.load(f)
            if student == authenticated_students[1]:
                presentation1 = presentation

            print(f"➡️ UniSA verifica la presentazione di {student.username}")
            result = university_salerno.verify_selective_presentation(presentation)

            if result:
                print("✅ Presentazione valida")
            else:
                print("❌ Presentazione non valida. Invio revoca a Rennes.")
                university_rennes.revocate_credential(presentation)
        except Exception as e:
            print(f"❌ Errore con presentazione: {e}")

    print("\n✅ FASE 5 completata.")
    return presentation1

# --- FASE 6: Revoca credenziali ---
def phase_6_revoke_multiple_credentials(erasmus_student, academic_student, university_salerno, university_rennes):
    """
    Revoco credenziale Erasmus di uno studente e accademica di un altro
    """
    print("\n" + "=" * 50)
    print("==== FASE 6: REVOCA CREDENZIALI ====")
    print("=" * 50)

    erasmus_cred = erasmus_student.load_erasmus_credential()
    if erasmus_cred:
        university_salerno.revocate_credential(erasmus_cred)
        print("✅ Erasmus revocata")
    else:
        print("⚠️ Nessuna Erasmus da revocare")

    academic_cred = academic_student.load_academic_credential()
    if academic_cred:
        university_rennes.revocate_credential(academic_cred)
        print("✅ Credenziale accademica revocata")
    else:
        print("⚠️ Nessuna credenziale accademica trovata")

    print("\n✅ FASE 6 completata.")


# --- FASE 7: Tentativo di riuso dopo revoca ---
def phase_7_re_presentation_after_revocation(erasmus_student, academic_student, presentation, university_salerno, university_rennes):
    """
    Gli studenti provano a riutilizzare credenziali già revocate
    """
    print("\n" + "=" * 50)
    print("==== FASE 7: RIUTILIZZO DOPO REVOCA ====")
    print("=" * 50)

    # Erasmus
    print(f"\n➡️ {erasmus_student.username} riprova a usare la credenziale Erasmus")
    erasmus_cred = erasmus_student.load_erasmus_credential()
    if not erasmus_cred:
        print("❌ Nessuna credenziale Erasmus trovata")
    else:
        if not university_rennes.verify_erasmus_credential(erasmus_cred):
            print("✅ Revoca Erasmus funzionante (non è più valida)")
        else:
            print("⚠️ ERRORE: Erasmus ancora valida dopo revoca!")

    # Accademica
    print(f"\n➡️ {academic_student.username} riprova a usare la presentazione accademica")
    if not university_salerno.verify_selective_presentation(presentation):
        print("✅ Revoca accademica funzionante (non è più valida)")
    else:
        print("⚠️ ERRORE: Accademica ancora valida dopo revoca!")

    print("\n✅ FASE 7 completata.")


# --- ESECUZIONE AUTOMATICA DEL FLUSSO COMPLETO ---
if __name__ == "__main__":
    cleanup_all_data()

    salerno_university, rennes_university = phase_0_initialization()

    students = phase_1_student_creation(salerno_university, rennes_university)
    if not students:
        print("❌ Nessuno studente registrato.")
        cleanup_all_data()
        exit()

    authenticated_students = phase_2_enrollment_and_data(students, salerno_university)
    if not authenticated_students:
        print("❌ Nessuno studente autenticato.")
        cleanup_all_data()
        exit()

    if len(authenticated_students) < 2:
        print("⚠️ Servono almeno 2 studenti autenticati.")
        cleanup_all_data()
        exit()

    student_for_erasmus_revoke = authenticated_students[0]
    student_for_academic_revoke = authenticated_students[1]

    phase_3_issue_erasmus_credential_unisa(authenticated_students, salerno_university)
    phase_4_request_grades_rennes(authenticated_students, rennes_university, salerno_university)
    presentation = phase_5_selective_presentation(authenticated_students, salerno_university, rennes_university)
    phase_6_revoke_multiple_credentials(student_for_erasmus_revoke, student_for_academic_revoke, salerno_university, rennes_university)
    phase_7_re_presentation_after_revocation(student_for_erasmus_revoke, student_for_academic_revoke, presentation, salerno_university, rennes_university)
