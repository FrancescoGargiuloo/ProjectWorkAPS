import os, base64
import json
import uuid
from Student import Student
from UniversitySalerno import UniversitySalerno
from UniversityRennes import UniversityRennes
import shutil
BASE_DIR = os.path.dirname(__file__)
REGISTERED_STUDENTS_FOR_CLEANUP = []


def _delete_dir_if_exists(dir_path):
    """Elimino una directory e tutto il suo contenuto se esiste."""
    if os.path.exists(dir_path) and os.path.isdir(dir_path):
        shutil.rmtree(dir_path)
        print(f"Eliminata directory: {dir_path}")

def _delete_file_if_exists(file_path):
    """Cancello il file solo se esiste (evito errori inutili)."""
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"Eliminato file: {file_path}")


# --- Pulizia totale dei dati generati ---
def cleanup_all_data():
    """
    Cancello tutti i file creati dal programma: database, chiavi, DIDs, credenziali ecc.
    """
    print("\n" + "=" * 50)
    print("==== FASE DI PULIZIA DATI ====")
    print("=" * 50)
    DB_DIR = os.path.join(BASE_DIR, "database")
    _delete_dir_if_exists(DB_DIR)

    KEY_DIR = os.path.join(BASE_DIR, "keys")
    _delete_dir_if_exists(KEY_DIR)

    UNISA_DIR = os.path.join(BASE_DIR, "unisa")
    _delete_dir_if_exists(UNISA_DIR)

    RENNES_DIR = os.path.join(BASE_DIR, "rennes")
    _delete_dir_if_exists(RENNES_DIR)

    for student_data in REGISTERED_STUDENTS_FOR_CLEANUP:
        username = student_data["username"]
        wallet_folder = os.path.join(BASE_DIR, f"wallet-{username}")
        _delete_dir_if_exists(wallet_folder)

    _delete_file_if_exists(os.path.join(BASE_DIR, "shared_blockchain.json"))
    _delete_file_if_exists(os.path.join(BASE_DIR, "revocation_registry.json"))

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
    universities = [salerno_university, rennes_university]
    distribute_dids_among_trusted_folders(universities)
    return salerno_university, rennes_university

def distribute_dids_among_trusted_folders(universities):
    """
    Per ogni università, copia i DID delle altre università nella sua cartella trusted_did_folder.
    """
    for uni_target in universities:
        os.makedirs(uni_target.trusted_did_folder, exist_ok=True)

        for uni_source in universities:
            if uni_source == uni_target:
                continue

            # Lista dei DID nella did_folder della uni_source
            did_files = [f for f in os.listdir(uni_source.did_folder) if f.endswith("_did.json")]

            for did_file in did_files:
                src = os.path.join(uni_source.did_folder, did_file)
                dst = os.path.join(uni_target.trusted_did_folder, did_file)
                shutil.copy2(src, dst)

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
        if university_salerno.register_student(user_id, username, password, first_name, last_name):
            university_salerno.assign_did_to_student(user_id, student_obj.did, student_obj.get_public_key())
            print(f"✅ {username} registrato a UniSA")
        else:
            print(f"❌ Errore a UniSA per {username}")
            continue

        # Registrazione anche a Rennes
        if university_rennes.register_student(user_id, username, password, first_name, last_name):
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
        result = university_salerno.generate_erasmus_credential(student)
        if result:  # Solo se la credenziale è stata realmente generata
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

        if not university_rennes.verify_erasmus_credential(erasmus_cred, student):
            print("❌ Erasmus non valida. Revoca inviata a UniSA.")
            university_salerno.revocate_credential(erasmus_cred)
            continue

        result = university_rennes.generate_academic_credential(student, all_exams_data)
        if result:
            print("✅ Credenziale accademica generata")

    print("\n✅ FASE 4 completata.")

def phase_5_selective_presentation(authenticated_students, university_salerno, university_rennes):
    print("\n" + "=" * 50)
    print("==== FASE 5: PRESENTAZIONE SELETTIVA ====")
    print("=" * 50)

    for student in authenticated_students:
        print(f"\n➡️ Generazione presentazione per {student.username}")
        try:
            # ✅ UniSA genera un nonce per lo studente usando il metodo dedicato
            nonce = university_salerno.generate_challenge(student.username)
            print(f"🔑 UniSA ha generato il nonce: {nonce}")

            # ✅ Lo studente usa il nonce ricevuto
            student.generate_selective_presentation_automated(nonce_received=nonce)
            print("✅ Presentazione generata")

            with open(os.path.join(student.get_wallet_path(),"credentials", f"{student.username}_vp.json")) as f:
                presentation = json.load(f)

            print(f"➡️ UniSA verifica la presentazione di {student.username}")
            result = university_salerno.verify_selective_presentation(presentation, student, expected_nonce=nonce)

            if result:
                print("✅ Presentazione valida")
            else:
                print("❌ Presentazione non valida. Invio revoca a Rennes.")
                vc = presentation.get("verifiableCredential")
                if not vc:
                    print("❌ VP non contiene una credenziale verificabile valida.")
                university_rennes.revocate_credential(vc)
        except Exception as e:
            print(f"❌ Errore con presentazione: {e}")

    print("\n✅ FASE 5 completata.")

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
def phase_7_re_presentation_after_revocation(erasmus_student, academic_student, university_salerno, university_rennes):

    print("\n" + "=" * 50)
    print("==== FASE 7: RIUTILIZZO DOPO REVOCA ====")
    print("=" * 50)

    # Erasmus
    print(f"\n➡️ {erasmus_student.username} riprova a usare la credenziale Erasmus")
    erasmus_cred = erasmus_student.load_erasmus_credential()
    if not erasmus_cred:
        print("❌ Nessuna credenziale Erasmus trovata")
    else:
        if not university_rennes.verify_erasmus_credential(erasmus_cred, erasmus_student):
            print("✅ Revoca Erasmus funzionante (non è più valida)")
        else:
            print("⚠️ ERRORE: Erasmus ancora valida dopo revoca!")

    # Accademica
    print(f"\n➡️ {academic_student.username} riprova a usare la presentazione accademica")
    path = os.path.join(academic_student.get_wallet_path(), "credentials", f"{academic_student.username}_vp.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            presentation = json.load(f)
    except FileNotFoundError:
        print("❌ Presentazione accademica non trovata")
        return

    # Genera il nonce/challenge per il DID dello studente
    nonce = university_salerno.generate_challenge(academic_student.username)
    print(f"🔑 UniSA ha generato il nonce: {nonce}")

    if not university_salerno.verify_selective_presentation(presentation, academic_student, expected_nonce=nonce):
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
    phase_5_selective_presentation(authenticated_students, salerno_university, rennes_university)
    phase_6_revoke_multiple_credentials(student_for_erasmus_revoke, student_for_academic_revoke, salerno_university,
                                        rennes_university)
    phase_7_re_presentation_after_revocation(student_for_erasmus_revoke, student_for_academic_revoke,
                                             salerno_university, rennes_university)
    #cleanup_all_data()
