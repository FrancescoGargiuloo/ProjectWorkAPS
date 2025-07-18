from Student import Student
from UniversitySalerno import UniversitySalerno
import json, os
from UniversityRennes import UniversityRennes

BASE_DIR = os.path.dirname(__file__)
CRED_FOLDER = os.path.join(BASE_DIR, "credential")


def pre_game():
    print("==== [ UNIVERSITÀ ] ====")
    university = UniversitySalerno()

    print("\n==== [ LOGIN O REGISTRAZIONE STUDENTE ] ====")
    username = input("Inserisci username: ").strip()
    password = input("Inserisci password: ").strip()

    # Prova ad autenticare lo studente
    # user_data conterrà 'id', 'username', 'first_name', 'last_name', 'did', 'public_key_pem'
    user_data = university.authenticate_student(username, password)

    #current_student_id = None  # Questo sarà l'ID dello studente autenticato/registrato

    if not user_data:
        print("Utente non trovato o password errata. Registrazione in corso...")
        return
        #first_name = input("Inserisci il tuo nome: ").strip()
        #last_name = input("Inserisci il tuo cognome: ").strip()

        # Genero ID univoco per il nuovo utente
        #user_id = str(uuid.uuid4())

        # Creo l'oggetto Student. Questo oggetto GENERERÀ le chiavi e il DID per la prima volta.
        # È l'oggetto che useremo per firmare.
        #student_obj = Student(username=username, password=password,
                              #first_name=first_name, last_name=last_name)

        # Registro lo studente nel DB dell'università, salvando il suo ID, username, password HASH,
        # nome, cognome e la CHIAVE PUBBLICA generata dallo studente.
        # Il DID viene anche salvato qui, anche se in questo momento è ancora "did:web:username.localhost".
        # La university NON decide il DID, lo studente lo porta.
        #success = university.register_student(user_id, username, password, first_name, last_name,
                                              #student_obj.get_public_key())

        #if not success:
            #print("Errore durante la registrazione.")
            #return

        # Ora che l'utente è stato registrato nel DB dell'uni con la sua chiave pubblica,
        # Aggiorniamo anche il suo DID nel DB dell'uni (se non lo avevamo fatto prima in register_student)
        # Questo garantisce che l'università abbia il DID corretto associato all'ID utente.
        #university.assign_did_to_student(user_id, student_obj.did,
                                         #student_obj.get_public_key())  # Assicurati di passare anche la chiave pubblica qui se necessario

        #print(f"Utente '{username}' registrato con DID: {student_obj.did}")
        #current_student_id = user_id  # Memorizza l'ID per le operazioni successive

    else:
        print("Autenticazione riuscita.")
        current_student_id = user_data["id"]  # Recupera l'ID utente dal database dell'università

        # Ri-crea l'oggetto Student. È FONDAMENTALE che questo oggetto carichi le chiavi private
        # persistenti associate a questo utente, altrimenti non potrà firmare correttamente.
        # Assumiamo che il costruttore di Student gestisca il caricamento delle chiavi.
        student_obj = Student(
            username=username,
            password=password,  # La password è usata per derivare la chiave per decifrare la chiave privata
            first_name=user_data.get("first_name"),
            last_name=user_data.get("last_name")
        )

        # Assicurati che il DID dell'oggetto Student sia quello recuperato dal DB dell'università
        student_obj.did = user_data.get("did")
        print("\n==== [ VERIFICA DID STUDENTE (dopo Auth, prima del Challenge-Response) ] ====")

        # Simulazione: Lo studente "invia" il suo DID all'università
        student_did_from_client = student_obj.did
        print(f"Studente (simulazione): Invio il mio DID: {student_did_from_client}")

        # L'università "riceve" il DID dallo studente e lo confronta con quello nel suo DB
        # Recupera il DID dal suo database per l'utente appena autenticato
        did_from_university_db = user_data.get("did")  # user_data è già stato recuperato

        if student_did_from_client == did_from_university_db:
            print("Università: DID dello studente ricevuto e corrisponde a quello nel nostro database. Proseguo.")
        else:
            print("Università: ATTENZIONE! DID dello studente inviato non corrisponde al nostro database.")
            print(f"  DID da Cliente: {student_did_from_client}")
            print(f"  DID da DB Università: {did_from_university_db}")
            print("Autenticazione DID fallita. Accesso negato.")
            return  # Termina la funzione se i DID non corrispondono
        # --- Fine Verifica DID Studente ---

        # Anche se l'oggetto Student dovrebbe già conoscere il suo DID dalle sue chiavi,
        # per coerenza potresti volerlo impostare dal user_data recuperato.
        student_obj.did = user_data.get("did")  # Assicurati che il DID dell'oggetto Student sia quello recuperato

    print("\n==== [ CHALLENGE-RESPONSE ] ====")

    # Università genera un challenge per lo studente, usando l'ID autenticato.
    # L'università recupera il DID dello studente dal suo DB interno.
    challenge = university.generate_challenge(current_student_id)
    if not challenge:
        print("Errore: Impossibile generare challenge per l'utente autenticato.")
        return

    print(f"Challenge generato: {challenge}")

    # Lo studente firma il challenge con la PROPRIA chiave privata
    # (quella che l'oggetto student_obj ha caricato/generato).
    signature = student_obj.sign(challenge)
    print(f"Firma generata: {signature[:32]}...")

    # L'università verifica la firma del challenge.
    # Riceve solo l'ID dello studente e la firma.
    # Recupera il DID e la chiave pubblica dallo user_id autonomamente dal suo DB.
    verification = university.verify_challenge_response(
        user_id=current_student_id,
        signature_b64=signature
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
            # Per generate_erasmus_credential, hai ancora bisogno dell'oggetto 'student_obj'
            # per accedere ai suoi dati (nome, cognome) e al suo DID per la VC.
            university.generate_erasmus_credential(student_obj)
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


def rennes():
    print("==== [ UNIVERSITÉ DE RENNES ] ====")
    university = UniversityRennes()

    username = input("Username studente: ").strip()
    first_name = input("Nome: ").strip()
    last_name = input("Cognome: ").strip()
    did = f"did:web:{username}.localhost"

    # COME AVVIENE L'AUTH??????
    student = Student(username=username, password="*", first_name=first_name, last_name=last_name)
    student.did = did  # Forziamo il DID per simulare

    # 1. Carica Erasmus Credential, (WALLET)
    erasmus_cred = load_erasmus_credential(username) # inviata dall'utente e non caricata direttamente
    if not erasmus_cred:
        return

    # 2. Verifica firma Erasmus VC
    if not university.verify_erasmus_credential(erasmus_cred):
        print("❌ Erasmus Credential NON valida.")
        return

    print("✅ Erasmus Credential verificata con successo.")
    # 3. Inserimento esami e generazione Academic VC
    exams = university.collect_exam_data() # vengono direttamente caricati
    if not exams:
      print("⚠️ Nessun esame inserito.")
      return
    university.generate_academic_credential(student, exams)
    student.generate_selective_presentation_from_terminal()


def verify_presentation_at_origin_university():
    print("\n==== [ UNIVERSITÀ ORIGINE - VERIFICA PRESENTATION ] ====")
    university = UniversitySalerno()

    username = input("Username studente: ").strip()

    # Forza dati base (nome, cognome e DID)
    did = f"did:web:{username}.localhost"
    student = Student(username=username, password="*", first_name="", last_name="")
    student.did = did

    # Carica anche la Selective Presentation
    path = os.path.join(CRED_FOLDER, f"{username}_vp.json")
    try:
        with open(path, "r") as f:
            presentation = json.load(f)
    except FileNotFoundError:
        print("❌ Presentazione non trovata.")
        return

    result = university.verify_selective_presentation(presentation)
    if result:
        print("✅ Presentazione verificata correttamente.")
    else:
        print("❌ Presentazione NON valida.")

if __name__ == "__main__":
    pre_game()
    print("\n==== FASE PRE GAME COMPLETATA ====")
    print("LO STUDENTE SI PRESENTA ALL'UNIVERSITà OSPITANTE E COMPLETA IL PERCORSO DI STUDIO")
    while True:
        print("\n==== [ MENU ] ====")
        print("1. Esci")
        print("2. Richiedi Attestazione Voti")
        print("3. Presenta VP")
        choice = input("Seleziona un'opzione: ").strip()

        if choice == "1":
            break
        elif choice == "2":
            rennes()
        elif choice == "3":
            verify_presentation_at_origin_university()
        else:
            print("Opzione non valida.")
