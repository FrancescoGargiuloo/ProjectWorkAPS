
import os
import json
import uuid
from Student import Student
from UniversitySalerno import UniversitySalerno
from UniversityRennes import UniversityRennes

BASE_DIR = os.path.dirname(__file__)
DB_FOLDER = os.path.join(BASE_DIR, "database")
KEY_FOLDER = os.path.join(BASE_DIR, "keys")
CRED_FOLDER = os.path.join(BASE_DIR, "credential")
DID_FOLDER = os.path.join(BASE_DIR, "DID")

# Ensure folders exist
os.makedirs(DB_FOLDER, exist_ok=True)
os.makedirs(KEY_FOLDER, exist_ok=True)
os.makedirs(CRED_FOLDER, exist_ok=True)
os.makedirs(DID_FOLDER, exist_ok=True)

# List to keep track of registered students for cleanup
REGISTERED_STUDENTS_FOR_CLEANUP = []


# --- Helper functions for cleanup ---
def _delete_file_if_exists(file_path):
    """Deletes a file if it exists."""
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"🗑️ Deleted: {file_path}")


def cleanup_all_data():
    """
    Function to clean up all generated databases, keys, DIDs, and credentials.
    """
    print("\n" + "=" * 50)
    print("==== DATA CLEANUP PHASE ====")
    print("=" * 50)

    # Database cleanup
    _delete_file_if_exists(os.path.join(DB_FOLDER, "unisa_users.json"))
    _delete_file_if_exists(os.path.join(DB_FOLDER, "rennes_users.json"))

    _delete_file_if_exists(os.path.join(BASE_DIR, "revocation_registry.json"))
    _delete_file_if_exists(os.path.join(BASE_DIR, "shared_blockchain.json"))

    # Cleanup of DB encryption keys (if present)
    _delete_file_if_exists(os.path.join(KEY_FOLDER, "unisa_users_encryption.key"))
    _delete_file_if_exists(os.path.join(KEY_FOLDER, "rennes_users_encryption.key"))

    # Cleanup of university DIDs and keys
    _delete_file_if_exists(os.path.join(KEY_FOLDER, "unisa_priv.pem"))
    _delete_file_if_exists(os.path.join(KEY_FOLDER, "unisa_pub.pem"))
    _delete_file_if_exists(os.path.join(DID_FOLDER, "unisa_it_did.json"))

    _delete_file_if_exists(os.path.join(KEY_FOLDER, "rennes_priv.pem"))
    _delete_file_if_exists(os.path.join(KEY_FOLDER, "rennes_pub.pem"))
    _delete_file_if_exists(os.path.join(DID_FOLDER, "rennes_it_did.json"))

    # Cleanup of student keys, DIDs, and credentials
    for student_data in REGISTERED_STUDENTS_FOR_CLEANUP:
        username = student_data["username"]
        user_id = student_data["user_id"]

        # Cleanup student keys (format: username_priv.pem)
        _delete_file_if_exists(os.path.join(KEY_FOLDER, f"{username}_priv.pem"))
        _delete_file_if_exists(os.path.join(KEY_FOLDER, f"{username}_pub.pem"))

        # Cleanup student DID (format: username_user_id_localhost_did.json)
        did_filename = f"{username.replace('.', '_')}_{user_id}_localhost_did.json"
        _delete_file_if_exists(os.path.join(DID_FOLDER, did_filename))

        # Cleanup student credentials
        _delete_file_if_exists(os.path.join(CRED_FOLDER, f"{username}_erasmus_credential.json"))
        _delete_file_if_exists(os.path.join(CRED_FOLDER, f"{username}_academic_credential.json"))
        _delete_file_if_exists(os.path.join(CRED_FOLDER, f"{username}_vp.json"))
        # Revoked credentials (may or may not be generated)
        _delete_file_if_exists(os.path.join(CRED_FOLDER, f"{username}_revoked_erasmus_credential.json"))
        _delete_file_if_exists(os.path.join(CRED_FOLDER, f"{username}_revoked_academic_credential.json"))

    print("\n✅ Cleanup completed.")
    print("=" * 50)


# --- PHASE 0: Initialization ---
def phase_0_initialization():
    """
    Initializes university instances.
    """
    print("\n" + "=" * 50)
    print("==== PHASE 0: INITIALIZATION ====")
    print("=" * 50)
    salerno_university = UniversitySalerno()
    rennes_university = UniversityRennes()
    print("✅ University of Salerno and University of Rennes initialized.")
    return salerno_university, rennes_university


# --- PHASE 1: Student Creation ---
def phase_1_student_creation(university_salerno: UniversitySalerno, university_rennes: UniversityRennes):
    """
    Creates and registers 5 fictitious students in both databases.
    """
    print("\n" + "=" * 50)
    print("==== PHASE 1: STUDENT CREATION AND REGISTRATION ====")
    print("=" * 50)

    students_data = [
        {"username": "mario.rossi", "password": "Password1!", "first_name": "Mario", "last_name": "Rossi"},
        {"username": "anna.bianchi", "password": "Password2!", "first_name": "Anna", "last_name": "Bianchi"},
        {"username": "luca.verdi", "password": "Password3!", "first_name": "Luca", "last_name": "Verdi"},
        {"username": "giulia.neri", "password": "Password4!", "first_name": "Giulia", "last_name": "Neri"},
        {"username": "marco.gialli", "password": "Password5!", "first_name": "Marco", "last_name": "Gialli"},
    ]

    registered_student_objects = []

    for i, data in enumerate(students_data):
        username = data["username"]
        password = data["password"]
        first_name = data["first_name"]
        last_name = data["last_name"]
        user_id = str(uuid.uuid4())  # Unique ID for each student

        print(f"\nAttempting to register student {i + 1}: {username}")

        # Create the Student object which generates keys and DID
        student_obj = Student(username=username, password=password, user_id=user_id,
                              first_name=first_name, last_name=last_name)

        # Registration at University of Salerno
        success_salerno = university_salerno.register_student(
            user_id, username, password, first_name, last_name, student_obj.get_public_key()
        )
        if success_salerno:
            university_salerno.assign_did_to_student(user_id, student_obj.did, student_obj.get_public_key())
            print(f"✅ Student '{username}' successfully registered with UniSA.")
        else:
            print(f"❌ Error registering '{username}' with UniSA.")
            continue

        # Registration at University of Rennes (simulating the same students)
        success_rennes = university_rennes.register_student(
            user_id, username, password, first_name, last_name, student_obj.get_public_key()
        )
        if success_rennes:
            university_rennes.assign_did_to_student(user_id, student_obj.did, student_obj.get_public_key())
            print(f"✅ Student '{username}' successfully registered with Rennes.")
        else:
            print(f"❌ Error registering '{username}' with Rennes.")
            continue

        registered_student_objects.append(student_obj)
        # Update to include necessary data to construct the DID filename correctly for cleanup
        REGISTERED_STUDENTS_FOR_CLEANUP.append({
            "username": username,
            "user_id": user_id,
            "first_name": first_name,
            "last_name": last_name
        })

    print("\n✅ PHASE 1 completed: All students have been created and registered in the databases.")
    return registered_student_objects


# --- PHASE 2: Enrollment and Data (Challenge-Response) ---
def phase_2_enrollment_and_data(students: list[Student], university_salerno: UniversitySalerno):
    """
    Simulates challenge-response authentication for each student with UniSA.
    """
    print("\n" + "=" * 50)
    print("==== PHASE 2: ENROLLMENT AND DATA (CHALLENGE-RESPONSE WITH UNISA) ====")
    print("=" * 50)

    authenticated_students = []
    for student_obj in students:
        print(f"\nAttempting authentication for {student_obj.username} with UniSA...")

        # 1. Retrieve user data from UniSA DB to simulate initial authentication
        user_data = university_salerno.authenticate_student(student_obj.username, student_obj.password)

        if not user_data:
            print(
                f"❌ Authentication failed for {student_obj.username} (incorrect password or user not found after registration)."
            )
            continue

        # Verify student DID
        student_did_from_client = student_obj.did
        did_from_university_db = user_data.get("did")

        if student_did_from_client == did_from_university_db:
            print(f"✅ UniSA: DID for {student_obj.username} matches. Proceeding.")
        else:
            print(
                f"❌ UniSA: ATTENTION! DID for {student_obj.username} does not match ({student_did_from_client} vs {did_from_university_db}). Skipping."
            )
            continue

        # Challenge-Response
        challenge = university_salerno.generate_challenge(student_obj.user_id)
        if not challenge:
            print(f"❌ Error: Unable to generate challenge for {student_obj.username}.")
            continue

        signature = student_obj.sign(challenge)
        verification = university_salerno.verify_challenge_response(
            user_id=student_obj.user_id,
            signature_b64=signature
        )

        if verification["status"] == "ok":
            print(f"✅ Challenge-Response for {student_obj.username} successful with UniSA.")
            authenticated_students.append(student_obj)
        else:
            print(f"❌ Challenge-Response verification for {student_obj.username} failed: {verification['message']}")
    print("\n✅ PHASE 2 completed.")
    return authenticated_students


# --- PHASE 3: Issuance of Erasmus Eligibility Credential at UniSA ---
def phase_3_issue_erasmus_credential_unisa(authenticated_students: list[Student],
                                           university_salerno: UniversitySalerno):
    """
    Each authenticated student requests the Erasmus credential from UniSA.
    """
    print("\n" + "=" * 50)
    print("==== PHASE 3: ISSUANCE OF ERASMUS ELIGIBILITY CREDENTIAL AT UNISA ====")
    print("=" * 50)

    for student_obj in authenticated_students:
        print(
            f"\nStudent {student_obj.username}: Requesting Erasmus eligibility credential from the University of Salerno."
        )
        university_salerno.generate_erasmus_credential(student_obj)
        print(
            f"✅ Erasmus credential request for {student_obj.username} completed. Check the 'credential' folder."
        )
    print("\n✅ PHASE 3 completed: Erasmus credentials issued for all authenticated students.")


# --- PHASE 4: Request for Grade Attestation from Rennes ---
def phase_4_request_grades_rennes(authenticated_students: list[Student], university_rennes: UniversityRennes,
                                  university_salerno: UniversitySalerno):
    """
    Interaction of each authenticated student with Rennes to obtain grade attestation.
    Includes verification of the Erasmus credential by Rennes.
    """
    print("\n" + "=" * 50)
    print("==== PHASE 4: REQUEST FOR GRADE ATTESTATION FROM RENNES ====")
    print("=" * 50)

    # Load exams from exams.json file
    all_exams_data = university_rennes.collect_exam_data()
    if not all_exams_data:
        print("❌ Could not load exam data from exams.json. Skipping Phase 4.")
        return

    for student_obj in authenticated_students:
        print(f"\nStudent {student_obj.username}: Interacting with University of Rennes.")

        # Student already has trusted DIDs (Rennes, UniSA) initialized.
        # No need to add them here.

        # Challenge-response with Rennes (even if the student is already registered)
        print(f"Rennes: Generating challenge for {student_obj.username}...")
        challenge = university_rennes.generate_challenge(student_obj.user_id)
        if not challenge:
            print(f"❌ Error generating challenge for Rennes user: {student_obj.username}.")
            continue

        signature = student_obj.sign(challenge)
        verification = university_rennes.verify_challenge_response(student_obj.user_id, signature)
        if verification["status"] != "ok":
            print(
                f"❌ Challenge-response verification failed with Rennes for {student_obj.username}: {verification['message']}"
            )
            continue

        print(f"✅ Challenge-response successful with Rennes for {student_obj.username}.")

        print(f"Student {student_obj.username}: Sending Erasmus credential to University of Rennes...")
        erasmus_cred = student_obj.load_erasmus_credential()
        if not erasmus_cred:
            print(f"❌ Erasmus credential not found for {student_obj.username}. Request it from UniSA first.")
            continue

        if not university_rennes.verify_erasmus_credential(erasmus_cred):
            print(
                f"❌ Erasmus credential for {student_obj.username} is NOT valid. Sending Revocation Communication to Salerno."
            )
            university_salerno.revocate_credential(erasmus_cred)
            continue

        print(f"✅ Erasmus credential for {student_obj.username} successfully verified by Rennes.")

        # Pass the exam data loaded from the file
        university_rennes.generate_academic_credential(student_obj, all_exams_data)
        print(f"✅ Academic Credential issued by Rennes for {student_obj.username}.")
    print("\n✅ PHASE 4 completed.")


# --- PHASE 5: Selective Presentation ---
def phase_5_selective_presentation(authenticated_students: list[Student], university_salerno: UniversitySalerno,
                                   university_rennes: UniversityRennes):
    """
    Each student generates and presents their Verifiable Presentation to the University of Salerno.
    """
    print("\n" + "=" * 50)
    print("==== PHASE 5: SELECTIVE PRESENTATION ====")
    print("=" * 50)

    for student_obj in authenticated_students:
        print(f"\nStudent {student_obj.username}: Generating selective presentation...")
        try:
            student_obj.generate_selective_presentation_automated(
                target_university_did=university_salerno.did  # Use the university's direct DID attribute
            )

            print(f"✅ Selective presentation generated for {student_obj.username}.")

            # University of Salerno verifies the presentation
            path = os.path.join(CRED_FOLDER, f"{student_obj.username}_vp.json")
            with open(path, "r") as f:
                presentation = json.load(f)
            print(
                f"University of Salerno: Received presentation from {student_obj.username}. Initiating verification...")

            result = university_salerno.verify_selective_presentation(presentation)
            if result:
                print(f"✅ Presentation for {student_obj.username} successfully verified by the University of Salerno.")
            else:
                print(
                    f"❌ Presentation for {student_obj.username} NOT valid for the University of Salerno. Sending revocation communication to Rennes."
                )
                university_rennes.revocate_credential(presentation)
        except Exception as e:
            print(
                f"❌ Error during selective presentation generation or verification for {student_obj.username}: {e}"
            )
    print("\n✅ PHASE 5 completed.")

### PHASE 6: Revocation of Credentials for Different Students

def phase_6_revoke_multiple_credentials(erasmus_student: Student, academic_student: Student,
                                        university_salerno: UniversitySalerno, university_rennes: UniversityRennes):
    """
    Performs revocation of different credentials for different students.
    """
    print("\n" + "=" * 50)
    print(f"==== PHASE 6: REVOCATION OF MULTIPLE CREDENTIALS (DIFFERENT STUDENTS) ====")
    print("=" * 50)

    # --- Revoke Erasmus Eligibility Credential for the first student ---
    print(
        f"\nRequesting revocation of the **Eligibility Erasmus** credential for {erasmus_student.username} from UniSA...")
    erasmus_cred = erasmus_student.load_erasmus_credential()
    if erasmus_cred:
        # The Erasmus credential is issued by UniSA, so revocation happens via UniSA
        university_salerno.revocate_credential(erasmus_cred)
        print(f"✅ Eligibility Erasmus credential of {erasmus_student.username} revoked by UniSA.")
    else:
        print(f"⚠️ Eligibility Erasmus credential for {erasmus_student.username} not found, unable to revoke.")

    # --- Revoke Academic Credential for the second student ---
    print(f"\nRequesting revocation of the **Academic Credential** for {academic_student.username} from Rennes...")
    academic_cred = academic_student.load_academic_credential()
    if academic_cred:
        # The Academic credential is issued by Rennes, so revocation happens via Rennes
        university_rennes.revocate_credential(academic_cred)
        print(f"✅ Academic Credential of {academic_student.username} revoked by Rennes.")
    else:
        print(f"⚠️ Academic Credential for {academic_student.username} not found, unable to revoke.")

    print("\n✅ PHASE 6 completed.")


### PHASE 7: Attempted Re-presentation after Revocations

def phase_7_re_presentation_after_revocation(erasmus_student: Student, academic_student: Student,
                                             university_salerno: UniversitySalerno,
                                             university_rennes: UniversityRennes):
    """
    Students attempt to re-present credentials after revocations.
    """
    print("\n" + "=" * 50)
    print("==== PHASE 7: ATTEMPTED RE-PRESENTATION AFTER REVOCATION ====")
    print("=" * 50)

    # Attempt to re-present the Erasmus credential (for the first student)
    print(f"\nStudent {erasmus_student.username}: Attempting to re-present the **Eligibility Erasmus Credential**.")
    erasmus_cred = erasmus_student.load_erasmus_credential()
    if not erasmus_cred:
        print(f"❌ Erasmus credential not found for {erasmus_student.username}. Unable to re-present.")
    else:
        # Attempt to re-present the Erasmus credential to Rennes (which will verify it with UniSA)
        print(
            f"Student {erasmus_student.username}: Re-sending the Erasmus credential to the University of Rennes for verification."
        )
        if not university_rennes.verify_erasmus_credential(erasmus_cred):
            print(
                f"❌ The Erasmus credential of {erasmus_student.username} was detected as NOT valid by Rennes (as expected after revocation)."
            )
            # Simulate another revocation communication to UniSA even if already revoked
            university_salerno.revocate_credential(erasmus_cred)
        else:
            print(
                f"⚠️ ERROR: The Erasmus credential of {erasmus_student.username} was unexpectedly verified as valid after revocation."
            )

    # Attempt to re-present the Academic credential (for the second student)
    print(f"\nStudent {academic_student.username}: Attempting to re-present the **Academic Credential**.")
    academic_cred = academic_student.load_academic_credential()
    if not academic_cred:
        print(f"❌ Academic Credential not found for {academic_student.username}. Unable to re-present.")
    else:
        print(
            f"Student {academic_student.username}: Attempting to re-present the Academic Credential (verification simulation).")

        # Extract revocation status details from the academic credential
        status_info = academic_cred.get("credentialStatus", {})
        namespace = status_info.get("namespace")
        list_id = status_info.get("revocationList")
        revocation_key = status_info.get("revocationKey")

        if namespace and list_id and revocation_key:
            # Use the is_revoked() method of Rennes's revocation registry
            if university_rennes.revocation_registry.is_revoked(namespace, list_id, revocation_key):
                print(
                    f"❌ The Academic Credential of {academic_student.username} was detected as NOT valid by Rennes (as expected after revocation).")
            else:
                print(
                    f"⚠️ ERROR: The Academic Credential of {academic_student.username} was unexpectedly verified as valid after revocation.")
        else:
            print(
                f"❌ Unable to verify revocation status: Insufficient information in the academic credential for {academic_student.username}.")

    print("\n✅ PHASE 7 completed.")

# --- Automated Flow Execution ---
if __name__ == "__main__":
    # Initial cleanup to ensure a clean state before execution
    cleanup_all_data()

    salerno_university, rennes_university = phase_0_initialization()

    # PHASE 1
    students = phase_1_student_creation(salerno_university, rennes_university)
    if not students:
        print("❌ No students registered. Terminating script.")
        cleanup_all_data()
        exit()

    # PHASE 2
    authenticated_students = phase_2_enrollment_and_data(students, salerno_university)
    if not authenticated_students:
        print("❌ No students authenticated. Terminating script.")
        cleanup_all_data()
        exit()

    # Ensure at least two authenticated students for separate revocation phases
    if len(authenticated_students) < 2:
        print(
            "⚠️ At least two authenticated students are required to proceed with separate revocation phases. Terminating script.")
        cleanup_all_data()
        exit()

    student_for_erasmus_revoke = authenticated_students[0]  # Mario Rossi
    student_for_academic_revoke = authenticated_students[1]  # Anna Bianchi

    # PHASE 3
    phase_3_issue_erasmus_credential_unisa(authenticated_students, salerno_university)

    # PHASE 4
    phase_4_request_grades_rennes(authenticated_students, rennes_university, salerno_university)

    # PHASE 5
    phase_5_selective_presentation(authenticated_students, salerno_university, rennes_university)

    # PHASE 6 - Multiple revocations for different students
    phase_6_revoke_multiple_credentials(student_for_erasmus_revoke, student_for_academic_revoke, salerno_university,
                                        rennes_university)
    # PHASE 7 - Re-presentation after Revocation
    phase_7_re_presentation_after_revocation(student_for_erasmus_revoke, student_for_academic_revoke,
                                             salerno_university, rennes_university)

    cleanup_all_data()
