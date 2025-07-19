import os, json, base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime
from MerkleTree import hash_leaf, build_merkle_proof # Assicurati che build_merkle_proof sia correttamente implementata in MerkleTree.py
import uuid

BASE_DIR = os.path.dirname(__file__)
DID_FOLDER = os.path.join(BASE_DIR, "DID")
CREDENTIAL_FOLDER = os.path.join(BASE_DIR, "credential")
KEYS_FOLDER = os.path.join(BASE_DIR, "keys")


class Student:
    """
    Rappresenta uno studente, gestendo la generazione di chiavi,
    documenti DID, la firma di messaggi e la generazione di presentazioni selettive.
    """
    def __init__(self, username, password, user_id, first_name=None, last_name=None):
        """
        Inizializza l'oggetto Student.
        :param username: Username dello studente.
        :param password: Password dello studente (usata per scopi interni, es. derivazione chiave per crittografia).
        :param first_name: Nome dello studente.
        :param last_name: Cognome dello studente.
        """
        self.username = username
        self.password = password
        self.first_name = first_name
        self.last_name = last_name
        self.user_id = user_id
        self.did = f"did:web:{username}.{user_id}.localhost"
        self.priv_path = os.path.join(KEYS_FOLDER, f"{username}_priv.pem")
        self.pub_path = os.path.join(KEYS_FOLDER, f"{username}_pub.pem")

        # Assicurati che le cartelle esistano
        os.makedirs(KEYS_FOLDER, exist_ok=True)
        os.makedirs(DID_FOLDER, exist_ok=True)
        os.makedirs(CREDENTIAL_FOLDER, exist_ok=True)

        if not os.path.exists(self.priv_path):
            self._generate_keypair()

        self._update_did_document()

    def _generate_keypair(self):
        """
        Genera una coppia di chiavi RSA (privata e pubblica) e le salva in formato PEM.
        Le chiavi vengono generate solo se non esistono già.
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        with open(self.priv_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption() # Per semplicità, nessuna crittografia della chiave privata
            ))

        with open(self.pub_path, "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print(f"Nuove chiavi generate per lo studente {self.username}.")

    def get_public_key(self):
        """
        Restituisce la chiave pubblica dello studente in formato PEM.
        :return: La chiave pubblica in formato stringa PEM.
        """
        # Assicurati che il file esista prima di tentare di leggerlo
        if not os.path.exists(self.pub_path):
            self._generate_keypair() # Genera se non esiste
        with open(self.pub_path, "rb") as f:
            return f.read().decode()

    def _update_did_document(self):
        """
        Crea o aggiorna il file DID dello studente con la chiave pubblica corrente.
        Il nome del file DID è basato sul DID dello studente.
        """
        did_doc = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": self.did,
            "verificationMethod": [{
                "id": f"{self.did}#key-1",
                "type": "RsaVerificationKey2018",
                "controller": self.did,
                "publicKeyPem": self.get_public_key()
            }]
        }
        filename = self.did.split(":")[-1].replace(".", "_") + "_did.json"
        path = os.path.join(DID_FOLDER, filename)
        with open(path, "w") as f:
            json.dump(did_doc, f, indent=2)
        print(f"Documento DID per {self.username} salvato in {path}")


    def sign(self, message: str) -> str:
        """
        Firma un messaggio con la chiave privata dello studente.
        :param message: Il messaggio da firmare.
        :return: La firma del messaggio in formato base64.
        :raises Exception: Se la chiave privata non può essere caricata.
        """
        try:
            with open(self.priv_path, "rb") as f:
                priv = serialization.load_pem_private_key(f.read(), password=None) # Nessuna password per semplicità
        except FileNotFoundError:
            raise Exception(f"Chiave privata non trovata per {self.username}. Impossibile firmare.")
        except Exception as e:
            raise Exception(f"Errore nel caricamento della chiave privata per {self.username}: {e}")

        signature = priv.sign(
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def get_trusted_dids(self):
        """
        Simula la lista di DID trusted nel wallet dello studente.
        Questi sono i DID di emittenti di cui lo studente si fida.
        :return: Lista di stringhe DID trusted.
        """
        # Lo studente si fida di Salerno e Rennes per questo scenario
        return ["did:web:unisa.it", "did:web:rennes.it"]

    def load_erasmus_credential(self):
        """
        Carica la credenziale Erasmus dallo storage locale dello studente.
        :return: La credenziale Erasmus come dizionario, o None se non trovata/errore.
        """
        path = os.path.join(CREDENTIAL_FOLDER, f"{self.username}_erasmus_credential.json")
        try:
            with open(path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"❌ Credenziale Erasmus non trovata per {self.username}.")
            return None
        except json.JSONDecodeError:
            print(f"❌ Errore di parsing della credenziale Erasmus per {self.username}.")
            return None

    def load_academic_credential(self):
        """
        Carica la credenziale Accademica dallo storage locale dello studente.
        :return: La credenziale Accademica come dizionario, o None se non trovata/errore.
        """
        path = os.path.join(CREDENTIAL_FOLDER, f"{self.username}_academic_credential.json")
        try:
            with open(path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"❌ Credenziale Accademica non trovata per {self.username}.")
            return None
        except json.JSONDecodeError:
            print(f"❌ Errore di parsing della credenziale Accademica per {self.username}.")
            return None

    def generate_selective_presentation_from_terminal(self):
        """
        Genera una presentazione selettiva interattivamente dal terminale.
        Chiede allo studente quali campi rivelare dalla sua credenziale accademica.
        """
        academic_cred = self.load_academic_credential()
        if not academic_cred:
            print("Impossibile generare la presentazione selettiva: Credenziale Accademica non trovata.")
            return None

        # La struttura della VC accademica ha gli esami completi in credentialSubject["exams"]
        original_exams = academic_cred["credentialSubject"]["exams"]

        # 1. Calcolo tutte le foglie Merkle per tutti i campi di tutti gli esami
        leaves = []
        leaf_lookup = {}  # Mappa hash della foglia all'oggetto foglia {hash: {examId, field, value}}
        for exam in original_exams:
            exam_id = exam.get("examId", str(uuid.uuid4())) # Assicurati che ogni esame abbia un ID
            for field in ["name", "grade", "credits", "date"]:
                if field in exam:
                    leaf_obj = {"examId": exam_id, "field": field, "value": exam[field]}
                    h = hash_leaf(leaf_obj)
                    leaves.append(h)
                    leaf_lookup[h] = leaf_obj

        # 2. Calcolo tutte le Merkle Proof per tutte le foglie
        full_proofs = {}  # { examId: { field: { "proof": [...], "value": "..." (solo se visibile) } } }
        for h, leaf in leaf_lookup.items():
            exam_id = leaf["examId"]
            field = leaf["field"]
            proof = build_merkle_proof(h, leaves) # build_merkle_proof deve essere implementata in MerkleTree.py

            if exam_id not in full_proofs:
                full_proofs[exam_id] = {}

            full_proofs[exam_id][field] = {
                "proof": proof,
                "value": leaf["value"]  # Questo valore verrà rimosso se il campo è nascosto
            }

        # 3. Chiedo interattivamente allo studente cosa mostrare
        selected_claims = {} # Contiene solo i dati che lo studente decide di rivelare

        print("\n==== [ Selezione Esami e Attributi da Mostrare nella Presentazione Selettiva ] ====")
        for exam in original_exams:
            exam_id = exam.get("examId", "N/A")
            name = exam.get("name", "Esame Sconosciuto")
            print(f"\n📝 Esame: {name} (ID: {exam_id})")

            include = input(f"→ Vuoi includere l'esame '{name}' nella presentazione? (s/N): ").strip().lower()
            if include != 's':
                continue

            selected_claims[exam_id] = {"name": name} # Il nome dell'esame è sempre incluso se l'esame è incluso

            for field in ["grade", "credits", "date"]:
                if field in exam:
                    if field == "grade":
                        # Il voto è obbligatorio se l'esame è incluso
                        selected_claims[exam_id][field] = exam[field]
                        print(f"   - '{field}' (Voto: {exam[field]}) è obbligatorio e sarà incluso.")
                    else:
                        show = input(f"   - Mostrare '{field}' (attuale: {exam[field]})? (s/N): ").strip().lower()
                        if show == "s":
                            selected_claims[exam_id][field] = exam[field]
                        else:
                            # Se il campo non viene rivelato, rimuovi il "value" dalla proof e aggiungi "leafHash"
                            if exam_id in full_proofs and field in full_proofs[exam_id]:
                                leaf_obj = {"examId": exam_id, "field": field, "value": exam[field]}
                                leaf_hash = hash_leaf(leaf_obj)
                                full_proofs[exam_id][field].pop("value", None) # Rimuovi il valore rivelato
                                full_proofs[exam_id][field]["leafHash"] = leaf_hash # Includi solo l'hash della foglia

        if not selected_claims:
            print("⚠️ Nessun esame selezionato per la presentazione. Presentazione non generata.")
            return None

        # 4. Costruisci il credentialSubject per la presentazione
        # Contiene i claims rivelati e le Merkle proofs complete (alcune con valori, altre solo con hash)
        presentation_credential_subject = {
            "id": academic_cred["credentialSubject"]["id"],
            "givenName": academic_cred["credentialSubject"]["givenName"],
            "familyName": academic_cred["credentialSubject"]["familyName"],
            "homeUniversity": academic_cred["credentialSubject"]["homeUniversity"],
            "disclosedClaims": selected_claims, # I claims che lo studente ha scelto di rivelare
            "proofs": full_proofs # Tutte le Merkle proofs, con o senza valore a seconda della selezione
        }

        # 5. Crea la Verifiable Presentation senza il campo 'proof' (che verrà aggiunto dopo la firma)
        vp_to_sign = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://consorzio-universita-europee.eu/presentations/v1"
            ],
            "type": ["VerifiablePresentation"],
            "holder": self.did,
            "verifiableCredential": {
                **academic_cred, # Includi l'intera credenziale accademica originale
                "credentialSubject": presentation_credential_subject # Sovrascrivi con il soggetto modificato per la presentazione
            }
        }

        # Rimuovi la 'proof' della VC interna prima di firmare la VP, se presente, per evitare firme annidate non desiderate
        # La VP firma la VC completa (con la sua proof) ma la sua stessa proof è esterna.
        if "verifiableCredential" in vp_to_sign and "proof" in vp_to_sign["verifiableCredential"]:
            # Crea una copia profonda per evitare modifiche all'originale academic_cred
            vc_copy_for_vp = json.loads(json.dumps(vp_to_sign["verifiableCredential"]))
            # Rimuovi la proof della VC interna solo per il payload che verrà firmato dalla VP
            # Questo è cruciale per evitare che la VP firmi la propria proof, il che creerebbe un loop.
            # La proof della VC originale è comunque inclusa nel campo 'verifiableCredential' della VP,
            # ma non è parte del payload che la VP stessa firma.
            # Questo punto è delicato e dipende dalle specifiche esatte del "proof" della VC e della VP.
            # Per questa implementazione, assumiamo che la VP firmi l'intera VC come payload,
            # ma la sua propria proof viene aggiunta dopo.
            pass # Non rimuoviamo la proof della VC qui, la VP firma la VC completa.

        nonce = base64.b64encode(os.urandom(16)).decode()
        created = datetime.utcnow().isoformat() + "Z"

        # 6. Firma tutta la presentazione (senza il campo 'proof' della VP)
        # Il payload da firmare è la rappresentazione JSON canonica della VP senza la sua proof.
        to_sign = json.dumps(vp_to_sign, sort_keys=True)
        signature = self.sign(to_sign)

        # 7. Aggiungi la prova con la firma alla Verifiable Presentation
        vp = vp_to_sign.copy() # Copia la VP_to_sign per aggiungere la proof
        vp["proof"] = {
            "type": "RsaSignature2023",
            "created": created,
            "verificationMethod": f"{self.did}#key-1",
            "nonce": nonce,
            "jws": signature
        }

        output_path = os.path.join(CREDENTIAL_FOLDER, f"{self.username}_vp.json")
        with open(output_path, "w") as f:
            json.dump(vp, f, indent=2)

        print(f"\n✅ Verifiable Presentation salvata in: {output_path}")
        return vp

