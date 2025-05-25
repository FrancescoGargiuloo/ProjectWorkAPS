import hashlib
import base64
import random
import string
import json
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class Student:
    def __init__(self, username):
        """
        Inizializza uno studente con username e password

        Args:
            username (str): Username dello studente
            password (str): Password dello studente
            key_path (str, optional): Percorso al file .pem della chiave privata
            public_key_path (str, optional): Percorso al file della chiave pubblica
        """
        self.username = username
        self.did = "" # teoricamente lo studente ha il did già associato
        self._private_key_path = "rsa_priv.key"
        self._public_key_path = "rsa_pub.key"

        # Se non viene fornito un percorso alla chiave, ne generiamo una nuova e la salviamo
        if not os.path.exists(self._private_key_path):
            self._generate_and_save_key()
        self.credentials = []  # Lista per memorizzare le credenziali ricevute

    def _generate_and_save_key(self):
        """Genera una chiave privata RSA e la salva in un file .pem"""
        # Genera una nuova chiave RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        # bisognerebbe però nel caso di una chiave privata o pubblica non disponibile
        # di generare entrambi le chiavi, altrimenti non funzioneraà mai la enc e la dec, da aggiustare
        # Serializza la chiave privata in formato PEM
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # In produzione usare BestAvailableEncryption
        )

        # Salva la chiave privata in un file
        with open(self._private_key_path, 'wb') as f:
            f.write(pem)

        print(f"Chiave privata generata e salvata in: {self._private_key_path}")
        print(f"Chiave pubblica salvata in: {self._public_key_path}")

    def _load_private_key(self):
        """Carica la chiave privata dal file .pem"""
        try:
            with open(self._private_key_path, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None  # In produzione utilizzare una password
                )
            return private_key
        except Exception as e:
            print(f"Errore nel caricamento della chiave privata: {e}")
            return None

    def sign(self, data):
        """
        Firma digitalmente i dati utilizzando la chiave privata dello studente

        Args:
            data (str | dict): I dati da firmare

        Returns:
            str: Firma digitale in formato base64
        """
        # Carica la chiave privata
        private_key = self._load_private_key()
        if not private_key:
            raise Exception("Impossibile caricare la chiave privata")

        # Serializza i dati in formato JSON ordinato se è un dizionario
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)

        # Firma i dati con RSA
        signature = private_key.sign(
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Restituisce la firma in formato base64
        return base64.b64encode(signature).decode()

    def get_public_key_pem(self):
        """
        Ottiene la chiave pubblica in formato PEM

        Returns:
            str: Chiave pubblica in formato PEM
        """
        try:
            # Controlla se il file della chiave pubblica esiste, questo controllo
            # se fatto a monte del codice nell'init non ha senso
            if os.path.exists(self._public_key_path):
                # Legge la chiave pubblica dal file
                with open(self._public_key_path, 'rb') as key_file:
                    return key_file.read().decode()
            else:
                # Se il file non esiste, genera la chiave pubblica dalla chiave privata
                private_key = self._load_private_key()
                if not private_key:
                    raise Exception("Impossibile caricare la chiave privata")

                public_key = private_key.public_key()
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                # Salva la chiave pubblica per uso futuro
                with open(self._public_key_path, 'wb') as f:
                    f.write(pem)

                return pem.decode()
        except Exception as e:
            print(f"Errore nell'ottenere la chiave pubblica: {e}")
            return None

    def store_credential(self, credential):
        """
        Memorizza una credenziale verificabile ricevuta

        Args:
            credential (dict): La credenziale verificabile da memorizzare

        Returns:
            bool: True se la memorizzazione è avvenuta con successo
        """
        # Aggiungi la credenziale alla lista
        self.credentials.append(credential)
        return True

    def get_credentials(self):
        """
        Recupera tutte le credenziali memorizzate

        Returns:
            list: Lista di tutte le credenziali
        """
        return self.credentials

    def get_credential_by_type(self, credential_type):
        """
        Recupera credenziali per tipo

        Args:
            credential_type (str): Il tipo di credenziale da cercare

        Returns:
            list: Lista delle credenziali del tipo specificato
        """
        return [cred for cred in self.credentials
                if credential_type in cred.get("type", [])]