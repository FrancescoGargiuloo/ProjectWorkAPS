import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PasswordManager:
    """Gestisce le operazioni di hashing e verifica delle password"""

    @staticmethod
    def generate_salt():
        """Genera un salt casuale per l'hashing delle password"""
        return base64.b64encode(os.urandom(32)).decode('utf-8')

    @staticmethod
    def hash_password(password, salt):
        """
        Crea un hash della password utilizzando PBKDF2HMAC

        Args:
            password (str): La password in chiaro
            salt (str): Il salt in formato base64

        Returns:
            str: Hash della password in formato base64
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=base64.b64decode(salt),
            iterations=100000,
        )

        key = kdf.derive(password.encode('utf-8'))
        return base64.b64encode(key).decode('utf-8')

    @staticmethod
    def verify_password(stored_hash, password, salt):
        """
        Verifica se una password corrisponde all'hash memorizzato

        Args:
            stored_hash (str): L'hash memorizzato in formato base64
            password (str): La password in chiaro da verificare
            salt (str): Il salt in formato base64

        Returns:
            bool: True se la password è corretta, False altrimenti
        """
        calculated_hash = PasswordManager.hash_password(password, salt)
        return calculated_hash == stored_hash

