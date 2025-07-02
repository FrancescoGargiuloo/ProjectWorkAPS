import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PasswordManager:
    """Gestisce le operazioni di hashing e verifica delle password."""

    @staticmethod
    def generate_salt():
        """Genera un salt casuale (base64)"""
        return base64.b64encode(os.urandom(32)).decode('utf-8')

    @staticmethod
    def hash_password(password, salt):
        """
        Crea un hash della password usando PBKDF2-HMAC-SHA256

        Args:
            password (str): Password in chiaro
            salt (str): Salt in base64

        Returns:
            str: Hash derivato in base64
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=base64.b64decode(salt),
            iterations=100_000,
        )
        key = kdf.derive(password.encode('utf-8'))
        return base64.b64encode(key).decode('utf-8')

    @staticmethod
    def verify_password(stored_hash, password, salt):
        """
        Verifica se l'hash calcolato da password + salt corrisponde a quello memorizzato

        Args:
            stored_hash (str): Hash salvato
            password (str): Password da verificare
            salt (str): Salt originale in base64

        Returns:
            bool
        """
        return stored_hash == PasswordManager.hash_password(password, salt)
