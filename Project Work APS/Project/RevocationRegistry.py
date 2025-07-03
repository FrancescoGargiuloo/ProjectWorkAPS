import hashlib
from typing import Dict

class RevocationRegistry:
    """
    Simula uno Smart Contract condiviso su blockchain, come singleton globale.
    Gestisce namespace -> revocationList -> revocationKey -> bool (revocato?)
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._registry = {}  # type: Dict[str, Dict[str, Dict[str, bool]]]
        return cls._instance

    def generate_list_id(self, namespace: str, category_id: str) -> str:
        combined = f"{namespace}:{category_id}"
        return hashlib.sha256(combined.encode()).hexdigest()

    def generate_revocation_key(self, credential_id: str) -> str:
        return hashlib.sha256(credential_id.encode()).hexdigest()

    def create_revocation_entry(self, namespace: str, list_id: str, revocation_key: str):
        """Inizializza l'entry a False (non revocata)"""
        ns = self._registry.setdefault(namespace, {})
        rev_list = ns.setdefault(list_id, {})
        if revocation_key not in rev_list:
            rev_list[revocation_key] = False

    def revoke(self, namespace: str, list_id: str, revocation_key: str) -> bool:
        """Marca una credenziale come revocata"""
        try:
            self._registry[namespace][list_id][revocation_key] = True
            return True
        except KeyError:
            return False

    def is_revoked(self, namespace: str, list_id: str, revocation_key: str) -> bool:
        """Restituisce True se la VC è revocata, False se non lo è, None se non esiste"""
        return self._registry.get(namespace, {}).get(list_id, {}).get(revocation_key)

    def debug_print(self):
        """Stampa lo stato interno (debug)"""
        import pprint
        pprint.pprint(self._registry)
