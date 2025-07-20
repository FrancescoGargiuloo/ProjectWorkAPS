import hashlib
import json
import os
from typing import Dict

BASE_DIR = os.path.dirname(__file__)
REGISTRY_FILE = os.path.join(BASE_DIR, "revocation_registry.json")

class RevocationRegistry:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._registry = {}  # type: ignore # type: Dict[str, Dict[str, Dict[str, bool]]]
            cls._instance.load_from_file(REGISTRY_FILE)
        return cls._instance

    def generate_list_id(self, namespace: str, category_id: str) -> str:
        combined = f"{namespace}:{category_id}"
        return hashlib.sha256(combined.encode()).hexdigest()

    def generate_revocation_key(self, credential_id: str) -> str:
        return hashlib.sha256(credential_id.encode()).hexdigest()

    def create_revocation_entry(self, namespace: str, list_id: str, revocation_key: str):
        ns = self._registry.setdefault(namespace, {})
        rev_list = ns.setdefault(list_id, {})
        if revocation_key not in rev_list:
            rev_list[revocation_key] = False
            self.save_to_file(REGISTRY_FILE)

    def revoke(self, namespace: str, list_id: str, revocation_key: str) -> bool:
        try:
            self._registry[namespace][list_id][revocation_key] = True
            self.save_to_file(REGISTRY_FILE)
            return True
        except KeyError:
            return False

    def is_revoked(self, namespace: str, list_id: str, revocation_key: str) -> bool:
        return self._registry.get(namespace, {}).get(list_id, {}).get(revocation_key)

    def save_to_file(self, filepath: str):
        with open(filepath, "w") as f:
            json.dump(self._registry, f, indent=2)

    def load_from_file(self, filepath: str):
        if os.path.exists(filepath):
            try:
                with open(filepath, "r") as f:
                    self._registry = json.load(f)
            except json.JSONDecodeError:
                print("⚠️ File JSON corrotto, inizializzo registro vuoto.")
                self._registry = {}
        else:
            self._registry = {}


