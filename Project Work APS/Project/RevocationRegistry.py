import hashlib
import json
import os

BASE_DIR = os.path.dirname(__file__)
REGISTRY_FILE = os.path.join(BASE_DIR, "revocation_registry.json")

class RevocationRegistry:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._registry = {}
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

    def revoke(self, namespace: str, list_id: str, revocation_key: str) -> bool:
        """Marca una credenziale come revocata e salva su file."""
        ns = self._registry.setdefault(namespace, {})
        rev_list = ns.setdefault(list_id, {})
        rev_list[revocation_key] = True  # Solo True
        self.save_to_file(REGISTRY_FILE)
        return True

    def is_revoked(self, namespace: str, list_id: str, revocation_key: str) -> bool:
        """Ritorna True se revocata, False se non esiste."""
        return self._registry.get(namespace, {}).get(list_id, {}).get(revocation_key, False)

    def save_to_file(self, filepath: str):
        """Salva solo i record con valore True."""
        filtered_registry = {
            ns: {
                lid: {rk: True for rk, val in rev_list.items() if val}
                for lid, rev_list in lists.items()
                if any(val for val in rev_list.values())
            }
            for ns, lists in self._registry.items()
            if any(any(val for val in rev_list.values()) for rev_list in lists.values())
        }

        with open(filepath, "w") as f:
            json.dump(filtered_registry, f, indent=2)

    def load_from_file(self, filepath: str):
        """Carica il registro, eventuali valori non True vengono ignorati."""
        if os.path.exists(filepath):
            try:
                with open(filepath, "r") as f:
                    data = json.load(f)
                    # Pulisce eventuali record errati
                    self._registry = {
                        ns: {
                            lid: {rk: True for rk, val in rev_list.items() if val}
                            for lid, rev_list in lists.items()
                        }
                        for ns, lists in data.items()
                    }
            except json.JSONDecodeError:
                print("⚠️ File JSON corrotto, inizializzo registro vuoto.")
                self._registry = {}
        else:
            self._registry = {}