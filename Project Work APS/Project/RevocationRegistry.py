import hashlib

class RevocationRegistry:
    def __init__(self):
        self.registry = {}  # {namespace: {revocationListId: {revocationKey: True/False}}}

    def create_revocation_entry(self, namespace, list_id, key):
        self.registry.setdefault(namespace, {}).setdefault(list_id, {})[key] = False

    def revoke(self, namespace, list_id, key):
        if namespace in self.registry and list_id in self.registry[namespace] and key in self.registry[namespace][list_id]:
            self.registry[namespace][list_id][key] = True
            return True
        return False

    def is_revoked(self, namespace, list_id, key):
        return self.registry.get(namespace, {}).get(list_id, {}).get(key, None)

    def generate_list_id(self, namespace, category_id):
        combined = f"{namespace}:{category_id}"
        return hashlib.sha256(combined.encode()).hexdigest()

    def generate_revocation_key(self, credential_id):
        return hashlib.sha256(credential_id.encode()).hexdigest()
