import hashlib
import json
import os
from datetime import datetime, timezone

BLOCKCHAIN_FILE = os.path.join(os.path.dirname(__file__), "shared_blockchain.json")

class Block:
    def __init__(self, index, previous_hash, data, timestamp=None):
        self.index = index
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.timestamp}{json.dumps(self.data, sort_keys=True)}{self.previous_hash}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }

    @staticmethod
    def from_dict(d):
        b = Block(d["index"], d["previous_hash"], d["data"], d["timestamp"])
        b.hash = d["hash"]
        return b

class Blockchain:
    def __init__(self):
        self.chain = self._load_chain()
        if not self.is_chain_valid():
            raise Exception("❌ Blockchain corrotta o manomessa.")

    def _create_genesis_block(self):
        return Block(0, "0", {"message": "Genesis Block"})

    def _load_chain(self):
        if os.path.exists(BLOCKCHAIN_FILE):
            try:
                with open(BLOCKCHAIN_FILE, "r") as f:
                    content = f.read().strip()
                    if not content:
                        genesis = self._create_genesis_block()
                        self._save_chain([genesis])
                        return [genesis]
                    data = json.loads(content)
                    return [Block.from_dict(b) for b in data]
            except Exception as e:
                print(f"⚠️ Errore durante il caricamento della blockchain: {e}")
                print("❗ Non sovrascrivo il file. Crea manualmente backup o correggi il file JSON.")
                raise e
        else:
            # se il file non esiste, crea la genesis chain
            genesis = self._create_genesis_block()
            self._save_chain([genesis])
            return [genesis]


    def _save_chain(self, chain):
        with open(BLOCKCHAIN_FILE, "w") as f:
            json.dump([b.to_dict() for b in chain], f, indent=2)

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        self.chain = self._load_chain()

        if not self.is_chain_valid():
            raise Exception("❌ Impossibile aggiungere blocchi a una catena non valida.")

        latest = self.get_latest_block()
        new_block = Block(index=latest.index + 1, previous_hash=latest.hash, data=data)
        self.chain.append(new_block)
        self._save_chain(self.chain)
        return new_block.hash

    def get_all_blocks(self):
        return [b.to_dict() for b in self.chain]

    def get_merkle_root(self, tx_hash):
        """
        Cerca nella blockchain il blocco con hash == tx_hash
        e ritorna la Merkle Root salvata in 'data'.
        """
        for block in self.chain:
            if block.hash == tx_hash:
                # supponendo che la Merkle Root sia salvata come:
                # block.data = {"merkleRoot": "...", ...}
                if isinstance(block.data, dict) and "merkleRoot" in block.data:
                    return block.data["merkleRoot"]
                else:
                    print("❌ Il blocco non contiene la Merkle Root nei dati.")
                    return None
        print("❌ Blocco con hash specificato non trovato.")
        return None

    def is_chain_valid(self):
        """
        Verifica che la catena sia valida:
        - ogni blocco punta al precedente con un hash corretto
        - ogni blocco ha un hash valido rispetto al suo contenuto
        """
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # Verifica che l'hash calcolato corrisponda
            if current.hash != current.calculate_hash():
                print(f"❌ Hash del blocco {i} non valido.")
                return False

            # Verifica che il blocco punti correttamente al precedente
            if current.previous_hash != previous.hash:
                print(f"❌ Hash del blocco precedente errato al blocco {i}.")
                return False

        print("✅ La blockchain è valida.")
        return True
