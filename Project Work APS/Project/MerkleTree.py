import hashlib
import json
from typing import List, Any, Optional
import base64

def generate_deterministic_salt(exam_id: str, field: str, value: Any, student) -> str:
    salt_input = f"{exam_id}:{field}:{str(value)}:{student.did}"
    return base64.b64encode(hashlib.sha256(salt_input.encode()).digest()[:16]).decode()

def hash_leaf_with_salt(exam_id: str, field: str, value: Any, salt: str) -> str:
    """
    Calcola l'hash di una foglia usando examId, field, value e salt (con debug)
    """
    leaf_data = {
        "examId": exam_id,
        "field": field,
        "value": value,
        "salt": salt
    }
    json_string = json.dumps(leaf_data, sort_keys=True)
    leaf_hash = hashlib.sha256(json_string.encode()).hexdigest()
    return leaf_hash

def build_merkle_proof(target_hash: str, leaves: List[str]) -> List[List[str]]:
    """
    Costruisce una Merkle proof per un hash target.
    """
    #print(f"\n[DEBUG] Costruzione proof per leaf: {target_hash}")
    if target_hash not in leaves:
        #print("[DEBUG] Leaf non trovata tra le foglie")
        return []

    current_level_hashes = leaves[:]

    try:
        target_index = current_level_hashes.index(target_hash)
    except ValueError:
        return []

    proof = [] # La proof conterrà coppie [direzione, hash_fratello]

    while len(current_level_hashes) > 1:
        next_level_hashes = []

        # Per ogni coppia di hash nel livello corrente
        for i in range(0, len(current_level_hashes), 2):
            left_hash = current_level_hashes[i]
            # Gestione del nodo orfano: se un nodo non ha un fratello, viene hashato con se stesso
            right_hash = current_level_hashes[i + 1] if i + 1 < len(current_level_hashes) else left_hash

            if target_index == i:
                proof.append(["right", right_hash])
            elif target_index == i + 1:
                proof.append(["left", left_hash])

            # Calcola l'hash combinato per il livello superiore
            combined_hash = hashlib.sha256((left_hash + right_hash).encode()).hexdigest()
            next_level_hashes.append(combined_hash)

        # Aggiorna l'indice del target per il prossimo livello dell'albero
        # Se il target era all'indice 'i' o 'i+1', il suo genitore sarà all'indice 'i // 2' nel next_level_hashes
        target_index = target_index // 2
        current_level_hashes = next_level_hashes

    return proof

def merkle_root(leaves: List[str]) -> Optional[str]:
    """
    Calcola la radice del Merkle Tree (con debug)
    """
    if not leaves:
        return None

    current_level = leaves[:]
    level = 0

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = hashlib.sha256((left + right).encode()).hexdigest()
            next_level.append(combined)
        current_level = next_level
        level += 1

    return current_level[0]

def verify_merkle_proof(leaf_hash: str, proof: List[List[str]], root: str) -> bool:
    """
    Verifica una Merkle proof.
    """
    computed_hash = leaf_hash

    for direction, sibling_hash in proof:
        if direction == 'left':      # Sibling è a sinistra
            combined = sibling_hash + computed_hash
        elif direction == 'right':   # Sibling è a destra
            combined = computed_hash + sibling_hash
        else:
            return False

        computed_hash = hashlib.sha256(combined.encode()).hexdigest()

    return computed_hash == root
