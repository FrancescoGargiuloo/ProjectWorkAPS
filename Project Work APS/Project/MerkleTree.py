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
    # print(f"[DEBUG] Foglia calcolata per {exam_id}.{field} "
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

    #print(f"[DEBUG] Proof generata: {proof}")
    return proof


def merkle_root(leaves: List[str]) -> Optional[str]:
    """
    Calcola la radice del Merkle Tree (con debug)
    """
    if not leaves:
        #print("[DEBUG] Nessuna foglia, root=None")
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
    Verifica una Merkle proof con debug dettagliato
    """
    computed_hash = leaf_hash

    for step, (direction, sibling_hash) in enumerate(proof):
        # La concatenazione deve sempre essere left + right,
        # indipendentemente da dove si trovi il 'computed_hash' o il 'sibling_hash'.
        # Se 'direction' è 'right', significa che il sibling è a destra del 'computed_hash'
        # quindi computed_hash è il sinistro.
        # Se 'direction' è 'left', significa che il sibling è a sinistra del 'computed_hash'
        # quindi computed_hash è il destro.
        if direction == 'left':  # Sibling è a sinistra, computed_hash è a destra
            combined = sibling_hash + computed_hash
        elif direction == 'right':  # Sibling è a destra, computed_hash è a sinistra
            combined = computed_hash + sibling_hash
            #print(
               #f"[DEBUG] Step {step}: computed + RIGHT (sibling) → {computed_hash[:6]}... + {sibling_hash[:6]}... = {combined[:8]}...")
        else:
            #print(f"[DEBUG] Step {step}: Direzione sconosciuta '{direction}'")
            return False

        computed_hash = hashlib.sha256(combined.encode()).hexdigest()
        #print(f"[DEBUG] Step {step}: Hash calcolato: {computed_hash}")

    #print(f"[DEBUG] Merkle Root attesa: {root}")
    #print(f"[DEBUG] Hash calcolato dalla proof: {computed_hash}")

    is_valid = computed_hash == root
    #print(f"[DEBUG] Verifica finale: {'✅ CORRETTA' if is_valid else '❌ MISMATCH'}")

    return is_valid