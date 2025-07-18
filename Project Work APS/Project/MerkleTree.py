import hashlib
import json
from typing import List


def build_merkle_proof(target_hash, leaves):
    index = leaves.index(target_hash)
    proof = []
    current_level = leaves[:]

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i+1] if i+1 < len(current_level) else left
            combined = hashlib.sha256((left + right).encode()).hexdigest()
            next_level.append(combined)

            if index == i:
                # fratello a destra
                proof.append(('right', right))
                index = len(next_level) - 1
            elif index == i + 1:
                # fratello a sinistra
                proof.append(('left', left))
                index = len(next_level) - 1

        current_level = next_level

    return proof



def hash_leaf(data: dict) -> str:
    json_string = json.dumps(data, sort_keys=True)
    hashed_data = hashlib.sha256(json_string.encode()).hexdigest()
    print(f"DEBUG: hash_leaf - Dati input: {data} -> Hash: {hashed_data[:8]}...")
    return hashed_data

def merkle_root(leaves: List[str]) -> str:
    print(f"DEBUG: merkle_root - Leaves (initial): {leaves}")
    if not leaves:
        print("DEBUG: merkle_root - Lista di leaves vuota, ritorno None.")
        return None
    current_level = leaves
    level_count = 0
    while len(current_level) > 1:
        print(f"DEBUG: merkle_root - Livello {level_count} - current_level: {current_level}")
        temp = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i+1] if i+1 < len(current_level) else left
            combined = hashlib.sha256((left + right).encode()).hexdigest()
            print(f"DEBUG: merkle_root - Combinando {left[:8]}... e {right[:8]}... -> {combined[:8]}...")
            temp.append(combined)
        current_level = temp
        level_count += 1
    final_root = current_level[0]
    print(f"DEBUG: merkle_root - Root finale: {final_root[:8]}...")
    return final_root

def verify_merkle_proof(leaf_hash, proof, root):
    computed_hash = leaf_hash
    for direction, sibling_hash in proof:
        if direction == 'left':
            combined = sibling_hash + computed_hash
        else:  # 'right'
            combined = computed_hash + sibling_hash
        computed_hash = hashlib.sha256(combined.encode()).hexdigest()
    return computed_hash == root


def reconstruct_merkle_root(proofs_dict: dict) -> str:
    print(f"DEBUG: reconstruct_merkle_root - Input proofs_dict: {proofs_dict}")
    leaf_hashes = []
    for exam_id, fields in proofs_dict.items():
        print(f"DEBUG: reconstruct_merkle_root - Processing examId: {exam_id}")
        for field, data in fields.items():
            print(f"DEBUG: reconstruct_merkle_root - Processing field: {field}, data: {data}")
            if "value" in data:
                leaf_obj = {"examId": exam_id, "field": field, "value": data["value"]}
                leaf_hash = hash_leaf(leaf_obj)
                print(f"DEBUG: reconstruct_merkle_root - Creato leaf_obj da value: {leaf_obj} -> Hash: {leaf_hash[:8]}...")
            elif "leafHash" in data:
                leaf_hash = data["leafHash"]
                print(f"DEBUG: reconstruct_merkle_root - Usato leafHash esistente: {leaf_hash[:8]}...")
            else:
                print(f"❌ Errore: manca valore o hash per {exam_id}.{field}")
                return None
            leaf_hashes.append(leaf_hash)
            print(f"DEBUG: reconstruct_merkle_root - Aggiunto hash a leaf_hashes. Current leaf_hashes count: {len(leaf_hashes)}")
    final_root = merkle_root(leaf_hashes)
    print(f"DEBUG: reconstruct_merkle_root - Root Merkle finale ricostruita: {final_root[:8]}...")
    return final_root