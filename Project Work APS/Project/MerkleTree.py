import hashlib
import json
from typing import List


def build_merkle_proof(target_hash, leaves):
    print(f"DEBUG: build_merkle_proof - target_hash: {target_hash}")
    print(f"DEBUG: build_merkle_proof - leaves (initial): {leaves}")
    try:
        index = leaves.index(target_hash)
        print(f"DEBUG: build_merkle_proof - target_hash index: {index}")
    except ValueError:
        print(f"DEBUG: build_merkle_proof - target_hash '{target_hash}' not found in leaves.")
        return [] # Ritorna una lista vuota se l'hash non è trovato

    proof = []
    current_level = leaves[:]
    level_count = 0
    while len(current_level) > 1:
        print(f"DEBUG: build_merkle_proof - Livello {level_count} - current_level: {current_level}")
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = hashlib.sha256((left + right).encode()).hexdigest()
            print(f"DEBUG: build_merkle_proof - Combinando {left[:8]}... e {right[:8]}... -> {combined[:8]}...")
            next_level.append(combined)

            if index == i:
                proof.append(right)
                print(f"DEBUG: build_merkle_proof - Aggiunto a proof (right): {right[:8]}...")
                index = len(next_level) - 1
                print(f"DEBUG: build_merkle_proof - Nuovo index per il prossimo livello: {index}")
            elif index == i + 1:
                proof.append(left)
                print(f"DEBUG: build_merkle_proof - Aggiunto a proof (left): {left[:8]}...")
                index = len(next_level) - 1
                print(f"DEBUG: build_merkle_proof - Nuovo index per il prossimo livello: {index}")
        current_level = next_level
        level_count += 1
    print(f"DEBUG: build_merkle_proof - Proof finale: {proof}")
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

def verify_merkle_proof(leaf_hash: str, proof: list, root: str) -> bool:
    print(f"DEBUG: verify_merkle_proof - Leaf hash: {leaf_hash[:8]}...")
    print(f"DEBUG: verify_merkle_proof - Proof: {proof}")
    print(f"DEBUG: verify_merkle_proof - Root atteso: {root[:8]}...")
    computed_hash = leaf_hash
    for sibling in proof:
        print(f"DEBUG: verify_merkle_proof - Hash corrente: {computed_hash[:8]}..., Sibling: {sibling[:8]}...")
        nodes = sorted([computed_hash, sibling])
        print(f"DEBUG: verify_merkle_proof - Nodi ordinati: {nodes[0][:8]}..., {nodes[1][:8]}...")
        computed_hash = hashlib.sha256((nodes[0] + nodes[1]).encode()).hexdigest()
        print(f"DEBUG: verify_merkle_proof - Hash calcolato dopo combinazione: {computed_hash[:8]}...")
    is_valid = (computed_hash == root)
    print(f"DEBUG: verify_merkle_proof - Confronto finale: {computed_hash[:8]}... == {root[:8]}... -> {is_valid}")
    return is_valid

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