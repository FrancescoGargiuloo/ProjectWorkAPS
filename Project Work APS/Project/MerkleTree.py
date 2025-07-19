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
    return hashed_data

def merkle_root(leaves: List[str]) -> str:
    if not leaves:
        return None
    current_level = leaves
    level_count = 0
    while len(current_level) > 1:
        temp = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i+1] if i+1 < len(current_level) else left
            combined = hashlib.sha256((left + right).encode()).hexdigest()
            temp.append(combined)
        current_level = temp
        level_count += 1
    final_root = current_level[0]
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
    leaf_hashes = []
    for exam_id, fields in proofs_dict.items():
        for field, data in fields.items():
            if "value" in data:
                leaf_obj = {"examId": exam_id, "field": field, "value": data["value"]}
                leaf_hash = hash_leaf(leaf_obj)
            elif "leafHash" in data:
                leaf_hash = data["leafHash"]
            else:
                print(f"❌ Errore: manca valore o hash per {exam_id}.{field}")
                return None
            leaf_hashes.append(leaf_hash)
    final_root = merkle_root(leaf_hashes)
    return final_root