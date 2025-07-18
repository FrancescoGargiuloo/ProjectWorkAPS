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
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = hashlib.sha256((left + right).encode()).hexdigest()
            next_level.append(combined)
            if index == i:
                proof.append(right)
                index = len(next_level) - 1
            elif index == i + 1:
                proof.append(left)
                index = len(next_level) - 1
        current_level = next_level
    return proof

def hash_leaf(data: dict) -> str:
    json_string = json.dumps(data, sort_keys=True)
    return hashlib.sha256(json_string.encode()).hexdigest()

def merkle_root(leaves: List[str]) -> str:
    if not leaves:
        return None
    current_level = leaves
    while len(current_level) > 1:
        temp = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i+1] if i+1 < len(current_level) else left
            combined = hashlib.sha256((left + right).encode()).hexdigest()
            temp.append(combined)
        current_level = temp
    return current_level[0]

def verify_merkle_proof(leaf_hash: str, proof: list, root: str) -> bool:
    computed_hash = leaf_hash
    for sibling in proof:
        nodes = sorted([computed_hash, sibling])
        computed_hash = hashlib.sha256((nodes[0] + nodes[1]).encode()).hexdigest()
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
    return merkle_root(leaf_hashes)
