import hashlib
import json
from typing import List

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