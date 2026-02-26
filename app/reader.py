"""
Reads fixture JSON files and validates input
"""

import json
from typing import Dict, List, Any


def read_fixture(filepath: str) -> Dict[str, Any]:
    """
    Read and validate transaction fixture JSON
    
    Returns:
        {
            'network': 'mainnet',
            'raw_tx': 'hex string',
            'prevouts': [...]
        }
    """
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        raise ValueError(f"Fixture file not found: {filepath}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in fixture: {e}")
    
    # Validate required fields
    if 'raw_tx' not in data:
        raise ValueError("Missing required field: raw_tx")
    
    if 'prevouts' not in data:
        raise ValueError("Missing required field: prevouts")
    
    if not isinstance(data['prevouts'], list):
        raise ValueError("prevouts must be an array")
    
    # Validate prevouts
    for idx, prevout in enumerate(data['prevouts']):
        required = ['txid', 'vout', 'value_sats', 'script_pubkey_hex']
        for field in required:
            if field not in prevout:
                raise ValueError(f"prevouts[{idx}] missing required field: {field}")
    
    return data


def validate_prevouts_match_inputs(prevouts: List[Dict], input_refs: List[tuple]) -> None:
    """
    Validate that prevouts match all transaction inputs
    
    Args:
        prevouts: List of prevout dicts with txid, vout, value_sats, script_pubkey_hex
        input_refs: List of (txid, vout) tuples from transaction inputs
    """
    prevout_keys = {(p['txid'], p['vout']) for p in prevouts}
    input_keys = set(input_refs)
    
    # Check for missing prevouts
    missing = input_keys - prevout_keys
    if missing:
        raise ValueError(f"Missing prevout(s): {missing}")
    
    # Check for duplicate prevouts
    if len(prevout_keys) != len(prevouts):
        raise ValueError("Duplicate prevouts found")
    
    # Check for extra prevouts
    extra = prevout_keys - input_keys
    if extra:
        raise ValueError(f"Extra prevout(s) not referenced by inputs: {extra}")