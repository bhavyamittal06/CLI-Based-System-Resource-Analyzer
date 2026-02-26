"""
Bitcoin transaction parser - handles raw hex parsing
"""
import sys
import os
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from io import BytesIO
from typing import Dict, List, Tuple
from utils import read_varint, double_sha256, write_varint


class TransactionParser:
    """Parses raw Bitcoin transaction bytes"""
    
    def __init__(self, raw_hex: str):
        self.raw_hex = raw_hex
        self.raw_bytes = bytes.fromhex(raw_hex)
        self.stream = BytesIO(self.raw_bytes)
        self.is_segwit = False
        
    def parse(self) -> Dict:
        """Parse transaction and return structured data"""
        # Version
        version = int.from_bytes(self.stream.read(4), 'little')
        
        # Check for SegWit marker
        marker_pos = self.stream.tell()
        marker = self.stream.read(1)[0]
        flag = self.stream.read(1)[0]
        
        if marker == 0x00 and flag == 0x01:
            self.is_segwit = True
        else:
            # Not SegWit, rewind
            self.stream.seek(marker_pos)
        
        # Inputs
        input_count = read_varint(self.stream)
        inputs = []
        for _ in range(input_count):
            inputs.append(self._parse_input())
        
        # Outputs
        output_count = read_varint(self.stream)
        outputs = []
        for _ in range(output_count):
            outputs.append(self._parse_output())
        
        # Witness data (if SegWit)
        witnesses = []
        if self.is_segwit:
            for _ in range(input_count):
                witnesses.append(self._parse_witness())
        else:
            witnesses = [[] for _ in range(input_count)]
        
        # Locktime
        locktime = int.from_bytes(self.stream.read(4), 'little')
        
        return {
            'version': version,
            'is_segwit': self.is_segwit,
            'inputs': inputs,
            'outputs': outputs,
            'witnesses': witnesses,
            'locktime': locktime
        }
    
    def _parse_input(self) -> Dict:
        """Parse a single transaction input"""
        # Previous txid (32 bytes, reversed for display)
        txid_bytes = self.stream.read(32)
        txid = txid_bytes[::-1].hex()
        
        # Previous vout
        vout = int.from_bytes(self.stream.read(4), 'little')
        
        # ScriptSig
        script_len = read_varint(self.stream)
        script_sig = self.stream.read(script_len)
        
        # Sequence
        sequence = int.from_bytes(self.stream.read(4), 'little')
        
        return {
            'txid': txid,
            'vout': vout,
            'script_sig_hex': script_sig.hex(),
            'sequence': sequence
        }
    
    def _parse_output(self) -> Dict:
        """Parse a single transaction output"""
        # Value
        value = int.from_bytes(self.stream.read(8), 'little')
        
        # ScriptPubKey
        script_len = read_varint(self.stream)
        script_pubkey = self.stream.read(script_len)
        
        return {
            'value_sats': value,
            'script_pubkey_hex': script_pubkey.hex()
        }
    
    def _parse_witness(self) -> List[str]:
        """Parse witness data for one input"""
        item_count = read_varint(self.stream)
        items = []
        
        for _ in range(item_count):
            item_len = read_varint(self.stream)
            item_data = self.stream.read(item_len)
            items.append(item_data.hex())
        
        return items
    
    def calculate_txid(self) -> str:
        """Calculate transaction ID (non-witness serialization)"""
        if not self.is_segwit:
            # For legacy, txid is just double-SHA256 of raw bytes
            txid_bytes = double_sha256(self.raw_bytes)
            return txid_bytes[::-1].hex()
        
        # For SegWit, need to serialize without witness data
        non_witness_tx = self._serialize_non_witness()
        txid_bytes = double_sha256(non_witness_tx)
        return txid_bytes[::-1].hex()
    
    def calculate_wtxid(self) -> str:
        """Calculate witness transaction ID (full serialization)"""
        if not self.is_segwit:
            return None
        
        # wtxid is double-SHA256 of full transaction (including witness)
        wtxid_bytes = double_sha256(self.raw_bytes)
        return wtxid_bytes[::-1].hex()
    
    def _serialize_non_witness(self) -> bytes:
        """Serialize transaction without witness data (for txid calculation)"""
        tx_data = self.parse()
        result = b''
        
        # Version
        result += tx_data['version'].to_bytes(4, 'little')
        
        # Input count
        result += write_varint(len(tx_data['inputs']))
        
        # Inputs
        for inp in tx_data['inputs']:
            result += bytes.fromhex(inp['txid'])[::-1]  # Reverse txid
            result += inp['vout'].to_bytes(4, 'little')
            script_sig = bytes.fromhex(inp['script_sig_hex'])
            result += write_varint(len(script_sig))
            result += script_sig
            result += inp['sequence'].to_bytes(4, 'little')
        
        # Output count
        result += write_varint(len(tx_data['outputs']))
        
        # Outputs
        for out in tx_data['outputs']:
            result += out['value_sats'].to_bytes(8, 'little')
            script_pubkey = bytes.fromhex(out['script_pubkey_hex'])
            result += write_varint(len(script_pubkey))
            result += script_pubkey
        
        # Locktime
        result += tx_data['locktime'].to_bytes(4, 'little')
        
        return result
    
    def calculate_weight_and_size(self) -> Tuple[int, int, float]:
        """
        Calculate size_bytes, weight, and vbytes according to BIP141
        
        Returns:
            (size_bytes, weight, vbytes)
        """
        if not self.is_segwit:
            # Legacy transaction: weight = size * 4
            size_bytes = len(self.raw_bytes)
            weight = size_bytes * 4
            vbytes = float(size_bytes)
            return (size_bytes, weight, vbytes)
        
        # SegWit transaction
        non_witness_bytes = len(self._serialize_non_witness())
        total_bytes = len(self.raw_bytes)
        witness_bytes = total_bytes - non_witness_bytes - 2  # -2 for marker and flag
        
        # weight = (non_witness_bytes + marker + flag) * 4 + witness_bytes
        # But marker/flag are counted as part of witness overhead
        weight = (non_witness_bytes * 4) + witness_bytes + 2  # +2 for marker/flag
        vbytes = weight / 4.0
        
        return (total_bytes, weight, vbytes)