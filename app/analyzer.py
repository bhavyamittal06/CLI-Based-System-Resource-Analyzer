"""
Bitcoin transaction analyzer - classifies scripts, calculates fees, generates warnings
"""
"""
Bitcoin transaction analyzer - classifies scripts, calculates fees, generates warnings
"""

import sys
import os
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
from typing import Dict, List, Tuple, Optional, Any
from utils import (
    encode_base58check, encode_bech32, encode_bech32m,
    hash160, disassemble_script
)


class TransactionAnalyzer:
    """Analyzes parsed Bitcoin transactions"""
    
    def __init__(self, tx_data: Dict, prevouts: List[Dict]):
        self.tx_data = tx_data
        self.prevouts_map = {(p['txid'], p['vout']): p for p in prevouts}
    
    def classify_output_script(self, script_hex: str) -> Tuple[str, Optional[str]]:
        """
        Classify output script type and derive address
        
        Returns:
            (script_type, address or None)
        """
        if not script_hex:
            return ('unknown', None)
        
        script = bytes.fromhex(script_hex)
        script_len = len(script)
        
        # P2PKH: 76a914{20-bytes}88ac
        if (script_len == 25 and
            script[0] == 0x76 and  # OP_DUP
            script[1] == 0xa9 and  # OP_HASH160
            script[2] == 0x14 and  # OP_PUSHBYTES_20
            script[23] == 0x88 and  # OP_EQUALVERIFY
            script[24] == 0xac):  # OP_CHECKSIG
            
            pubkey_hash = script[3:23]
            address = encode_base58check(b'\x00' + pubkey_hash)
            return ('p2pkh', address)
        
        # P2SH: a914{20-bytes}87
        if (script_len == 23 and
            script[0] == 0xa9 and  # OP_HASH160
            script[1] == 0x14 and  # OP_PUSHBYTES_20
            script[22] == 0x87):  # OP_EQUAL
            
            script_hash = script[2:22]
            address = encode_base58check(b'\x05' + script_hash)
            return ('p2sh', address)
        
        # P2WPKH: 0014{20-bytes}
        if script_len == 22 and script[0] == 0x00 and script[1] == 0x14:
            pubkey_hash = script[2:22]
            address = encode_bech32('bc', 0, pubkey_hash)
            return ('p2wpkh', address)
        
        # P2WSH: 0020{32-bytes}
        if script_len == 34 and script[0] == 0x00 and script[1] == 0x20:
            script_hash = script[2:34]
            address = encode_bech32('bc', 0, script_hash)
            return ('p2wsh', address)
        
        # P2TR: 5120{32-bytes}
        if script_len == 34 and script[0] == 0x51 and script[1] == 0x20:
            pubkey = script[2:34]
            address = encode_bech32m('bc', 1, pubkey)
            return ('p2tr', address)
        
        # OP_RETURN: starts with 0x6a
        if script_len > 0 and script[0] == 0x6a:
            return ('op_return', None)
        
        return ('unknown', None)
    
    def classify_input(self, inp: Dict, prevout: Dict, witness: List[str]) -> Tuple[str, Optional[str]]:
        """
        Classify input spend type and derive address from prevout
        
        Returns:
            (script_type, address)
        """
        script_sig_hex = inp['script_sig_hex']
        script_sig = bytes.fromhex(script_sig_hex) if script_sig_hex else b''
        
        # Get prevout script type and address
        prevout_type, prevout_address = self.classify_output_script(prevout['script_pubkey_hex'])
        
        # P2PKH: scriptSig has signature + pubkey
        if prevout_type == 'p2pkh':
            return ('p2pkh', prevout_address)
        
        # P2SH-wrapped SegWit
        if prevout_type == 'p2sh' and len(script_sig) in [22, 34]:
            redeem_script = script_sig
            
            # P2SH-P2WPKH: 22-byte redeem script (0014{20-bytes})
            if len(redeem_script) == 22 and redeem_script[0] == 0x00 and redeem_script[1] == 0x14:
                if len(witness) == 2:
                    pubkey_hash = redeem_script[2:22]
                    address = encode_bech32('bc', 0, pubkey_hash)
                    return ('p2sh-p2wpkh', address)
            
            # P2SH-P2WSH: 34-byte redeem script (0020{32-bytes})
            if len(redeem_script) == 34 and redeem_script[0] == 0x00 and redeem_script[1] == 0x20:
                if len(witness) >= 2:
                    script_hash = redeem_script[2:34]
                    address = encode_bech32('bc', 0, script_hash)
                    return ('p2sh-p2wsh', address)
        
        # Regular P2SH (non-SegWit)
        if prevout_type == 'p2sh':
        # P2SH inputs need more analysis - return unknown for now
         return ('unknown', prevout_address)
    
    # Native SegWit
        if prevout_type == 'p2wpkh':
         return ('p2wpkh', prevout_address)
        
        if prevout_type == 'p2wsh':
            return ('p2wsh', prevout_address)
        
        # Taproot
        if prevout_type == 'p2tr':
            if len(witness) == 1 and len(bytes.fromhex(witness[0])) == 64:
                return ('p2tr_keypath', prevout_address)
            elif len(witness) >= 2:
                # Check for control block
                last_item = bytes.fromhex(witness[-1])
                if len(last_item) >= 33 and last_item[0] in [0xc0, 0xc1]:
                    return ('p2tr_scriptpath', prevout_address)
            return ('p2tr_keypath', prevout_address)
        
        return ('unknown', None)
    
    def parse_op_return(self, script_hex: str) -> Dict[str, Any]:
        """
        Parse OP_RETURN data and detect protocol
        
        Returns:
            {
                'op_return_data_hex': str,
                'op_return_data_utf8': str or None,
                'op_return_protocol': str
            }
        """
        script = bytes.fromhex(script_hex)
        
        if not script or script[0] != 0x6a:
            return {
                'op_return_data_hex': '',
                'op_return_data_utf8': None,
                'op_return_protocol': 'unknown'
            }
        
        # Extract all data pushes after OP_RETURN
        data_parts = []
        i = 1  # Skip OP_RETURN
        
        while i < len(script):
            opcode = script[i]
            i += 1
            
            # Direct push (1-75 bytes)
            if 1 <= opcode <= 75:
                if i + opcode > len(script):
                    break
                data_parts.append(script[i:i+opcode])
                i += opcode
            
            # OP_PUSHDATA1
            elif opcode == 0x4c:
                if i >= len(script):
                    break
                length = script[i]
                i += 1
                if i + length > len(script):
                    break
                data_parts.append(script[i:i+length])
                i += length
            
            # OP_PUSHDATA2
            elif opcode == 0x4d:
                if i + 1 >= len(script):
                    break
                length = int.from_bytes(script[i:i+2], 'little')
                i += 2
                if i + length > len(script):
                    break
                data_parts.append(script[i:i+length])
                i += length
            
            # OP_PUSHDATA4
            elif opcode == 0x4e:
                if i + 3 >= len(script):
                    break
                length = int.from_bytes(script[i:i+4], 'little')
                i += 4
                if i + length > len(script):
                    break
                data_parts.append(script[i:i+length])
                i += length
            
            else:
                # Not a push opcode, stop
                break
        
        # Concatenate all data
        full_data = b''.join(data_parts)
        data_hex = full_data.hex()
        
        # Try UTF-8 decode
        try:
            data_utf8 = full_data.decode('utf-8')
        except UnicodeDecodeError:
            data_utf8 = None
        
        # Detect protocol
        protocol = 'unknown'
        if full_data.startswith(b'omni'):
            protocol = 'omni'
        elif full_data.startswith(bytes.fromhex('0109f91102')):
            protocol = 'opentimestamps'
        
        return {
            'op_return_data_hex': data_hex,
            'op_return_data_utf8': data_utf8,
            'op_return_protocol': protocol
        }
    
    def analyze_locktime(self, locktime: int) -> Tuple[str, int]:
        """
        Analyze absolute locktime
        
        Returns:
            (locktime_type, locktime_value)
        """
        if locktime == 0:
            return ('none', 0)
        elif locktime < 500000000:
            return ('block_height', locktime)
        else:
            return ('unix_timestamp', locktime)
    
    def analyze_relative_timelock(self, sequence: int) -> Dict[str, Any]:
        """
        Analyze BIP68 relative timelock from nSequence
        
        Returns:
            {
                'enabled': bool,
                'type': 'blocks' or 'time' (if enabled),
                'value': int (if enabled)
            }
        """
        # Bit 31: disable flag
        if sequence & (1 << 31):
            return {'enabled': False}
        
        # Extract the 16-bit value
        value = sequence & 0xFFFF
        
        # Bit 22: time vs blocks
        if sequence & (1 << 22):
            # Time-based: value * 512 seconds
            return {
                'enabled': True,
                'type': 'time',
                'value': value * 512
            }
        else:
            # Block-based
            return {
                'enabled': True,
                'type': 'blocks',
                'value': value
            }
    
    def generate_warnings(self, fee_sats: int, fee_rate: float, outputs: List[Dict], rbf: bool) -> List[str]:
        """Generate warning codes"""
        warnings = []
        
        # HIGH_FEE
        if fee_sats > 1_000_000 or fee_rate > 200:
            warnings.append('HIGH_FEE')
        
        # DUST_OUTPUT
        for out in outputs:
            if out['script_type'] != 'op_return' and out['value_sats'] < 546:
                warnings.append('DUST_OUTPUT')
                break
        
        # UNKNOWN_OUTPUT_SCRIPT
        for out in outputs:
            if out['script_type'] == 'unknown':
                warnings.append('UNKNOWN_OUTPUT_SCRIPT')
                break
        
        # RBF_SIGNALING
        if rbf:
            warnings.append('RBF_SIGNALING')
        
        return warnings
    
    def calculate_segwit_savings(self, weight_actual: int, non_witness_bytes: int, witness_bytes: int) -> Optional[Dict]:
        """Calculate SegWit savings vs legacy"""
        if not self.tx_data['is_segwit']:
            return None
        
        total_bytes = non_witness_bytes + witness_bytes + 2  # +2 for marker/flag
        weight_if_legacy = total_bytes * 4
        savings_pct = round(((weight_if_legacy - weight_actual) / weight_if_legacy) * 100, 2)
        
        return {
            'witness_bytes': witness_bytes,
            'non_witness_bytes': non_witness_bytes,
            'total_bytes': total_bytes,
            'weight_actual': weight_actual,
            'weight_if_legacy': weight_if_legacy,
            'savings_pct': savings_pct
        }