#!/usr/bin/env python3
"""
Bitcoin block parser - handles block files, undo data, and merkle verification
"""

import sys
import os
import struct
from io import BytesIO
from typing import List, Dict, Tuple, Any

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from parser import TransactionParser
from analyzer import TransactionAnalyzer
from utils import read_varint, double_sha256, disassemble_script


def xor_decode(data: bytes, key: bytes) -> bytes:
    """XOR-decode data with repeating key"""
    if not key or all(b == 0 for b in key):
        # All-zero key means no encoding
        return data
    
    result = bytearray(len(data))
    key_len = len(key)
    
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % key_len]
    
    return bytes(result)


def read_xor_key(xor_file: str) -> bytes:
    """Read XOR key from file"""
    with open(xor_file, 'rb') as f:
        return f.read()


class BlockParser:
    """Parses Bitcoin block files"""
    
    def __init__(self, blk_file: str, rev_file: str, xor_key: bytes):
        self.blk_file = blk_file
        self.rev_file = rev_file
        self.xor_key = xor_key
        
        # Read and decode block file
        with open(blk_file, 'rb') as f:
            blk_data = f.read()
        self.blk_data = xor_decode(blk_data, xor_key)
        
        # Read and decode undo file
        with open(rev_file, 'rb') as f:
            rev_data = f.read()
        self.rev_data = xor_decode(rev_data, xor_key)
        
        self.blk_stream = BytesIO(self.blk_data)
        self.rev_stream = BytesIO(self.rev_data)
    
    def parse_all_blocks(self) -> List[Dict[str, Any]]:
        """Parse all blocks in the file"""
        blocks = []

        while self.blk_stream.tell() < len(self.blk_data):
            remaining = len(self.blk_data) - self.blk_stream.tell()
            if remaining < 80:
                break

            try:
                block = self.parse_single_block()
                if block:
                    blocks.append(block)
            except Exception:
                break

        
        import json
        import os

        os.makedirs("out", exist_ok=True)

        with open("out/block_output.json", "w") as f:
            json.dump(blocks, f, indent=2)

        return blocks
    
    def parse_single_block(self) -> Dict[str, Any]:
        """Parse a single block"""
        # Read 80-byte header
        header_data = self.blk_stream.read(80)
        if len(header_data) < 80:
            return None
        
        header = self.parse_block_header(header_data)
        
        # Read transaction count
        tx_count = read_varint(self.blk_stream)
        
        # Parse transactions
        transactions = []
        raw_txs = []
        
        for i in range(tx_count):
            # Mark position before transaction
            tx_start = self.blk_stream.tell()
            
            # Read raw transaction hex
            raw_tx_hex = self._read_transaction_raw()
            
            # Parse transaction
            parser = TransactionParser(raw_tx_hex)
            tx_data = parser.parse()
            tx_data['raw_tx_hex'] = raw_tx_hex  # Store for later analysis
            
            # Get raw bytes for merkle calculation
            raw_tx_bytes = bytes.fromhex(raw_tx_hex)
            raw_txs.append(raw_tx_bytes)
            
            transactions.append(tx_data)
        
        # Calculate merkle root
        calculated_merkle = self.calculate_merkle_root(raw_txs)
        merkle_valid = calculated_merkle == header['merkle_root']
        header['merkle_root_valid'] = merkle_valid
        
        # Parse undo data for this block
        prevouts = self.parse_undo_data(transactions)
        
        # Identify coinbase
        coinbase_info = self.parse_coinbase(transactions[0])
        
        return {
            'header': header,
            'tx_count': tx_count,
            'transactions': transactions,
            'prevouts': prevouts,
            'coinbase': coinbase_info
        }
    
    def parse_block_header(self, data: bytes) -> Dict[str, Any]:
        """Parse 80-byte block header"""
        stream = BytesIO(data)
        
        # Version (4 bytes)
        version = struct.unpack('<I', stream.read(4))[0]
        
        # Previous block hash (32 bytes, reversed for display)
        prev_block = stream.read(32)[::-1].hex()
        
        # Merkle root (32 bytes, reversed for display)
        merkle_root = stream.read(32)[::-1].hex()
        
        # Timestamp (4 bytes)
        timestamp = struct.unpack('<I', stream.read(4))[0]
        
        # Bits (4 bytes)
        bits = stream.read(4).hex()
        
        # Nonce (4 bytes)
        nonce = struct.unpack('<I', stream.read(4))[0]
        
        # Calculate block hash (double SHA256 of header, reversed)
        block_hash = double_sha256(data)[::-1].hex()
        
        return {
            'version': version,
            'prev_block_hash': prev_block,
            'merkle_root': merkle_root,
            'timestamp': timestamp,
            'bits': bits,
            'nonce': nonce,
            'block_hash': block_hash
        }
    
    def _read_transaction_raw(self) -> str:
        """Read raw transaction from stream and return hex"""
        start_pos = self.blk_stream.tell()
        
        # Version
        version = self.blk_stream.read(4)
        
        # Check for SegWit marker
        marker_pos = self.blk_stream.tell()
        marker = self.blk_stream.read(1)
        flag = self.blk_stream.read(1)
        
        is_segwit = (marker[0] == 0x00 and flag[0] == 0x01)
        if not is_segwit:
            self.blk_stream.seek(marker_pos)
        
        # Input count
        input_count = read_varint(self.blk_stream)
        
        # Inputs
        for _ in range(input_count):
            self.blk_stream.read(32)  # txid
            self.blk_stream.read(4)   # vout
            script_len = read_varint(self.blk_stream)
            self.blk_stream.read(script_len)  # scriptSig
            self.blk_stream.read(4)   # sequence
        
        # Output count
        output_count = read_varint(self.blk_stream)
        
        # Outputs
        for _ in range(output_count):
            self.blk_stream.read(8)   # value
            script_len = read_varint(self.blk_stream)
            self.blk_stream.read(script_len)  # scriptPubKey
        
        # Witness data (if SegWit)
        if is_segwit:
            for _ in range(input_count):
                item_count = read_varint(self.blk_stream)
                for _ in range(item_count):
                    item_len = read_varint(self.blk_stream)
                    self.blk_stream.read(item_len)
        
        # Locktime
        self.blk_stream.read(4)
        
        # Get raw transaction
        end_pos = self.blk_stream.tell()
        self.blk_stream.seek(start_pos)
        raw_tx = self.blk_stream.read(end_pos - start_pos)
        
        return raw_tx.hex()
    
    def calculate_merkle_root(self, raw_txs: List[bytes]) -> str:
        """Calculate merkle root from transaction list"""
        if not raw_txs:
            return "0" * 64
        
        # Calculate txids (double SHA256 of each transaction)
        hashes = [double_sha256(tx) for tx in raw_txs]
        
        # Build merkle tree
        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])  # Duplicate last hash if odd
            
            new_hashes = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i + 1]
                new_hashes.append(double_sha256(combined))
            
            hashes = new_hashes
        
        # Return reversed (display convention)
        return hashes[0][::-1].hex()
    
    def parse_undo_data(self, transactions: List[Dict]) -> Dict[Tuple[str, int], Dict]:
        """Parse undo data to get prevouts"""
        prevouts = {}
        
        # Skip coinbase (first transaction has no prevouts)
        for tx_idx in range(1, len(transactions)):
            tx = transactions[tx_idx]
            
            for inp in tx['inputs']:
                # Read prevout from undo data
                try:
                    prevout = self._read_undo_prevout()
                    key = (inp['txid'], inp['vout'])
                    prevouts[key] = prevout
                except:
                    # If undo data is exhausted, create placeholder
                    prevouts[(inp['txid'], inp['vout'])] = {
                        'value_sats': 0,
                        'script_pubkey_hex': ''
                    }
        
        return prevouts
    
    def _read_undo_prevout(self) -> Dict[str, Any]:
        """Read a single prevout from undo data"""
        # Read nSize (compressed size)
        nSize = read_varint(self.rev_stream)
        
        # Decompress script based on nSize
        if nSize == 0:
            # P2PKH
            hash160 = self.rev_stream.read(20)
            script = b'\x76\xa9\x14' + hash160 + b'\x88\xac'
        elif nSize == 1:
            # P2SH
            hash160 = self.rev_stream.read(20)
            script = b'\xa9\x14' + hash160 + b'\x87'
        elif nSize in [2, 3]:
            # Compressed pubkey (P2PK)
            pubkey = bytes([nSize]) + self.rev_stream.read(32)
            script = bytes([33]) + pubkey + b'\xac'
        elif nSize in [4, 5]:
            # Uncompressed pubkey (P2PK)
            pubkey = bytes([nSize - 2]) + self.rev_stream.read(32) + self.rev_stream.read(32)
            script = bytes([65]) + pubkey + b'\xac'
        else:
            # Raw script
            script_len = nSize - 6
            script = self.rev_stream.read(script_len)
        
        # Read value (varint)
        value = read_varint(self.rev_stream)
        
        return {
            'value_sats': value,
            'script_pubkey_hex': script.hex()
        }
    
    def parse_coinbase(self, coinbase_tx: Dict) -> Dict[str, Any]:
        """Parse coinbase transaction"""
        # Get first input's scriptSig
        scriptsig_hex = coinbase_tx['inputs'][0]['script_sig_hex']
        scriptsig = bytes.fromhex(scriptsig_hex)
        
        # Decode BIP34 height (first byte is push length, then height in little-endian)
        bip34_height = None
        if len(scriptsig) >= 4:
            try:
                # First byte is the push opcode (number of bytes)
                push_len = scriptsig[0]
                if push_len <= 4 and len(scriptsig) >= push_len + 1:
                    height_bytes = scriptsig[1:1+push_len]
                    bip34_height = int.from_bytes(height_bytes, 'little')
            except:
                bip34_height = None
        
        # Calculate total coinbase output
        total_output = sum(out['value_sats'] for out in coinbase_tx['outputs'])
        
        return {
            'bip34_height': bip34_height,
            'coinbase_script_hex': scriptsig_hex,
            'total_output_sats': total_output
        }