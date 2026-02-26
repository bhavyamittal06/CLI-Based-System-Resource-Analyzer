"""
Utility functions for Bitcoin transaction analysis
"""

import hashlib
from typing import Optional


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data))"""
    sha = hashlib.sha256(data).digest()
    ripemd = hashlib.new('ripemd160')
    ripemd.update(sha)
    return ripemd.digest()


def double_sha256(data: bytes) -> bytes:
    """SHA256(SHA256(data))"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def encode_base58(data: bytes) -> str:
    """Encode bytes to Base58"""
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    
    # Convert bytes to integer
    num = int.from_bytes(data, 'big')
    
    # Convert to base58
    encoded = ''
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = alphabet[remainder] + encoded
    
    # Add '1' for each leading zero byte
    for byte in data:
        if byte == 0:
            encoded = '1' + encoded
        else:
            break
    
    return encoded or '1'


def encode_base58check(payload: bytes) -> str:
    """Encode with Base58Check (payload + 4-byte checksum)"""
    checksum = double_sha256(payload)[:4]
    return encode_base58(payload + checksum)


def bech32_polymod(values):
    """Bech32 checksum polymod"""
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    """Expand HRP for Bech32 checksum"""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp, data, const):
    """Create Bech32/Bech32m checksum"""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp, witver, witprog, const):
    """Encode Bech32/Bech32m address"""
    charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    
    # Convert witness program to 5-bit groups
    data = [witver] + convertbits(witprog, 8, 5, True)
    
    # Create checksum
    checksum = bech32_create_checksum(hrp, data, const)
    
    # Combine and encode
    combined = data + checksum
    return hrp + '1' + ''.join([charset[d] for d in combined])


def convertbits(data, frombits, tobits, pad=True):
    """Convert between bit groups"""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    
    for value in data:
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    
    return ret


def encode_bech32(hrp: str, witver: int, witprog: bytes) -> str:
    """Encode Bech32 address (for witness v0)"""
    BECH32_CONST = 1
    return bech32_encode(hrp, witver, list(witprog), BECH32_CONST)


def encode_bech32m(hrp: str, witver: int, witprog: bytes) -> str:
    """Encode Bech32m address (for witness v1+)"""
    BECH32M_CONST = 0x2bc830a3
    return bech32_encode(hrp, witver, list(witprog), BECH32M_CONST)


def read_varint(stream) -> int:
    """Read Bitcoin varint from byte stream"""
    first = stream.read(1)[0]
    
    if first < 0xfd:
        return first
    elif first == 0xfd:
        return int.from_bytes(stream.read(2), 'little')
    elif first == 0xfe:
        return int.from_bytes(stream.read(4), 'little')
    else:  # 0xff
        return int.from_bytes(stream.read(8), 'little')


def write_varint(n: int) -> bytes:
    """Encode integer as Bitcoin varint"""
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    elif n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    else:
        return b'\xff' + n.to_bytes(8, 'little')


# Opcode definitions
OPCODES = {
    0x00: 'OP_0',
    0x4c: 'OP_PUSHDATA1',
    0x4d: 'OP_PUSHDATA2',
    0x4e: 'OP_PUSHDATA4',
    0x4f: 'OP_1NEGATE',
    0x51: 'OP_1', 0x52: 'OP_2', 0x53: 'OP_3', 0x54: 'OP_4',
    0x55: 'OP_5', 0x56: 'OP_6', 0x57: 'OP_7', 0x58: 'OP_8',
    0x59: 'OP_9', 0x5a: 'OP_10', 0x5b: 'OP_11', 0x5c: 'OP_12',
    0x5d: 'OP_13', 0x5e: 'OP_14', 0x5f: 'OP_15', 0x60: 'OP_16',
    0x61: 'OP_NOP', 0x63: 'OP_IF', 0x64: 'OP_NOTIF',
    0x67: 'OP_ELSE', 0x68: 'OP_ENDIF', 0x69: 'OP_VERIFY',
    0x6a: 'OP_RETURN', 0x6b: 'OP_TOALTSTACK', 0x6c: 'OP_FROMALTSTACK',
    0x6d: 'OP_2DROP', 0x6e: 'OP_2DUP', 0x6f: 'OP_3DUP',
    0x70: 'OP_2OVER', 0x71: 'OP_2ROT', 0x72: 'OP_2SWAP',
    0x73: 'OP_IFDUP', 0x74: 'OP_DEPTH', 0x75: 'OP_DROP',
    0x76: 'OP_DUP', 0x77: 'OP_NIP', 0x78: 'OP_OVER',
    0x79: 'OP_PICK', 0x7a: 'OP_ROLL', 0x7b: 'OP_ROT',
    0x7c: 'OP_SWAP', 0x7d: 'OP_TUCK', 0x82: 'OP_SIZE',
    0x87: 'OP_EQUAL', 0x88: 'OP_EQUALVERIFY',
    0x8b: 'OP_1ADD', 0x8c: 'OP_1SUB', 0x8f: 'OP_NEGATE',
    0x90: 'OP_ABS', 0x91: 'OP_NOT', 0x92: 'OP_0NOTEQUAL',
    0x93: 'OP_ADD', 0x94: 'OP_SUB', 0x9a: 'OP_BOOLAND',
    0x9b: 'OP_BOOLOR', 0x9c: 'OP_NUMEQUAL', 0x9d: 'OP_NUMEQUALVERIFY',
    0x9e: 'OP_NUMNOTEQUAL', 0x9f: 'OP_LESSTHAN',
    0xa0: 'OP_GREATERTHAN', 0xa1: 'OP_LESSTHANOREQUAL',
    0xa2: 'OP_GREATERTHANOREQUAL', 0xa3: 'OP_MIN', 0xa4: 'OP_MAX',
    0xa5: 'OP_WITHIN', 0xa6: 'OP_RIPEMD160', 0xa7: 'OP_SHA1',
    0xa8: 'OP_SHA256', 0xa9: 'OP_HASH160', 0xaa: 'OP_HASH256',
    0xab: 'OP_CODESEPARATOR', 0xac: 'OP_CHECKSIG',
    0xad: 'OP_CHECKSIGVERIFY', 0xae: 'OP_CHECKMULTISIG',
    0xaf: 'OP_CHECKMULTISIGVERIFY', 0xb1: 'OP_CHECKLOCKTIMEVERIFY',
    0xb2: 'OP_CHECKSEQUENCEVERIFY',
}


def disassemble_script(script_hex: str) -> str:
    """Disassemble Bitcoin script to human-readable format"""
    if not script_hex:
        return ""
    
    script = bytes.fromhex(script_hex)
    asm_parts = []
    i = 0
    
    while i < len(script):
        opcode = script[i]
        i += 1
        
        # Direct push (1-75 bytes)
        if 1 <= opcode <= 75:
            if i + opcode > len(script):
                break
            data = script[i:i+opcode]
            asm_parts.append(f'OP_PUSHBYTES_{opcode} {data.hex()}')
            i += opcode
        
        # OP_PUSHDATA1
        elif opcode == 0x4c:
            if i >= len(script):
                break
            length = script[i]
            i += 1
            if i + length > len(script):
                break
            data = script[i:i+length]
            asm_parts.append(f'OP_PUSHDATA1 {data.hex()}')
            i += length
        
        # OP_PUSHDATA2
        elif opcode == 0x4d:
            if i + 1 >= len(script):
                break
            length = int.from_bytes(script[i:i+2], 'little')
            i += 2
            if i + length > len(script):
                break
            data = script[i:i+length]
            asm_parts.append(f'OP_PUSHDATA2 {data.hex()}')
            i += length
        
        # OP_PUSHDATA4
        elif opcode == 0x4e:
            if i + 3 >= len(script):
                break
            length = int.from_bytes(script[i:i+4], 'little')
            i += 4
            if i + length > len(script):
                break
            data = script[i:i+length]
            asm_parts.append(f'OP_PUSHDATA4 {data.hex()}')
            i += length
        
        # Named opcode
        elif opcode in OPCODES:
            asm_parts.append(OPCODES[opcode])
        
        # Unknown opcode
        else:
            asm_parts.append(f'OP_UNKNOWN_{opcode:#04x}')
    
    return ' '.join(asm_parts)