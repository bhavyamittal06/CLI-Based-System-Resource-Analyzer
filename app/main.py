#!/usr/bin/env python3
"""
Main entry point for Bitcoin transaction analyzer
Called by cli.sh
"""

import sys
import os
import json
from pathlib import Path
def safe_get(lst, index):
    return lst[index] if isinstance(lst, list) and len(lst) > index else None
# Ensure the script's directory is in the Python path
# This fixes "ModuleNotFoundError: No module named 'utils'"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

# Import from reader (not readers!)
from reader import read_fixture, validate_prevouts_match_inputs
from parser import TransactionParser
from analyzer import TransactionAnalyzer
from utils import disassemble_script


def error_response(code: str, message: str) -> dict:
    """Create error response"""
    return {
        'ok': False,
        'error': {
            'code': code,
            'message': message
        }
    }


def analyze_transaction(fixture_path: str) -> dict:
    """Main analysis function for single transaction"""
    try:
        # Read fixture
        fixture = read_fixture(fixture_path)
        raw_tx = fixture['raw_tx']
        prevouts = fixture['prevouts']
        
        # Parse transaction
        parser = TransactionParser(raw_tx)
        tx_data = parser.parse()
        
        # Validate prevouts match inputs
        input_refs = [(inp['txid'], inp['vout']) for inp in tx_data['inputs']]
        validate_prevouts_match_inputs(prevouts, input_refs)
        
        # Calculate IDs
        txid = parser.calculate_txid()
        wtxid = parser.calculate_wtxid() if tx_data['is_segwit'] else None
        
        # Calculate weight and size
        size_bytes, weight, vbytes = parser.calculate_weight_and_size()
        vbytes = int(vbytes)  # Convert to integer as required by spec
        
        # Create analyzer
        analyzer = TransactionAnalyzer(tx_data, prevouts)
        
        # Calculate fees
        prevouts_map = {(p['txid'], p['vout']): p for p in prevouts}
        total_input = sum(prevouts_map[(inp['txid'], inp['vout'])]['value_sats'] 
                         for inp in tx_data['inputs'])
        total_output = sum(out['value_sats'] for out in tx_data['outputs'])
        fee_sats = total_input - total_output
        fee_rate_sat_vb = round(fee_sats / vbytes, 2) if vbytes > 0 else 0.0
        
        # RBF detection
        rbf_signaling = any(inp['sequence'] < 0xfffffffe for inp in tx_data['inputs'])
        
        # Locktime
        locktime_type, locktime_value = analyzer.analyze_locktime(tx_data['locktime'])
        
        # Process inputs
        vin = []
        for idx, inp in enumerate(tx_data['inputs']):
            prevout = prevouts_map[(inp['txid'], inp['vout'])]
            witness = tx_data['witnesses'][idx]
            
            script_type, address = analyzer.classify_input(inp, prevout, witness)
            script_asm = disassemble_script(inp['script_sig_hex'])
            
            vin_entry = {
                'txid': inp['txid'],
                'vout': inp['vout'],
                'prevout': {
                    'value_sats': prevout['value_sats'],
                    'script_pubkey_hex': prevout['script_pubkey_hex']
                },
                'script_sig_hex': inp['script_sig_hex'],
                'script_asm': script_asm,
                'witness': witness,
                'sequence': inp['sequence'],
                'script_type': script_type,
                'address': address,
                'relative_timelock': analyzer.analyze_relative_timelock(inp['sequence'])
            }
            
            
               # Add witness_script_asm for P2WSH/P2SH-P2WSH
            if script_type in ['p2wsh', 'p2sh-p2wsh'] and witness and len(witness) > 0:
                witness_script_asm = disassemble_script(witness[-1])
                vin_entry['witness_script_asm'] = witness_script_asm
                
        # Process outputs
        vout = []
        for idx, out in enumerate(tx_data['outputs']):
            script_type, address = analyzer.classify_output_script(out['script_pubkey_hex'])
            script_asm = disassemble_script(out['script_pubkey_hex'])
            
            vout_entry = {
                'n': idx,
                'value_sats': out['value_sats'],
                'script_pubkey_hex': out['script_pubkey_hex'],
                'script_asm': script_asm,
                'script_type': script_type,
                'address': address
            }
            
            # OP_RETURN extras
            if script_type == 'op_return':
                op_return_data = analyzer.parse_op_return(out['script_pubkey_hex'])
                vout_entry.update(op_return_data)
            
            vout.append(vout_entry)
        
        # Warnings
        warnings = analyzer.generate_warnings(fee_sats, fee_rate_sat_vb, vout, rbf_signaling)
        
        # SegWit savings
        if tx_data['is_segwit']:
            non_witness_tx = parser._serialize_non_witness()
            non_witness_bytes = len(non_witness_tx)
            total_bytes = len(parser.raw_bytes)
            witness_bytes = total_bytes - non_witness_bytes - 2  # -2 for marker/flag
            segwit_savings = analyzer.calculate_segwit_savings(weight, non_witness_bytes, witness_bytes)
        else:
            segwit_savings = None
        
        # Build result
        result = {
            'ok': True,
            'network': fixture.get('network', 'mainnet'),
            'segwit': tx_data['is_segwit'],
            'txid': txid,
            'wtxid': wtxid,
            'version': tx_data['version'],
            'locktime': tx_data['locktime'],
            'locktime_type': locktime_type,
            'locktime_value': locktime_value,
            'size_bytes': size_bytes,
            'weight': weight,
            'vbytes': vbytes,
            'total_input_sats': total_input,
            'total_output_sats': total_output,
            'fee_sats': fee_sats,
            'fee_rate_sat_vb': fee_rate_sat_vb,
            'rbf_signaling': rbf_signaling,
            'vin': vin,
            'vout': vout,
            'warnings': warnings,
            'segwit_savings': segwit_savings
        }
        
        # Write to output file
        output_dir = Path('out')
        output_dir.mkdir(exist_ok=True)
        output_file = output_dir / f'{txid}.json'
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        
        return result
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return error_response('ANALYSIS_ERROR', str(e))


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print(json.dumps(error_response('INVALID_ARGS', 'No input file provided')))
        sys.exit(1)
    
    # Check for block mode
    if sys.argv[1] == '--block':
        if len(sys.argv) < 5:
            print(json.dumps(error_response('INVALID_ARGS', 'Block mode requires: --block <blk> <rev> <xor>')))
            sys.exit(1)
        
        # Import block parser
        from block_parser import BlockParser, read_xor_key
        
        blk_file = sys.argv[2]
        rev_file = sys.argv[3]
        xor_file = sys.argv[4]
        
        try:
            # Read XOR key
            xor_key = read_xor_key(xor_file)
            
            # Parse blocks
            parser = BlockParser(blk_file, rev_file, xor_key)
            blocks = parser.parse_all_blocks()
            
            # Write output for each block
            Path('out').mkdir(exist_ok=True)
            
            for block_data in blocks:
                header = block_data['header']
                block_hash = header['block_hash']
                prevouts_map = block_data['prevouts']
                
                # Analyze each transaction in the block
                analyzed_txs = []
                total_fees = 0
                total_weight = 0
                script_type_counts = {}
                
                for tx_idx, tx_data in enumerate(block_data['transactions']):
                    # Create prevouts list for this transaction (skip coinbase)
                    tx_prevouts = []
                    if tx_idx > 0:  # Not coinbase
                        for inp in tx_data['inputs']:
                            key = (inp['txid'], inp['vout'])
                            if key in prevouts_map:
                                tx_prevouts.append(prevouts_map[key])
                    
                    # Analyze transaction using existing analyzer
                    from parser import TransactionParser
                    tx_parser = TransactionParser(tx_data['raw_tx_hex'])
                    parsed_tx = tx_parser.parse()
                    
                    txid = tx_parser.calculate_txid()
                    wtxid = tx_parser.calculate_wtxid() if parsed_tx['is_segwit'] else None
                    size_bytes, weight, vbytes = tx_parser.calculate_weight_and_size()
                    vbytes = int(vbytes)
                    
                    # Calculate fees (skip coinbase)
                    if tx_idx > 0 and tx_prevouts:
                        total_input = sum(p['value_sats'] for p in tx_prevouts)
                        total_output = sum(out['value_sats'] for out in parsed_tx['outputs'])
                        fee_sats = total_input - total_output
                        total_fees += fee_sats
                    else:
                        fee_sats = 0
                        total_input = 0
                        total_output = sum(out['value_sats'] for out in parsed_tx['outputs'])
                    
                    total_weight += weight
                    fee_rate = round(fee_sats / vbytes, 2) if vbytes > 0 else 0.0
                    
                    # Analyze with full pipeline
                    analyzer = TransactionAnalyzer(parsed_tx, tx_prevouts if tx_prevouts else [])
                    
                    # Process inputs
                    vin = []
                    for idx, inp in enumerate(parsed_tx['inputs']):
                        if tx_idx == 0:  # Coinbase
                            prevout_data = {
                                'value_sats': 0,
                                'script_pubkey_hex': ''
                            }
                            script_type = 'coinbase'
                            address = None
                        else:
                            key = (inp['txid'], inp['vout'])
                            prevout_data = prevouts_map.get(key, {'value_sats': 0, 'script_pubkey_hex': ''})
                            witness = parsed_tx['witnesses'][idx]
                            script_type, address = analyzer.classify_input(inp, prevout_data, witness)
                        
                        vin_entry = {
                            'txid': inp['txid'],
                            'vout': inp['vout'],
                            'prevout': prevout_data,
                            'script_sig_hex': inp['script_sig_hex'],
                            'script_asm': disassemble_script(inp['script_sig_hex']),
                            'witness': parsed_tx['witnesses'][idx],
                            'sequence': inp['sequence'],
                            'script_type': script_type,
                            'address': address,
                            'relative_timelock': analyzer.analyze_relative_timelock(inp['sequence'])
                        }
                        vin.append(vin_entry)
                    
                    # Process outputs
                    vout = []
                    for idx, out in enumerate(parsed_tx['outputs']):
                        script_type, address = analyzer.classify_output_script(out['script_pubkey_hex'])
                        
                        # Count script types
                        script_type_counts[script_type] = script_type_counts.get(script_type, 0) + 1
                        
                        vout_entry = {
                            'n': idx,
                            'value_sats': out['value_sats'],
                            'script_pubkey_hex': out['script_pubkey_hex'],
                            'script_asm': disassemble_script(out['script_pubkey_hex']),
                            'script_type': script_type,
                            'address': address
                        }
                        
                        if script_type == 'op_return':
                            op_return_data = analyzer.parse_op_return(out['script_pubkey_hex'])
                            vout_entry.update(op_return_data)
                        
                        vout.append(vout_entry)
                    
                    # Build transaction result
                    locktime_type, locktime_value = analyzer.analyze_locktime(parsed_tx['locktime'])
                    rbf_signaling = any(inp['sequence'] < 0xfffffffe for inp in parsed_tx['inputs'])
                    warnings = analyzer.generate_warnings(fee_sats, fee_rate, vout, rbf_signaling)
                    
                    segwit_savings = None
                    if parsed_tx['is_segwit']:
                        non_witness_tx = tx_parser._serialize_non_witness()
                        non_witness_bytes = len(non_witness_tx)
                        total_bytes = len(tx_parser.raw_bytes)
                        witness_bytes = total_bytes - non_witness_bytes - 2
                        segwit_savings = analyzer.calculate_segwit_savings(weight, non_witness_bytes, witness_bytes)
                    
                    tx_result = {
                        'ok': True,
                        'network': 'mainnet',
                        'segwit': parsed_tx['is_segwit'],
                        'txid': txid,
                        'wtxid': wtxid,
                        'version': parsed_tx['version'],
                        'locktime': parsed_tx['locktime'],
                        'locktime_type': locktime_type,
                        'locktime_value': locktime_value,
                        'size_bytes': size_bytes,
                        'weight': weight,
                        'vbytes': vbytes,
                        'total_input_sats': total_input,
                        'total_output_sats': total_output,
                        'fee_sats': fee_sats,
                        'fee_rate_sat_vb': fee_rate,
                        'rbf_signaling': rbf_signaling,
                        'vin': vin,
                        'vout': vout,
                        'warnings': warnings,
                        'segwit_savings': segwit_savings
                    }
                    
                    analyzed_txs.append(tx_result)
                
                # Calculate average fee rate
                total_vbytes = sum(tx['vbytes'] for tx in analyzed_txs if tx.get('vbytes', 0) > 0)
                avg_fee_rate = round(total_fees / total_vbytes, 2) if total_vbytes > 0 else 0.0
                
                # Build block result
                result = {
                    'ok': True,
                    'mode': 'block',
                    'block_header': {
                        'version': header['version'],
                        'prev_block_hash': header['prev_block_hash'],
                        'merkle_root': header['merkle_root'],
                        'merkle_root_valid': header.get('merkle_root_valid', False),
                        'timestamp': header['timestamp'],
                        'bits': header['bits'],
                        'nonce': header['nonce'],
                        'block_hash': header['block_hash']
                    },
                    'tx_count': block_data['tx_count'],
                    'coinbase': block_data['coinbase'],
                    'transactions': analyzed_txs,
                    'block_stats': {
                        'total_fees_sats': total_fees,
                        'total_weight': total_weight,
                        'avg_fee_rate_sat_vb': avg_fee_rate,
                        'script_type_summary': script_type_counts
                    }
                }
                
                # Write to file (NO stdout in block mode!)
                output_file = Path('out') / f"{block_hash}.json"
                with open(output_file, 'w') as f:
                    json.dump(result, f, indent=2)
            
            # Block mode exits without printing
            sys.exit(0)
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            # Even errors shouldn't print to stdout in block mode
            sys.exit(1)
    
    # Transaction mode
    fixture_path = sys.argv[1]
    result = analyze_transaction(fixture_path)
    
    # Print result (only in transaction mode!)
    print(json.dumps(result, indent=2))
    
    # Exit code
    if result.get('ok', False):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()