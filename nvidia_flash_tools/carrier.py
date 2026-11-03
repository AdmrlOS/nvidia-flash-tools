"""Board-specific carrier identity rule for the Seeed reComputer J40/J4012 (J401).

The Seeed J401 carrier has no NVIDIA-format carrier EEPROM at the devkit
address (its MB2 configuration zeroes ``cvb_eeprom_read_size``), so the exact
``cvb == 3768-0000`` rule used for the NVIDIA P3768 carrier cannot identify it.
The module (cvm) identity and fuse checks stay exactly as strict as orin-nx.
For the carrier this module implements ONE documented rule:

* the cvb result is recorded verbatim (sha256 + decoded fields, or the exact
  failure) in the board identity, which the destructive approval digest binds;
* the run may proceed only when the cvb outcome is accepted by ``CVB_TABLE``
  below, which never accepts anything that decodes as an NVIDIA carrier; and
* the operator types ``CONFIRMATION`` at the identity stage, also bound.

No hardware capture of the real J401 cvb result exists yet. ``CVB_TABLE`` and
``PINNED_CVB_SHA256`` are the single place to tighten once one is pasted back.
"""
import copy
import json
import re

BOARD = 'recomputer-j40'
CARRIER = 'seeed-j401'
RULE = 'recomputer-j40-cvb-v2'
CONFIRMATION = 'OBSERVED SEEED RECOMPUTER J401 CARRIER'
EEPROM_SIZE = 256
# MB2's own answer when nothing responds at NVIDIA's carrier EEPROM address
# (observed on a J4012, R39.2.1). NVIDIA's tegraflash then retries through
# tegradevflash with tegrarcm-only --chip arguments, which fails with "Invalid
# option --chip"; that retry is noise and never evidence.
MB2_NO_CVB = 'NV3P_SERVER: Could not read eeprom for module cvb.'
_MB2_NO_CVB = re.compile(r'E> ' + re.escape(MB2_NO_CVB))

# Boards whose carrier is established by this rule instead of exact cvb equality.
BOARDS = (BOARD,)

# NVIDIA carrier part numbers that must never be mistaken for the J401. The
# generic 4-digit rule below also refuses every other NVIDIA-format decode.
NVIDIA_CARRIER_IDS = ('3768', '3509', '3737', '4071')

# The single cvb outcome table: (outcome, accepted, meaning). Order is the
# classification precedence documented in docs/reference.md.
CVB_TABLE = (
    ('dump-failed', True,
     "no file, and MB2 answered '" + MB2_NO_CVB + "': nothing at NVIDIA's carrier EEPROM address"),
    ('dump-error', False,
     "dump exited non-zero or wrote no file WITHOUT that MB2 answer (tool, USB or applet error)"),
    ('unexpected-size', False,
     'dump succeeded but the output is not a regular 256-byte single-link file'),
    ('nvidia-carrier-decoded', False,
     'chkbdinfo -i or -k returned a 4-digit NVIDIA board id/SKU '
     '(includes 3768, 3509, 3737, 4071)'),
    ('blank-zero', True, '256 bytes of 0x00 and neither decoder returned a value'),
    ('blank-ff', True, '256 bytes of 0xff and neither decoder returned a value'),
    ('undecodable', True,
     '256 bytes, not silently blank, and no decoder returned an NVIDIA-format '
     '(4-digit) id/SKU'),
)
ACCEPTED = frozenset(name for name, accepted, _ in CVB_TABLE if accepted)
OUTCOMES = frozenset(name for name, _, _ in CVB_TABLE)

# Tightening hook: when non-empty, an 'undecodable' cvb must have exactly one
# of these sha256 values (the captured Seeed EEPROM contents).
PINNED_CVB_SHA256 = frozenset()

_NVIDIA_FIELD = re.compile(r'[0-9]{4}')


def requires_confirmation(board):
    return board in BOARDS


def classify(*, dump_returncode, data, decoded, mb2_no_cvb=False):
    """Return the CVB_TABLE outcome name.

    ``data`` is the 256-byte cvb file contents, ``None`` when the dump did not
    produce a usable file, or ``False`` when a file exists with an unacceptable
    form. ``decoded`` maps ``-i``/``-k`` to a decoded value or ``None``.
    ``mb2_no_cvb``: the dump output carries MB2's own no-EEPROM answer.
    """
    if dump_returncode != 0 or data is None:
        return 'dump-failed' if mb2_no_cvb else 'dump-error'
    if data is False or len(data) != EEPROM_SIZE:
        return 'unexpected-size'
    if any(value is not None and _NVIDIA_FIELD.fullmatch(value) for value in decoded.values()):
        return 'nvidia-carrier-decoded'
    silent = all(value is None for value in decoded.values())
    if silent and data == b'\x00' * EEPROM_SIZE:
        return 'blank-zero'
    if silent and data == b'\xff' * EEPROM_SIZE:
        return 'blank-ff'
    return 'undecodable'


def reason(outcome, decoded=None):
    meaning = next(text for name, _, text in CVB_TABLE if name == outcome)
    named = [v for v in (decoded or {}).values() if v in NVIDIA_CARRIER_IDS]
    return meaning + (' [' + ', '.join(sorted(set(named))) + ']' if named else '')


def evidence(*, dump_returncode, dump_output, data, sha256, size, decoders):
    """Build the verbatim cvb record. ``decoders``: flag -> (returncode, output)."""
    decoded = {}
    stable_decoders = {}
    for flag in ('-i', '-k'):
        returncode, output = decoders.get(flag, (None, ''))
        text = (output or '').strip()
        stable_decoders[flag] = {'returncode': returncode, 'output': text[:200]}
        decoded[flag] = text if returncode == 0 and text and '\n' not in text else None
    output = dump_output or ''
    mb2 = _MB2_NO_CVB.search(output) is not None
    outcome = classify(dump_returncode=dump_returncode, data=data, decoded=decoded, mb2_no_cvb=mb2)
    return {'rule': RULE, 'outcome': outcome,
            'cvb_sha256': sha256,
            'cvb_size': size,
            'dump_returncode': dump_returncode,
            'mb2_answer': MB2_NO_CVB if mb2 else None,
            'decoded': {'id': decoded['-i'], 'sku': decoded['-k']},
            'decoders': stable_decoders,
            'reason': reason(outcome, decoded),
            # tegraflash logs carry timestamps; kept verbatim for the approval
            # record but excluded from the same-board re-probe comparison.
            'volatile': {'dump_output_tail': output[-2000:]}}


def check_evidence(record):
    """Re-derive acceptance from CVB_TABLE; never trust a stored flag."""
    if not isinstance(record, dict) or record.get('rule') != RULE:
        raise ValueError('missing/unknown recomputer-j40 carrier evidence')
    outcome = record.get('outcome')
    if outcome not in OUTCOMES:
        raise ValueError('unknown recomputer-j40 cvb outcome')
    if outcome not in ACCEPTED:
        shown = {k: v for k, v in record.items() if k != 'volatile'}
        raise ValueError('recomputer-j40 carrier refused: cvb outcome ' + outcome + ': ' +
                         str(record.get('reason')) + ' evidence=' + json.dumps(shown, sort_keys=True))
    if outcome == 'undecodable' and PINNED_CVB_SHA256 and record.get('cvb_sha256') not in PINNED_CVB_SHA256:
        raise ValueError('recomputer-j40 carrier refused: cvb sha256 is not a pinned J401 capture')
    return record


def stable(identity):
    """Identity as compared across same-board re-probes."""
    result = copy.deepcopy(dict(identity))
    result.pop('uefi_policy', None)
    result.pop('carrier_confirmation', None)
    if isinstance(result.get('carrier_evidence'), dict):
        result['carrier_evidence'].pop('volatile', None)
    return result


def bind_confirmation(identity, typed):
    """Bind the operator's typed phrase and the evidence into the identity."""
    check_evidence(identity.get('carrier_evidence'))
    if identity.get('carrier') != CARRIER or identity.get('carrier_rule') != RULE:
        raise ValueError('recomputer-j40 carrier identity not established by the carrier rule')
    if typed != CONFIRMATION:
        raise ValueError('explicit ' + CONFIRMATION + ' confirmation required; no carrier assumed')
    identity['carrier_confirmation'] = typed
    return identity


def validate_bound(identity):
    """Approval guard: a J401 identity must carry accepted evidence AND confirmation."""
    if identity.get('carrier') != CARRIER and identity.get('carrier_rule') is None:
        return
    check_evidence(identity.get('carrier_evidence'))
    if (identity.get('carrier') != CARRIER or identity.get('carrier_rule') != RULE or
            identity.get('carrier_confirmation') != CONFIRMATION):
        raise ValueError('recomputer-j40 approval requires the bound carrier confirmation')


def describe(identity):
    record = identity['carrier_evidence']
    lines = ['Module (cvm, exact): ' + identity['module'],
             'Carrier EEPROM (cvb) outcome: ' + record['outcome'] + ' - ' + record['reason'],
             '  cvb sha256: ' + str(record['cvb_sha256']) + '  size: ' + str(record['cvb_size']),
             '  tegraflash dump returncode: ' + str(record['dump_returncode']),
             '  MB2 answer: ' + str(record.get('mb2_answer')),
             '  chkbdinfo -i: ' + repr(record['decoders']['-i']) + '  -k: ' + repr(record['decoders']['-k'])]
    tail = record.get('volatile', {}).get('dump_output_tail')
    if record['outcome'] in ('dump-failed', 'dump-error') and tail:
        lines.append("  (NVIDIA's tegradevflash retry after MB2's answer fails on '--chip'; that is noise)")
        lines.append('  dump output (tail): ' + tail.strip().replace('\n', '\n    '))
    return '\n'.join(lines)
