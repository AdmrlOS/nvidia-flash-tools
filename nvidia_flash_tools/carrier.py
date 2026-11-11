"""Board-specific carrier identity rules for carriers without an NVIDIA carrier EEPROM.

Two boards use this module, each with its own rule id, carrier name,
confirmation phrase and accepted cvb outcomes:

* ``recomputer-j40``: Seeed reComputer J40/J4012, Orin NX 16GB on Seeed's J401
  carrier (Seeed's MB2 configuration zeroes ``cvb_eeprom_read_size``).
* ``mic-733-ao``: Advantech MIC-733-AO, AGX Orin 64GB (P3701-0005) on
  Advantech's MIC-733 carrier (Advantech's MB2 BCT zeroes
  ``cvb_eeprom_read_size``; with NVIDIA's default MB2 busy-spins in "Prepare
  eeprom data" on this carrier).

Neither carrier has an NVIDIA-format carrier EEPROM at the devkit address, so
the exact ``cvb == <NVIDIA carrier>`` rule used for NVIDIA's own carriers cannot
identify them. The module (cvm) identity and fuse checks stay exactly as strict
as for NVIDIA boards. For the carrier each board has ONE documented rule:

* the cvb result is recorded verbatim (sha256 + decoded fields, or the exact
  failure) in the board identity, which the destructive approval digest binds;
* the run may proceed only when the cvb outcome is accepted for that board
  (``CVB_TABLE`` classifies; ``ACCEPTED`` / ``MIC733_ACCEPTED`` decide), which
  never accepts anything that decodes as an NVIDIA carrier; and
* the operator types the board's confirmation phrase at the identity stage,
  also bound.

recomputer-j40: one real J4012 answered with MB2's ``dump-failed`` line.

mic-733-ao: one real MIC-733-AO6A1 (P3701-0005, R39.2.1 RAM-only probe)
answered with MB2's ``dump-failed`` line; the rule accepts only that outcome.
"""
import copy
import json
import re

EEPROM_SIZE = 256
# MB2's own answer when nothing responds at NVIDIA's carrier EEPROM address
# (observed on a J4012, R39.2.1). NVIDIA's tegraflash then retries through
# tegradevflash with tegrarcm-only --chip arguments, which fails with "Invalid
# option --chip"; that retry is noise and never evidence.
MB2_NO_CVB = 'NV3P_SERVER: Could not read eeprom for module cvb.'
_MB2_NO_CVB = re.compile(r'E> ' + re.escape(MB2_NO_CVB))

# The single cvb outcome table: (outcome, accepted for recomputer-j40, meaning).
# Order is the classification precedence documented in docs/reference.md. The
# classification is shared; each board's accepted set is below.
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
OUTCOMES = frozenset(name for name, _, _ in CVB_TABLE)

# recomputer-j40 (Seeed J401).
BOARD = 'recomputer-j40'
CARRIER = 'seeed-j401'
RULE = 'recomputer-j40-cvb-v2'
CONFIRMATION = 'OBSERVED SEEED RECOMPUTER J401 CARRIER'
ACCEPTED = frozenset(name for name, accepted, _ in CVB_TABLE if accepted)
# NVIDIA carrier part numbers that must never be mistaken for the J401. The
# generic 4-digit rule also refuses every other NVIDIA-format decode.
NVIDIA_CARRIER_IDS = ('3768', '3509', '3737', '4071')
# Tightening hook: when non-empty, an 'undecodable' cvb must have exactly one
# of these sha256 values (the captured Seeed EEPROM contents).
PINNED_CVB_SHA256 = frozenset()

# mic-733-ao (Advantech MIC-733). Accepted set tightened from the first real
# RAM-only probe (dump-failed); never loosen it from documentation alone.
MIC733_BOARD = 'mic-733-ao'
MIC733_CARRIER = 'advantech-mic-733'
MIC733_RULE = 'mic-733-ao-cvb-v2'
MIC733_CONFIRMATION = 'OBSERVED ADVANTECH MIC-733-AO CARRIER'
MIC733_ACCEPTED = frozenset({'dump-failed'})
# NVIDIA carriers a P3701 module is found on (P3737 AGX Orin devkit first, then
# IGX/other NVIDIA carriers). Any other 4-digit decode is refused as well.
MIC733_NVIDIA_CARRIER_IDS = ('3737', '3711', '3740', '3768', '3509', '4071')
MIC733_PINNED_CVB_SHA256 = frozenset()
# Bound on the tolerated carrier dump. Advantech disables MB2's boot-time cvb
# read because MB2 spins on this carrier; if the RAM applet's dump spins the
# same way, the probe stops (refused) instead of waiting tegraflash's 30 min.
MIC733_CVB_TIMEOUT = 180

RULES = {
    BOARD: {'board': BOARD, 'carrier': CARRIER, 'rule': RULE, 'confirmation': CONFIRMATION,
            'accepted': 'ACCEPTED', 'pinned': 'PINNED_CVB_SHA256', 'nvidia_ids': 'NVIDIA_CARRIER_IDS',
            'label': 'J401', 'cvb_timeout': None,
            'unit': 'a Seeed reComputer J40/J4012 with its original J401 carrier',
            'no_eeprom': 'The Seeed J401 carrier has no NVIDIA carrier EEPROM',
            'power_cycle': ("The J401 has no NVIDIA carrier EEPROM; that read leaves NVIDIA's flashing applet "
                            "running. Power-cycle the unit with the Force Recovery jumper still fitted."),
            'reenter': 'power-cycle the unit with the jumper fitted'},
    MIC733_BOARD: {'board': MIC733_BOARD, 'carrier': MIC733_CARRIER, 'rule': MIC733_RULE,
                   'confirmation': MIC733_CONFIRMATION, 'accepted': 'MIC733_ACCEPTED',
                   'pinned': 'MIC733_PINNED_CVB_SHA256', 'nvidia_ids': 'MIC733_NVIDIA_CARRIER_IDS',
                   'label': 'MIC-733-AO', 'cvb_timeout': MIC733_CVB_TIMEOUT,
                   'unit': 'an Advantech MIC-733-AO (AGX Orin 64GB) with its original Advantech carrier',
                   'no_eeprom': 'The Advantech MIC-733 carrier has no NVIDIA carrier EEPROM',
                   'power_cycle': ("The MIC-733-AO has no NVIDIA carrier EEPROM; if that read leaves NVIDIA's "
                                   "flashing applet running the boot ROM no longer answers. Re-enter Force "
                                   "Recovery: hold the recovery button SW_REC1, press and release the reset "
                                   "button SW_RST1, then release SW_REC1."),
                   'reenter': 're-enter Force Recovery (hold SW_REC1, press and release SW_RST1, '
                              'then release SW_REC1)'},
}
# Boards whose carrier is established by a rule here instead of exact cvb equality.
BOARDS = tuple(RULES)
_BY_RULE = {rule['rule']: rule for rule in RULES.values()}
_BY_CARRIER = {rule['carrier']: rule for rule in RULES.values()}

_NVIDIA_FIELD = re.compile(r'[0-9]{4}')


def requires_confirmation(board):
    return board in RULES


def rule_for(board):
    if board not in RULES:
        raise ValueError('no carrier rule for board ' + str(board))
    return RULES[board]


def accepted(board):
    # Looked up at call time: the tightening hooks are module attributes.
    return globals()[rule_for(board)['accepted']]


def _pinned(board):
    return globals()[rule_for(board)['pinned']]


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


def reason(outcome, decoded=None, board=BOARD):
    meaning = next(text for name, _, text in CVB_TABLE if name == outcome)
    ids = globals()[rule_for(board)['nvidia_ids']]
    named = [v for v in (decoded or {}).values() if v in ids]
    return meaning + (' [' + ', '.join(sorted(set(named))) + ']' if named else '')


def evidence(*, dump_returncode, dump_output, data, sha256, size, decoders, board=BOARD):
    """Build the verbatim cvb record. ``decoders``: flag -> (returncode, output)."""
    rule = rule_for(board)
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
    return {'rule': rule['rule'], 'outcome': outcome,
            'cvb_sha256': sha256,
            'cvb_size': size,
            'dump_returncode': dump_returncode,
            'mb2_answer': MB2_NO_CVB if mb2 else None,
            'decoded': {'id': decoded['-i'], 'sku': decoded['-k']},
            'decoders': stable_decoders,
            'reason': reason(outcome, decoded, board),
            # tegraflash logs carry timestamps; kept verbatim for the approval
            # record but excluded from the same-board re-probe comparison.
            'volatile': {'dump_output_tail': output[-2000:]}}


def check_evidence(record, board=None):
    """Re-derive acceptance from the board's rule; never trust a stored flag.

    ``board``: when given, the record must have been made by that board's rule
    (a J401 record never satisfies the MIC-733-AO rule and vice versa).
    """
    rule = _BY_RULE.get(record.get('rule')) if isinstance(record, dict) else None
    if rule is None or (board is not None and rule['board'] != board):
        raise ValueError('missing/unknown ' + (board or BOARD) + ' carrier evidence')
    name = rule['board']
    outcome = record.get('outcome')
    if outcome not in OUTCOMES:
        raise ValueError('unknown ' + name + ' cvb outcome')
    if outcome not in accepted(name):
        shown = {k: v for k, v in record.items() if k != 'volatile'}
        raise ValueError(name + ' carrier refused: cvb outcome ' + outcome + ': ' +
                         str(record.get('reason')) + ' evidence=' + json.dumps(shown, sort_keys=True))
    pinned = _pinned(name)
    if outcome == 'undecodable' and pinned and record.get('cvb_sha256') not in pinned:
        raise ValueError(name + ' carrier refused: cvb sha256 is not a pinned ' + rule['label'] + ' capture')
    return record


def stable(identity):
    """Identity as compared across same-board re-probes."""
    result = copy.deepcopy(dict(identity))
    result.pop('uefi_policy', None)
    result.pop('carrier_confirmation', None)
    if isinstance(result.get('carrier_evidence'), dict):
        result['carrier_evidence'].pop('volatile', None)
    return result


def bind_confirmation(identity, typed, board=BOARD):
    """Bind the operator's typed phrase and the evidence into the identity."""
    rule = rule_for(board)
    check_evidence(identity.get('carrier_evidence'), board)
    if identity.get('carrier') != rule['carrier'] or identity.get('carrier_rule') != rule['rule']:
        raise ValueError(board + ' carrier identity not established by the carrier rule')
    if typed != rule['confirmation']:
        raise ValueError('explicit ' + rule['confirmation'] + ' confirmation required; no carrier assumed')
    identity['carrier_confirmation'] = typed
    return identity


def validate_bound(identity):
    """Approval guard: a rule-identified identity must carry accepted evidence AND confirmation."""
    rule = _BY_CARRIER.get(identity.get('carrier'))
    if rule is None and identity.get('carrier_rule') is None:
        return
    rule = rule or _BY_RULE.get(identity.get('carrier_rule'))
    if rule is None:
        raise ValueError('unknown carrier rule in board identity')
    check_evidence(identity.get('carrier_evidence'), rule['board'])
    if (identity.get('carrier') != rule['carrier'] or identity.get('carrier_rule') != rule['rule'] or
            identity.get('carrier_confirmation') != rule['confirmation']):
        raise ValueError(rule['board'] + ' approval requires the bound carrier confirmation')


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
