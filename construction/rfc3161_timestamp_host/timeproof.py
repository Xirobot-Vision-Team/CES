#!/usr/bin/env python3
"""EC273: pinned RFC3161 TSA timestamps for the exact EC272 current signed tail.

This intentionally does not request timestamps over the network or claim an
independent clock: an operator obtains a standard DER RFC3161 TimeStampResp
from a separately governed TSA. OpenSSL checks RFC3161 CMS, trust chain,
nonce, imprint and policy; a small strict DER reader checks authenticated
TSTInfo fields and timing without scraping human-readable openssl output.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import subprocess
import tempfile
from typing import Any

from source_provenance_host import provenance as prov
from emergency_recovery_host import recovery as rec
from freshness_quorum_host import freshness as fresh
from freshness_rollover_host import rollover as roll

SCHEMA = 'ces.ec273.rfc3161_tail_timestamp_statement.v1'
DOMAIN = b'CES/EC273/rfc3161/current-signed-tail/v1\x00'
SHA256_OID = '2.16.840.1.101.3.4.2.1'
OID = re.compile(r'(?:0|[1-9][0-9]{0,9})(?:\.(?:0|[1-9][0-9]{0,9})){2,15}\Z')
GENTIME = re.compile(rb'([0-9]{14})(?:\.([0-9]{1,6}))?Z\Z')
MAX_QUERY = 2048
MAX_RESPONSE = 192 * 1024
MAX_CA_BUNDLE = 64 * 1024
MAX_SIGNER = 64 * 1024
MAX_TSTINFO = 8192
MAX_AGE = 900
MAX_SKEW = 30


class TimestampError(roll.RolloverError):
    """Fixed-code failure: never expose keys, TSA data, or subprocess stderr."""


def deny(code: str) -> None:
    raise TimestampError(code)


def _blob(path: str, sha: str, limit: int, kind: str) -> bytes:
    try:
        raw = prov._bytes(prov._path(path), limit)
        if not hmac.compare_digest(prov._digest(raw), rec._sha(sha)):
            deny('EC273_' + kind + '_PIN_MISMATCH')
        return raw
    except (prov.ProvenanceError, OSError, ValueError, TypeError) as exc:
        raise TimestampError('EC273_' + kind + '_PRIVATE_PINNED_FILE_UNAVAILABLE') from exc


def _len(n: int) -> bytes:
    if n < 0 or n > MAX_RESPONSE:
        deny('EC273_DER_LENGTH_INVALID')
    if n < 128:
        return bytes([n])
    raw = n.to_bytes((n.bit_length()+7)//8, 'big')
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def _integer(n: int) -> bytes:
    if type(n) is not int or n < 0:
        deny('EC273_DER_INTEGER_INVALID')
    b = (n.to_bytes((n.bit_length()+7)//8 or 1, 'big'))
    if b[0] & 0x80:
        b = b'\x00' + b
    return _tlv(2, b)


def _base128(value: int) -> bytes:
    if value < 0 or value > 2**50:
        deny('EC273_OID_ARC_OUT_OF_RANGE')
    pieces = [value & 127]
    value >>= 7
    while value:
        pieces.insert(0, 0x80 | (value & 127))
        value >>= 7
    return bytes(pieces)


def _oid(oid: str) -> bytes:
    if type(oid) is not str or OID.fullmatch(oid) is None:
        deny('EC273_TSA_POLICY_OID_INVALID')
    parts = list(map(int, oid.split('.')))
    if parts[0] > 2 or (parts[0] < 2 and parts[1] > 39):
        deny('EC273_TSA_POLICY_OID_INVALID')
    raw = _base128(parts[0]*40+parts[1]) + b''.join(map(_base128, parts[2:]))
    return _tlv(6, raw)


def _oid_text(value: bytes) -> str:
    if not value:
        deny('EC273_DER_OID_INVALID')
    numbers = []
    cur = 0
    start = 0
    for i, byte in enumerate(value):
        if i == start and byte == 0x80:
            deny('EC273_DER_OID_NONMINIMAL')
        cur = (cur << 7) | (byte & 0x7f)
        if cur > 2**50:
            deny('EC273_DER_OID_TOO_LARGE')
        if not byte & 0x80:
            numbers.append(cur)
            cur = 0
            start = i + 1
    if start != len(value) or not numbers:
        deny('EC273_DER_OID_INVALID')
    first = numbers.pop(0)
    if first < 40:
        head = (0, first)
    elif first < 80:
        head = (1, first-40)
    else:
        head = (2, first-80)
    return '.'.join(map(str, (*head, *numbers)))


def _node(data: bytes, at: int = 0) -> tuple[int, bytes, int]:
    if at >= len(data):
        deny('EC273_DER_TRUNCATED')
    tag = data[at]
    if tag & 0x1f == 0x1f or at + 1 >= len(data):
        deny('EC273_DER_TAG_UNSUPPORTED')
    first = data[at+1]
    if first & 0x80:
        count = first & 0x7f
        if count == 0 or count > 3 or at+2+count > len(data):
            deny('EC273_DER_LENGTH_INVALID')
        n_bytes = data[at+2:at+2+count]
        if n_bytes[0] == 0:
            deny('EC273_DER_LENGTH_NONMINIMAL')
        length = int.from_bytes(n_bytes, 'big')
        if length < 128:
            deny('EC273_DER_LENGTH_NONMINIMAL')
        start = at+2+count
    else:
        length = first
        start = at+2
    end = start+length
    if end > len(data) or length > MAX_RESPONSE:
        deny('EC273_DER_OVERRUN')
    return tag, data[start:end], end


def _children(raw: bytes) -> list[tuple[int, bytes]]:
    result = []
    p = 0
    while p < len(raw):
        tag, value, p = _node(raw, p)
        result.append((tag, value))
        if len(result) > 32:
            deny('EC273_DER_TOO_MANY_FIELDS')
    return result


def _one(raw: bytes, tag: int) -> bytes:
    actual, data, end = _node(raw)
    if actual != tag or end != len(raw):
        deny('EC273_DER_STRUCTURE_INVALID')
    return data


def _value_integer(raw: bytes) -> int:
    if not raw or raw[0] & 0x80 or (len(raw)>1 and raw[0] == 0 and not raw[1] & 0x80):
        deny('EC273_DER_INTEGER_ENCODING_INVALID')
    return int.from_bytes(raw, 'big')


def _imprint(raw: bytes) -> bytes:
    parts = _children(raw)
    if len(parts) != 2 or parts[0][0] != 0x30 or parts[1][0] != 4:
        deny('EC273_MESSAGE_IMPRINT_INVALID')
    algorithm = _children(parts[0][1])
    if (len(algorithm) not in (1, 2) or algorithm[0][0] != 6 or
            _oid_text(algorithm[0][1]) != SHA256_OID or
            (len(algorithm) == 2 and algorithm[1] != (5, b'')) or
            len(parts[1][1]) != 32):
        deny('EC273_SHA256_MESSAGE_IMPRINT_REQUIRED')
    return parts[1][1]


def _request(imprint: bytes, policy: str, nonce: int) -> bytes:
    if type(imprint) is not bytes or len(imprint) != 32:
        deny('EC273_SHA256_IMPRINT_INVALID')
    if type(nonce) is not int or not 2**127 <= nonce < 2**128:
        deny('EC273_128BIT_REQUEST_NONCE_REQUIRED')
    algorithm = _tlv(0x30, _oid(SHA256_OID) + _tlv(5, b''))
    msg = _tlv(0x30, algorithm + _tlv(4, imprint))
    return _tlv(0x30, _integer(1) + msg + _oid(policy) + _integer(nonce) + _tlv(1, b'\xff'))


def _parse_request(raw: bytes, policy: str, expected_imprint: bytes) -> int:
    parts = _children(_one(raw, 0x30))
    if ([tag for tag, _ in parts] != [2, 0x30, 6, 2, 1] or
            _value_integer(parts[0][1]) != 1 or
            _imprint(parts[1][1]) != expected_imprint or
            _oid_text(parts[2][1]) != policy or
            parts[4][1] != b'\xff'):
        deny('EC273_REQUEST_NOT_BOUND_TO_CURRENT_CHAIN_AND_POLICY')
    nonce = _value_integer(parts[3][1])
    if raw != _request(expected_imprint, policy, nonce):
        deny('EC273_REQUEST_NONCANONICAL_OR_NONCE_INVALID')
    return nonce


def _time(value: bytes) -> float:
    match = GENTIME.fullmatch(value)
    if match is None:
        deny('EC273_TSA_GENTIME_UTC_REQUIRED')
    try:
        base = dt.datetime.strptime(match.group(1).decode('ascii'), '%Y%m%d%H%M%S')
        moment = base.replace(tzinfo=dt.timezone.utc)
        micro = int((match.group(2) or b'').ljust(6,b'0')) if match.group(2) else 0
        moment = moment.replace(microsecond=micro)
        value = moment.timestamp()
    except (ValueError, OverflowError) as exc:
        raise TimestampError('EC273_TSA_GENTIME_INVALID') from exc
    if not 1 <= value <= 2**40:
        deny('EC273_TSA_GENTIME_INVALID')
    return value


def _tstinfo(raw: bytes, policy: str, imprint: bytes, nonce: int) -> tuple[float, int]:
    if len(raw) > MAX_TSTINFO:
        deny('EC273_TSTINFO_OVERSIZE')
    parts = _children(_one(raw, 0x30))
    if (len(parts) < 5 or [tag for tag, _ in parts[:5]] != [2, 6, 0x30, 2, 0x18] or
            _value_integer(parts[0][1]) != 1 or
            _oid_text(parts[1][1]) != policy or _imprint(parts[2][1]) != imprint):
        deny('EC273_TSTINFO_NOT_BOUND_TO_QUERY')
    serial = _value_integer(parts[3][1])
    if not 0 < serial < 2**160:
        deny('EC273_TSTINFO_SERIAL_INVALID')
    optional = parts[5:]
    matched_nonce = []
    allowed = {0x30, 1, 2, 0xa0, 0xa1}
    if any(tag not in allowed for tag, _ in optional):
        deny('EC273_TSTINFO_OPTION_INVALID')
    for tag, value in optional:
        if tag == 2:
            matched_nonce.append(_value_integer(value))
    if matched_nonce != [nonce]:
        deny('EC273_TSA_NONCE_MISMATCH')
    return _time(parts[4][1]), serial


def _binary(path: str, expected_sha256: str) -> str:
    """Root-owned, exact SHA pinned OpenSSL executable; never execute via shell."""
    try:
        if type(path) is not str or not path.startswith('/') or os.path.normpath(path) != path:
            deny('EC273_OPENSSL_ABSOLUTE_PATH_REQUIRED')
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022 or not st.st_mode & 0o111:
            deny('EC273_OPENSSL_ROOT_OWNED_EXECUTABLE_REQUIRED')
        digest = hashlib.sha256()
        with open(path, 'rb') as stream:
            while True:
                block = stream.read(1024*1024)
                if not block:
                    break
                digest.update(block)
        if not hmac.compare_digest(digest.hexdigest(), rec._sha(expected_sha256)):
            deny('EC273_OPENSSL_BINARY_SHA256_MISMATCH')
        after = os.lstat(path)
        if (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns) != (
                after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
            deny('EC273_OPENSSL_BINARY_REPLACED')
        return path
    except (OSError, ValueError, TypeError) as exc:
        raise TimestampError('EC273_OPENSSL_BINARY_UNAVAILABLE') from exc


def _call(path: str, pin: str, *args: str) -> None:
    binary = _binary(path, pin)
    try:
        # OpenSSL CLI does not receive any client-controlled shell, command,
        # executable path, environment variable, or dynamic custom provider.
        completed = subprocess.run([binary, *args], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8,
            env={'PATH':'/usr/bin:/bin','OPENSSL_CONF':'/dev/null',
                 'HOME':'/nonexistent','LC_ALL':'C'},check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TimestampError('EC273_CRYPTO_EXECUTION_UNAVAILABLE') from exc
    if completed.returncode != 0 or len(completed.stdout) > 8192:
        deny('EC273_OPENSSL_RFC3161_CRYPTO_VERIFY_FAILED')


def _statement(*, checkpoint_sha256: str, segment_sha256: str,
               latest_receipt_sha256: str, newest: dict[str, Any]) -> bytes:
    # Full SHA of the signed EC271 seal, chain manifest, ratified EC272
    # checkpoint and recovered governance epoch. No path-only binding.
    doc = {
        'schema':SCHEMA,'checkpoint_sha256':rec._sha(checkpoint_sha256),
        'segment_sha256':rec._sha(segment_sha256),
        'latest_receipt_sha256':rec._sha(latest_receipt_sha256),
        'sequence':newest['sequence'],
        'previous_receipt_sha256':newest['previous_receipt_sha256'],
        'closure_sha256':newest['closure_sha256'],
        'recovered_root_public_sha256':newest['recovered_root_public_sha256'],
        'governance_epoch':newest['governance_epoch'],
        'governance_sha256':newest['governance_sha256'],
        'not_before_unix':newest['not_before_unix'],
        'expires_at_unix':newest['expires_at_unix'],
        'witness_public_sha256':newest['witness_public_sha256']}
    fresh._fields(newest)
    return DOMAIN + prov._canonical(doc)


def _tail(*, segment: str, segment_sha256: str,
          checkpoint_sha256: str) -> tuple[bytes, dict[str, Any], str]:
    entries = roll._checked_config(segment, segment_sha256)
    end = entries[-1]
    # Caller MUST verify the entire EC272 chain first. Reading only newest
    # here is strictly for timestamp binding and signed interval retrieval.
    raw, newest = rec._read(end['receipt_path'], fresh.MAX_RECEIPT)
    rec._check_pin(raw, end['receipt_sha256'], 'EC273_LATEST_RECEIPT_PIN_INVALID')
    statement = _statement(checkpoint_sha256=checkpoint_sha256,
        segment_sha256=segment_sha256,latest_receipt_sha256=end['receipt_sha256'],
        newest=newest)
    return statement, newest, end['receipt_sha256']


def prepare_request(*, segment: str, segment_sha256: str,
                    checkpoint_sha256: str, policy_oid: str, output: str) -> dict:
    """Generate new 128-bit-nonce TSQ. Must pair with full EC272 verification."""
    statement,newest,last_pin=_tail(segment=segment,
        segment_sha256=segment_sha256,checkpoint_sha256=checkpoint_sha256)
    nonce=(1 << 127) | secrets.randbits(127)
    raw=_request(hashlib.sha256(statement).digest(),policy_oid,nonce)
    try:
        prov._new(output,raw)
    except prov.ProvenanceError as exc:
        raise TimestampError('EC273_NEW_PRIVATE_REQUEST_FILE_REQUIRED') from exc
    return {'status':'partial','exit_code':2,'request_sha256':prov._digest(raw),
        'timestamp_message_sha256':prov._digest(statement),
        'latest_receipt_sha256':last_pin,'freshness_sequence':newest['sequence'],
        'tsa_policy_oid':policy_oid,'request_has_128bit_nonce':True,
        'tsa_response_must_be_independently_acquired':True}


def verify_timestamp(*, segment: str,segment_sha256: str,
                     checkpoint_sha256: str,request: str,request_sha256: str,
                     response: str,response_sha256: str,ca_bundle: str,
                     ca_bundle_sha256: str,leaf_cert_sha256: str,
                     policy_oid: str,openssl_binary: str,openssl_binary_sha256: str,
                     effective_now: float,maximum_age_seconds: int,
                     minimum_time_unix: int,
                     intermediates: str | None = None,
                     intermediates_sha256: str | None = None) -> dict:
    """Check pinned TSA trust and timestamp against current EC272 signed tail."""
    age = rec._integer(maximum_age_seconds,1,MAX_AGE,'EC273_MAX_TIMESTAMP_AGE_INVALID')
    floor = rec._integer(minimum_time_unix,1,2**40,'EC273_TIMESTAMP_FLOOR_INVALID')
    if (intermediates is None) != (intermediates_sha256 is None):
        deny('EC273_INTERMEDIATE_CERTIFICATE_PIN_PAIR_REQUIRED')
    expected_leaf = rec._sha(leaf_cert_sha256)
    _oid(policy_oid)
    statement,newest,last_pin=_tail(segment=segment,
        segment_sha256=segment_sha256,checkpoint_sha256=checkpoint_sha256)
    imprint = hashlib.sha256(statement).digest()
    request_bytes = _blob(request,request_sha256,MAX_QUERY,'REQUEST')
    nonce = _parse_request(request_bytes,policy_oid,imprint)
    response_bytes = _blob(response,response_sha256,MAX_RESPONSE,'RESPONSE')
    ca = _blob(ca_bundle,ca_bundle_sha256,MAX_CA_BUNDLE,'CA_BUNDLE')
    if b'-----BEGIN CERTIFICATE-----' not in ca:
        deny('EC273_TRUST_STORE_MUST_BE_PEM')
    extra = None if intermediates is None else _blob(
        intermediates,intermediates_sha256,MAX_CA_BUNDLE,'INTERMEDIATES')
    if not isinstance(effective_now,(int,float)) or isinstance(effective_now,bool):
        deny('EC273_EFFECTIVE_TIME_INVALID')
    if not 1 <= effective_now <= 2**40:
        deny('EC273_EFFECTIVE_TIME_INVALID')
    if len(response_bytes) < 64:
        deny('EC273_RESPONSE_TOO_SHORT')
    # Temporary copies are private and bounded: OpenSSL sees only bytes that
    # were previously read and pinned, not attacker-swappable source paths.
    with tempfile.TemporaryDirectory(prefix='ces-ec273-') as tmp:
        p=Path(tmp)
        for name,raw in (('request.tsq',request_bytes),('response.tsr',response_bytes),
                         ('roots.pem',ca)):
            (p/name).write_bytes(raw)
        if extra is not None:
            (p/'intermediate.pem').write_bytes(extra)
        verify = ['ts','-verify','-queryfile',str(p/'request.tsq'),
                  '-in',str(p/'response.tsr'),'-CAfile',str(p/'roots.pem'),
                  '-tspolicy',policy_oid]
        if extra is not None:
            verify.extend(['-untrusted',str(p/'intermediate.pem')])
        _call(openssl_binary,openssl_binary_sha256,*verify)
        _call(openssl_binary,openssl_binary_sha256,'ts','-reply',
              '-in',str(p/'response.tsr'),'-token_out','-out',str(p/'token.der'))
        _call(openssl_binary,openssl_binary_sha256,'cms','-verify',
              '-noverify','-binary','-inform','DER','-in',str(p/'token.der'),
              '-out',str(p/'tstinfo.der'),'-signer',str(p/'signer.pem'))
        try:
            info=(p/'tstinfo.der').read_bytes()
            pem=(p/'signer.pem').read_text('ascii')
        except (OSError,UnicodeError) as exc:
            raise TimestampError('EC273_TSA_SIGNER_CERT_UNAVAILABLE') from exc
    # Exactly one signer, pinned by its DER certificate fingerprint; unlike a
    # CAfile-only check, no alternate leaf in that trust store is accepted.
    if (pem.count('-----BEGIN CERTIFICATE-----') != 1 or
            pem.count('-----END CERTIFICATE-----') != 1):
        deny('EC273_EXACTLY_ONE_TSA_SIGNER_REQUIRED')
    try:
        signer_der=ssl.PEM_cert_to_DER_cert(pem)
    except ValueError as exc:
        raise TimestampError('EC273_TSA_SIGNER_CERT_INVALID') from exc
    if not hmac.compare_digest(hashlib.sha256(signer_der).hexdigest(),expected_leaf):
        deny('EC273_TSA_LEAF_CERT_SHA256_MISMATCH')
    if len(info)>MAX_TSTINFO:
        deny('EC273_TSTINFO_OVERSIZE')
    certified, serial = _tstinfo(info,policy_oid,imprint,nonce)
    last_vote=newest['approvals'][-1]['observed_at_unix']
    if not newest['not_before_unix'] <= certified < newest['expires_at_unix']:
        deny('EC273_TSA_TIME_OUTSIDE_SIGNED_LIVE_SEAL')
    if certified < last_vote - MAX_SKEW:
        deny('EC273_TSA_TIME_PRECEDES_LAST_WITNESS')
    if certified < floor:
        deny('EC273_TSA_TIME_BELOW_OPERATOR_FLOOR')
    if certified > effective_now + MAX_SKEW:
        deny('EC273_TSA_TIME_UNREASONABLY_FUTURE')
    if effective_now-certified > age:
        deny('EC273_TSA_TIMESTAMP_STALE')
    return {'status':'partial','exit_code':2,
        'reason_code':'EC273_PINNED_RFC3161_TIMESTAMP_LOCALLY_VERIFIED',
        'trusted_external_timestamp_signature_verified':True,
        'timestamp_gen_time_unix':certified,'timestamp_serial':str(serial),
        'tsa_leaf_certificate_sha256':expected_leaf,
        'tsa_policy_oid':policy_oid,'timestamp_query_nonce_bits':128,
        'timestamp_max_age_seconds':age,
        'timestamp_response_sha256':rec._sha(response_sha256),
        'timestamp_request_sha256':rec._sha(request_sha256),
        'timestamp_message_sha256':prov._digest(statement),
        'timestamp_bound_to_latest_receipt_sha256':last_pin,
        'timestamp_cross_restart_nonrollbackable_escrow_verified':False,
        'ec272_chain_verified_by_this_function':False,
        'independent_real_tsa_operator_verified':False}
