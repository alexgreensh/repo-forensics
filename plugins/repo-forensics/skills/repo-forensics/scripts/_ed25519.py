#!/usr/bin/env python3
"""
_ed25519.py - Vendored, pure-Python, VERIFY-ONLY Ed25519 (RFC 8032).

Derived from the public-domain reference implementation in RFC 8032 Appendix A
and the djb/ed25519 reference code. This module intentionally contains NO
signing primitives — only signature verification. Signing lives exclusively in
the repo-root dev tooling (scripts/sign_rulepacks.py), which is never shipped or
imported by the skill at scan time.

Why vendored: the skill ships pure stdlib (no `cryptography` dependency) and must
verify signed update feeds (rule packs + IOC feed) offline on macOS, Linux, and
Windows. Verify cost is ~5-20ms; callers memoize per (path, mtime, size).

Public API:
    verify(signature: bytes, message: bytes, public_key: bytes) -> bool
        Returns True iff `signature` (64 bytes) is a valid Ed25519 signature of
        `message` under `public_key` (32 bytes). Returns False on ANY malformed
        input (wrong length, non-canonical encoding, bad point) — never raises
        for attacker-controlled data.

Created by Alex Greenshpun.
"""

import hashlib

# --- Curve constants (RFC 8032, edwards25519) -------------------------------

_b = 256
_q = 2 ** 255 - 19
# Group order L.
_L = 2 ** 252 + 27742317777372353535851937790883648493
# d = -121665/121666 mod q
_d = -121665 * pow(121666, _q - 2, _q) % _q
# I = sqrt(-1) mod q
_I = pow(2, (_q - 1) // 4, _q)


def _sha512(data):
    return hashlib.sha512(data).digest()


def _inv(x):
    """Multiplicative inverse mod q via Fermat's little theorem."""
    return pow(x, _q - 2, _q)


def _xrecover(y):
    """Recover x-coordinate from y on edwards25519."""
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


# Base point B.
_By = 4 * _inv(5) % _q
_Bx = _xrecover(_By)
_B = (_Bx % _q, _By % _q, 1, (_Bx * _By) % _q)


def _edwards_add(P, Q):
    """Add two points in extended homogeneous coordinates (X, Y, Z, T)."""
    (x1, y1, z1, t1) = P
    (x2, y2, z2, t2) = Q
    a = (y1 - x1) * (y2 - x2) % _q
    b = (y1 + x1) * (y2 + x2) % _q
    c = t1 * 2 * _d * t2 % _q
    dd = z1 * 2 * z2 % _q
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    x3 = e * f
    y3 = g * h
    t3 = e * h
    z3 = f * g
    return (x3 % _q, y3 % _q, z3 % _q, t3 % _q)


def _scalarmult(P, e):
    """Scalar multiplication via double-and-add (constant-time not required for
    verification of public data)."""
    if e == 0:
        return (0, 1, 1, 0)
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _isoncurve(P):
    (x, y, z, t) = P
    return (
        z % _q != 0
        and x * y % _q == z * t % _q
        and (y * y - x * x - z * z - _d * t * t) % _q == 0
    )


def _decodeint(s):
    return int.from_bytes(s, "little")


def _decodepoint(s):
    """Decode a 32-byte compressed point. Returns the extended-coord point, or
    raises ValueError on a non-canonical / off-curve encoding."""
    if len(s) != 32:
        raise ValueError("point must be 32 bytes")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    # Non-canonical y (>= q) is rejected.
    if y >= _q:
        raise ValueError("non-canonical point encoding")
    x = _xrecover(y)
    if x & 1 != sign:
        x = _q - x
    P = (x, y, 1, (x * y) % _q)
    if not _isoncurve(P):
        raise ValueError("point not on curve")
    return P


def verify(signature, message, public_key):
    """Verify an Ed25519 signature.

    Args:
        signature: 64-byte signature (R || S).
        message: the signed message bytes.
        public_key: 32-byte compressed public key.

    Returns:
        True iff valid; False on any malformed input or verification failure.
        Never raises for attacker-controlled data.
    """
    try:
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
            return False
        if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
            return False
        if not isinstance(message, (bytes, bytearray)):
            return False
        signature = bytes(signature)
        public_key = bytes(public_key)
        message = bytes(message)

        Rs = signature[:32]
        Ss = signature[32:]
        S = _decodeint(Ss)
        # S must be canonical: 0 <= S < L. Reject malleable / oversized S.
        if S >= _L:
            return False

        A = _decodepoint(public_key)
        R = _decodepoint(Rs)

        h = _decodeint(_sha512(Rs + public_key + message)) % _L

        # Check [S]B == R + [h]A
        sB = _scalarmult(_B, S)
        hA = _scalarmult(A, h)
        rhs = _edwards_add(R, hA)

        return _point_equal(sB, rhs)
    except (ValueError, TypeError, IndexError, OverflowError):
        return False


def _point_equal(P, Q):
    """Compare two extended-coordinate points projectively."""
    (x1, y1, z1, _t1) = P
    (x2, y2, z2, _t2) = Q
    if (x1 * z2 - x2 * z1) % _q != 0:
        return False
    if (y1 * z2 - y2 * z1) % _q != 0:
        return False
    return True
