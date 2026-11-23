"""ztaf-mandate: the Zero-TAF mandate-chain reference implementation.

Reference only. The normative format, field semantics, constraint vocabulary,
and comparison rules live in ztaf-spec (mandate format document). This
package implements exactly that document; the two move together by change
request.
"""

from .canonical import canonical_bytes, canonical_hash, digest
from .constraints import check_attenuation, grade_rank
from .keys import DictKeyProvider, generate_key, sign, verify
from .mandate import body_of, mandate_hash, mint, validate_body, verify_signature
from .revocation import REVOKED, VALID, StatusChecker, verify_status_list
from .chain import ChainResult, verify_chain

__version__ = "0.1.0"
