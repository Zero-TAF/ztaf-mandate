"""Replay the golden vectors: tests/test_vectors.py (run from repo root)."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ztaf_mandate.chain import verify_chain  # noqa: E402
from ztaf_mandate.keys import DictKeyProvider  # noqa: E402
from ztaf_mandate.revocation import StatusChecker  # noqa: E402

VECTORS = Path(__file__).resolve().parents[1] / "vectors"


def load_all():
    index = json.loads((VECTORS / "index.json").read_text())
    for name in index["vectors"]:
        yield json.loads((VECTORS / name).read_text())


def parse_now(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class TestGoldenVectors:
    def test_all_vectors_replay(self):
        checked = 0
        for vector in load_all():
            keys = DictKeyProvider({
                kid: bytes.fromhex(block["public_hex"])
                for kid, block in vector["keys"].items()
            })
            status_list = vector.get("status_list")
            now = parse_now(vector["now"])
            if status_list is not None:
                root_kid = next(iter(vector["keys"]))
                revocation = StatusChecker(status_list, keys.get(root_kid), now)
            else:
                revocation = lambda mid: False  # noqa: E731

            result = verify_chain(
                vector["mandates"], keys, now, revocation, subject=vector.get("subject")
            )
            expect = vector["expect"]
            if expect["result"] == "ok":
                assert result.ok, f"{vector['vector_id']}: expected ok, got fail: {result.reason}"
            else:
                assert not result.ok, f"{vector['vector_id']}: expected fail, got ok"
                assert expect["reason_contains"] in (result.reason or ""), \
                    f"{vector['vector_id']}: reason {result.reason!r} lacks {expect['reason_contains']!r}"
            checked += 1
        assert checked == 10, f"expected 10 vectors, replayed {checked}"
