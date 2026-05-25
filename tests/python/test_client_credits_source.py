from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_client_credit_signature_helpers_reject_null_inputs() -> None:
    source = (app_source_root() / "ClientCredits.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "ASSERT(pTarget != NULL && pachOutput != NULL);\n\tif (pTarget == NULL || pachOutput == NULL)\n\t\treturn GetClientCreditsSignatureFailureResult();" in source
    assert "ASSERT(pTarget);\n\tASSERT(pachSignature);\n\tif (pTarget == NULL || pachSignature == NULL)\n\t\treturn false;" in source
