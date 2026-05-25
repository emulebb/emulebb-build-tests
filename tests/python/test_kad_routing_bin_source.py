from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_routing_bin_rejects_null_contact_inputs_before_deref() -> None:
    source = (app_source_root() / "kademlia" / "routing" / "RoutingBin.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "bool CRoutingBin::AddContact(CContact *pContact)\n{\n\tASSERT(pContact != NULL);\n\tif (pContact == NULL)\n\t\treturn false;" in source
    assert "void CRoutingBin::SetAlive(const CContact *pContact)\n{\n\tASSERT(pContact != NULL);\n\tif (pContact == NULL)\n\t\treturn;" in source
    assert "void CRoutingBin::RemoveContact(CContact *const pContact, bool bNoTrackingAdjust)\n{\n\tASSERT(pContact != NULL);\n\tif (pContact == NULL)\n\t\treturn;" in source
    assert "bool CRoutingBin::ChangeContactIPAddress(CContact *pContact, uint32 uNewIP)\n{\n\tASSERT(pContact != NULL);\n\tif (pContact == NULL)\n\t\treturn false;" in source
    assert "void CRoutingBin::PushToBottom(CContact *pContact) // puts an existing contact from X to the end of the list\n{\n\tASSERT(pContact != NULL);\n\tif (pContact == NULL)\n\t\treturn;" in source


def test_routing_bin_skips_stale_null_entries_while_checking_duplicates() -> None:
    source = (app_source_root() / "kademlia" / "routing" / "RoutingBin.cpp").read_text(encoding="utf-8", errors="ignore")

    assert "const CContact *pExistingContact = *itContact;\n\t\tif (pExistingContact == NULL)\n\t\t\tcontinue;" in source
    assert "if (pContact->GetClientID() == pExistingContact->m_uClientID)\n\t\t\treturn false;" in source
