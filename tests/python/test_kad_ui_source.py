from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def read_source(name: str) -> str:
    return (app_source_root() / name).read_text(encoding="utf-8", errors="ignore")


def test_kademlia_window_rejects_null_contacts_before_deref() -> None:
    source = read_source("KademliaWnd.cpp")

    assert "bool CKademliaWnd::ContactAdd(const Kademlia::CContact *contact)\n{\n\tASSERT(contact != NULL);\n\tif (contact == NULL)\n\t\treturn false;" in source
    assert "void CKademliaWnd::ContactRem(const Kademlia::CContact *contact)\n{\n\tASSERT(contact != NULL);\n\tif (contact == NULL)\n\t\treturn;" in source
    assert "void CKademliaWnd::ContactRef(const Kademlia::CContact *contact)\n{\n\tASSERT(contact != NULL);\n\tif (contact == NULL)\n\t\treturn;" in source


def test_kad_contact_controls_reject_null_contacts() -> None:
    histogram = read_source("KadContactHistogramCtrl.cpp")
    contact_list = read_source("KadContactListCtrl.cpp")

    assert "bool CKadContactHistogramCtrl::ContactAdd(const Kademlia::CContact *contact)\n{\n\tASSERT(contact != NULL);\n\tif (contact == NULL)\n\t\treturn false;" in histogram
    assert "void CKadContactHistogramCtrl::ContactRem(const Kademlia::CContact *contact)\n{\n\tASSERT(contact != NULL);\n\tif (contact == NULL)\n\t\treturn;" in histogram
    assert "ASSERT(contact != NULL);\n\t\tif (contact == NULL)\n\t\t\treturn false;" in contact_list
    assert contact_list.count("ASSERT(contact != NULL);\n\t\tif (contact == NULL)\n\t\t\treturn;") >= 2


def test_kad_search_list_rejects_null_searches_before_lparam_lookup() -> None:
    source = read_source("KadSearchListCtrl.cpp")

    assert source.count("ASSERT(search != NULL);\n\t\tif (search == NULL)\n\t\t\treturn;") >= 3
    assert "find.lParam = reinterpret_cast<LPARAM>(search);" in source
