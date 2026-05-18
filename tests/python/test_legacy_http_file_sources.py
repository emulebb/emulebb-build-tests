from pathlib import Path


def test_http_file_sources_are_removed_from_transfer_engine() -> None:
    workspace_root = Path(__file__).resolve().parents[4]
    app_root = workspace_root / "workspaces" / "workspace" / "app" / "eMule-main" / "srchybrid"

    for removed_file in (
        "URLClient.cpp",
        "URLClient.h",
        "HttpClientReqSocket.cpp",
        "HttpClientReqSocket.h",
    ):
        assert not (app_root / removed_file).exists()

    project_text = (app_root / "emule.vcxproj").read_text(encoding="utf-8")
    assert "URLClient" not in project_text
    assert "HttpClientReqSocket" not in project_text

    client_state_text = (app_root / "ClientStateDefs.h").read_text(encoding="utf-8")
    assert "SO_URL" not in client_state_text

    add_source_text = (app_root / "AddSourceInputSeams.h").read_text(encoding="utf-8")
    assert "ParseUrlSourceInput" not in add_source_text
    assert "UrlSourceInput" not in add_source_text

    ed2k_link_text = (app_root / "ED2KLink.cpp").read_text(encoding="utf-8")
    assert 'astrEd2kParams.Add(_T("s=")' not in ed2k_link_text
    assert "HTTP file sources are intentionally not imported" in ed2k_link_text
