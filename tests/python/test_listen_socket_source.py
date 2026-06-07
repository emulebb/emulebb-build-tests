from __future__ import annotations

from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main"


def test_packet_received_preserves_mfc_exception_details_before_generic_unknown() -> None:
    source = (APP_ROOT / "srchybrid" / "ListenSocket.cpp").read_text(encoding="utf-8", errors="ignore")
    block = source[source.index("bool CClientReqSocket::PacketReceived(Packet *packet)") : source.index("void CClientReqSocket::OnReceive")]
    catch_block = block[block.index("} catch (CException *ex) {") : block.index("#ifndef _DEBUG")]

    assert "} catch (CException *ex) {" in block
    assert "} catch (CClientException *) {\n\t\t\tthrow;\n\t\t} catch (CFileException *ex) {" in block
    assert "} catch (const CString &) {\n\t\t\tthrow;\n#ifndef _DEBUG" in block
    assert block.index("} catch (CClientException *) {") < block.index("} catch (CException *ex) {")
    assert block.index("} catch (const CString &) {") < block.index("} catch (...) {\n\t\t\tthrowCStr(_T(\"Unknown exception\"));")
    assert 'strError.Format(_T("%s%s"), (LPCTSTR)GetResString(IDS_ERR_INVALIDPACKET), (LPCTSTR)CExceptionStrDash(*ex));' in catch_block
    assert catch_block.index("CExceptionStrDash(*ex)") < catch_block.index("ex->Delete();")
    assert block.index("} catch (CException *ex) {") < block.index("} catch (...) {\n\t\t\tthrowCStr(_T(\"Unknown exception\"));")


def test_shared_browse_requests_use_shared_file_snapshots() -> None:
    source = (APP_ROOT / "srchybrid" / "ListenSocket.cpp").read_text(encoding="utf-8", errors="ignore")
    full_list_block = source[source.index("case OP_ASKSHAREDFILES:") : source.index("case OP_ASKSHAREDFILESANSWER:")]
    directory_block = source[source.index("case OP_ASKSHAREDFILESDIR:") : source.index("case OP_ASKSHAREDFILESDIRANS:")]

    assert "CopyAllSharedFiles(sharedFiles);" in full_list_block
    assert "CopySingleSharedFiles(singleSharedFiles);" in directory_block
    assert "CopySharedFilesForDirectory(strReqDir, directoryFiles);" in directory_block
    assert "m_Files_map.PGetFirstAssoc" not in full_list_block
    assert "m_Files_map.PGetFirstAssoc" not in directory_block
    assert "ShouldBeShared(cur_file->GetSharedDirectory(), NULL, false)" not in directory_block
