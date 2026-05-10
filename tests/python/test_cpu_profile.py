from __future__ import annotations

from pathlib import Path

from emule_test_harness import cpu_profile


def test_build_xperf_commands_use_bounded_profile_capture(tmp_path: Path) -> None:
    tools = cpu_profile.CpuProfileTools(xperf="xperf.exe")
    paths = cpu_profile.build_cpu_profile_paths(tmp_path)

    start = cpu_profile.build_xperf_start_command(tools, paths, max_file_mb=128)
    stop = cpu_profile.build_xperf_stop_command(tools, paths)
    cancel = cpu_profile.build_xperf_cancel_command(tools)
    export = cpu_profile.build_xperf_profile_export_command(tools, paths)
    stack_export = cpu_profile.build_xperf_stack_export_command(tools, paths, min_hits=25)

    assert start[:3] == ["xperf.exe", "-on", "PROC_THREAD+LOADER+PROFILE"]
    assert start[start.index("-stackwalk") + 1] == "Profile"
    assert start[start.index("-MaxFile") + 1] == "128"
    assert start[start.index("-FileMode") + 1] == "Circular"
    assert stop == ["xperf.exe", "-d", str(paths.etl_path)]
    assert cancel == ["xperf.exe", "-stop"]
    assert export[:5] == ["xperf.exe", "-i", str(paths.etl_path), "-symbols", "-target"]
    assert export[-2:] == ["profile", "-detail"]
    assert stack_export[:5] == ["xperf.exe", "-i", str(paths.etl_path), "-symbols", "-target"]
    assert stack_export[-7:] == ["stack", "-process", "emule.exe", "-event", "Profile", "-butterfly", "25"]


def test_symbol_environment_prefers_app_pdb_and_sets_symcache(tmp_path: Path) -> None:
    app_exe = tmp_path / "app" / "srchybrid" / "x64" / "Release" / "emule.exe"
    symbol_cache = tmp_path / "symbols"

    env = cpu_profile.build_symbol_environment(app_exe, symbol_cache, base_env={})

    assert str(app_exe.parent) in env["_NT_SYMBOL_PATH"]
    assert "https://msdl.microsoft.com/download/symbols" not in env["_NT_SYMBOL_PATH"]
    assert env["_NT_SYMCACHE_PATH"] == str(symbol_cache)
    assert cpu_profile.resolve_app_pdb_path(app_exe) == app_exe.with_suffix(".pdb")


def test_parse_xperf_profile_detail_extracts_top_emule_functions() -> None:
    text = """
Process          Module       Function                                      Count Weight
emule.exe        emule.exe    emule!CDownloadQueue::Process                 120   42.5%
emule.exe        emule.exe    emule!CPartFile::Process                      40    12.25%
System           ntoskrnl     ntoskrnl!KiIdleLoop                           900   80.0%
emule.exe        cryptopp     cryptopp!SHA1::Transform                      12    3.0%
"""

    summary = cpu_profile.parse_xperf_profile_detail(text, limit=2)

    assert summary["available"] is True
    assert summary["row_count"] == 3
    assert summary["app_row_count"] == 2
    assert summary["top_app_functions"] == summary["top"]
    assert summary["top"] == [
        {
            "function": "emule!CDownloadQueue::Process",
            "sample_count": 120,
            "weight_percent": 42.5,
            "raw": "emule.exe        emule.exe    emule!CDownloadQueue::Process                 120   42.5%",
        },
        {
            "function": "emule!CPartFile::Process",
            "sample_count": 40,
            "weight_percent": 12.25,
            "raw": "emule.exe        emule.exe    emule!CPartFile::Process                      40    12.25%",
        },
    ]


def test_parse_xperf_profile_detail_reports_unresolved_emule_rows() -> None:
    text = "emule.exe        emule.exe    <unknown>                      7    1.0%\n"

    summary = cpu_profile.parse_xperf_profile_detail(text)

    assert summary["available"] is True
    assert summary["unresolved_row_count"] == 1
    assert summary["top"][0]["function"] == "<unresolved>"


def test_parse_xperf_profile_detail_extracts_xperf_csv_rows() -> None:
    text = """
emule.exe (17236),  102036800,       1.06,            ntdll.dll!"Unknown"
emule.exe (17236),    1656901,       0.02,            emule.exe!CMapPtrToPtr::GetValueAt
emule.exe (17236),     505140,       0.01,            emule.exe!CPartFile::WriteToBuffer
"""

    summary = cpu_profile.parse_xperf_profile_detail(text, limit=2)

    assert summary["available"] is True
    assert summary["row_count"] == 3
    assert summary["app_row_count"] == 2
    assert summary["unresolved_row_count"] == 1
    assert summary["top"] == [
        {
            "function": "<unresolved>",
            "sample_count": 102036800,
            "weight_percent": 1.06,
            "raw": 'emule.exe (17236),  102036800,       1.06,            ntdll.dll!"Unknown"',
        },
        {
            "function": "emule!CMapPtrToPtr::GetValueAt",
            "sample_count": 1656901,
            "weight_percent": 0.02,
            "raw": "emule.exe (17236),    1656901,       0.02,            emule.exe!CMapPtrToPtr::GetValueAt",
        },
    ]
    assert [row["function"] for row in summary["top_app_functions"]] == [
        "emule!CMapPtrToPtr::GetValueAt",
        "emule!CPartFile::WriteToBuffer",
    ]


def test_parse_xperf_profile_detail_preserves_csv_template_symbols() -> None:
    text = (
        "emule.exe (5740),     136000,       0.01,            "
        "emule.exe!nlohmann::json_abi_v3_11_3::basic_json<std::map,"
        "std::vector,std::basic_string<char,std::char_traits<char>,std::allocator<char> > >::destroy\n"
    )

    summary = cpu_profile.parse_xperf_profile_detail(text)

    function = summary["top_app_functions"][0]["function"]
    assert function.startswith("emule!nlohmann::json_abi_v3_11_3::basic_json<std::map,std::vector")
    assert function.endswith(">::destroy")


def test_parse_xperf_stack_report_extracts_top_app_inclusive_functions() -> None:
    text = """
<h2>Functions by UniInclusive Hits</h2><table><tbody>
<tr><td><a href='#m'>emule.exe</a>!<a href='#s'>WebServerJson::RunDispatchedCommand</a></td><td>5131</td><td>68.17%</td><td>0</td></tr>
<tr><td><a href='#m'>ntdll.dll</a>!<a href='#s'>RtlCaptureStackBackTrace</a></td><td>4417</td><td>58.68%</td><td>6</td></tr>
<tr><td><a href='#m'>emule.exe</a>!<a href='#s'>CDownloadQueue::CollectProtectedVolumeStatuses</a></td><td>32</td><td>0.42%</td><td>1</td></tr>
</tbody></table><h2>Functions by Multi-Inclusive Hits with Callers and Callees</h2>
"""

    summary = cpu_profile.parse_xperf_stack_report(text)

    assert summary["available"] is True
    assert summary["app_row_count"] == 2
    assert summary["top_app_inclusive_functions"] == [
        {
            "function": "emule!WebServerJson::RunDispatchedCommand",
            "inclusive_hits": 5131,
            "total_percent": 68.17,
            "exclusive_hits": 0,
        },
        {
            "function": "emule!CDownloadQueue::CollectProtectedVolumeStatuses",
            "inclusive_hits": 32,
            "total_percent": 0.42,
            "exclusive_hits": 1,
        },
    ]
