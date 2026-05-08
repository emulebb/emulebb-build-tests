"""Builds deterministic long-path fixture trees for Shared Files live testing."""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

DEFAULT_SHARED_ROOT = Path(r"C:\tmp\00_long_paths")
MANIFEST_FILENAME = "generated-fixture-manifest.json"
FIXTURE_VERSION = 1
MAX_REPORT_FILES = 8

LONG_PATH_OUTPUT_BRANCH_DEPTHS = [6, 7, 8, 9, 7, 8, 9, 10, 6, 7, 8, 9, 7, 8, 9, 10]
LONG_PATH_OUTPUT_FILE_TEMPLATES = [
    "payload_{branch:02d}_{file:02d}_unicode_lambda_\u03bb_\u4f8b_{tail}.bin",
    "payload_{branch:02d}_{file:02d}_capsLOCK_[mix]_{tail}.dat",
    "payload_{branch:02d}_{file:02d}_semi;comma,name_{tail}.bin",
    "payload_{branch:02d}_{file:02d}_hash#plus+percent%25_{tail}.bin",
    "payload_{branch:02d}_{file:02d}_multi.part.name_{tail}.tar",
    "payload_{branch:02d}_{file:02d}_brace{{}}_bracket[]_{tail}.bin",
]
LONG_PATH_NAME_PARTS = [
    "alpha beta",
    "mix,match",
    "semi;colon",
    "quote's",
    "bang!zone",
    "hash#tag",
    "plus+sign",
    "equal=value",
    "caret^up",
    "tilde~wave",
    "braces{}",
    "brackets[]",
    "paren()",
    "percent%25",
    "at@home",
    "unicode_\u00f1",
    "snow_\u2603",
    "kanji_\u4f8b",
    "greek_\u03a9",
    "math_\u2211",
]
LONG_PATH_ROOT_FILE_SPECS = [
    ("root_000_zero_bytes_[shared].bin", 0, 0xA001, False),
    ("root_001_single_byte_unicode_\u03a9.bin", 1, 0xA002, True),
    ("root_002_readme_like multi.part.txt", 65537, 0xA003, True),
    ("root_003_large_emoji_\U0001F680_\u4f8b.iso", 917521, 0xA004, True),
]

ROBUSTNESS_DIRECTORY_LAYOUT = {
    "root": (),
    "flat": ("00 flat files",),
    "unicode": ("01 unicode_\u03bb_\u4f8b_\U0001F680",),
    "mixed": ("02 mixed.case and spaces", "child_[01]_plus+hash#"),
    "deep": (
        "03 deep path",
        "level_01_xxxxxxxxxxxx",
        "level_02_greek_\u03a9",
        "level_03_kanji_\u4f8b",
    ),
    "wide": ("04 wide names and commas",),
    "archive": ("05 archive-like names", "inner.tar.parts"),
}
ROBUSTNESS_FILE_SPECS = [
    ("root", "100_zero_bytes_visible.bin", 0, 0xB001, False),
    ("root", "101_one_byte_ leading-space.bin", 1, 0xB002, True),
    ("root", "102_dot.leading.visible.dat", 7, 0xB003, True),
    ("root", "103_nbsp_\u00a0_visible.bin", 63, 0xB004, True),
    ("flat", "110_queue[01]_part.met.bak", 1025, 0xB005, True),
    ("flat", "111_multi..dot..name.tar", 4099, 0xB006, True),
    ("flat", "112_UPPER_lower_Mixed.part", 8193, 0xB007, False),
    ("flat", "113_hash#plus+percent%25.bin", 16387, 0xB008, True),
    ("unicode", "120_emoji_\U0001F680_kana_\u30ab\u30ca.bin", 32771, 0xB009, True),
    ("unicode", "121_math_\u2211_greek_\u03a9.txt", 65539, 0xB00A, True),
    ("unicode", "122_cyrillic_\u043a\u0438\u0440\u0438\u043b\u043b\u0438\u0446\u0430.bin", 98311, 0xB00B, True),
    ("unicode", "123_hanzi_\u4f8b_visible.dat", 131101, 0xB00C, True),
    ("mixed", "130_braces{}_brackets[]_paren().bin", 196613, 0xB00D, True),
    ("mixed", "131_equal=value_semi;colon,comma.bin", 262187, 0xB00E, True),
    ("mixed", "132_dash-under_score-mix.bin", 393241, 0xB00F, True),
    ("mixed", "133_capsLOCK_and spaces.iso", 524309, 0xB010, True),
    ("deep", "140_long_path_payload_alpha.bin", 786451, 0xB011, True),
    ("deep", "141_long_path_payload_beta.bin", 1048597, 0xB012, True),
    ("deep", "142_long_path_payload_gamma.bin", 1310751, 0xB013, True),
    ("deep", "143_long_path_payload_delta.bin", 1572877, 0xB014, True),
    ("wide", "150_commas,spaces,and;symbols.bin", 1835021, 0xB015, True),
    ("wide", "151_square[brackets]_visible.bin", 2097163, 0xB016, True),
    ("wide", "152_very_long_stem_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx.bin", 2359299, 0xB017, True),
    ("wide", "153_mixed.script_\u03bb_\u4f8b_\U0001F680.bin", 2621453, 0xB018, True),
    ("archive", "160_archive.part001.rar", 2883597, 0xB019, True),
    ("archive", "161_archive.part002.rar", 3145739, 0xB01A, True),
    ("archive", "162_stream.capture.sample.mkv", 3407881, 0xB01B, True),
    ("archive", "163_large_tail_payload.iso", 3670027, 0xB01C, True),
]
TREE_STRESS_BRANCH_COUNT = 500
TREE_STRESS_FILES_PER_BRANCH = 100
TREE_STRESS_EMPTY_CHILDREN_PER_BRANCH = 0
TREE_STRESS_GROUP_SIZE = 10
TREE_STRESS_MIN_FILE_COUNT = 50000
TREE_STRESS_MIN_OBSERVABLE_NODES = 10000


def to_windows_long_path(path: Path) -> str:
    """Converts one absolute path into the extended-length Win32 namespace."""

    absolute = str(path.resolve())
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute[2:]
    return "\\\\?\\" + absolute


def write_json(path: Path, payload) -> None:
    """Writes one UTF-8 JSON file with stable formatting."""

    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def ensure_directory(path: Path) -> None:
    """Creates one directory using an extended-length Windows path."""

    os.makedirs(to_windows_long_path(path), exist_ok=True)


def build_payload_chunk(state: int, size_bytes: int) -> tuple[bytes, int]:
    """Builds one deterministic payload chunk and returns the updated state."""

    chunk = bytearray(size_bytes)
    for index in range(size_bytes):
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        chunk[index] = (state >> 16) & 0xFF
    return bytes(chunk), state


def write_deterministic_file(path: Path, size_bytes: int, seed: int) -> str:
    """Creates or reuses one deterministic binary file."""

    ensure_directory(path.parent)
    existing_size = None
    try:
        existing_size = os.stat(to_windows_long_path(path)).st_size
    except OSError:
        existing_size = None

    if existing_size == size_bytes:
        return "reused"

    state = seed & 0xFFFFFFFF
    with open(to_windows_long_path(path), "wb") as handle:
        remaining = size_bytes
        while remaining > 0:
            chunk_size = min(65536, remaining)
            chunk, state = build_payload_chunk(state or 0xC0FFEE11, chunk_size)
            handle.write(chunk)
            remaining -= chunk_size
    return "written"


def make_branch_segment(branch_index: int, level: int) -> str:
    """Returns one deterministic long-path directory segment."""

    part_a = LONG_PATH_NAME_PARTS[(branch_index + level) % len(LONG_PATH_NAME_PARTS)]
    part_b = LONG_PATH_NAME_PARTS[(branch_index * 3 + level * 5) % len(LONG_PATH_NAME_PARTS)]
    filler = f"branch_{branch_index:02d}_level_{level:02d}_" + ("x" * (18 + ((branch_index + level) % 7)))
    return f"{filler}__{part_a}__{part_b}"


def make_long_output_file_name(branch_index: int, file_index: int) -> str:
    """Returns one deterministic long-path output file name."""

    template = LONG_PATH_OUTPUT_FILE_TEMPLATES[(file_index - 1) % len(LONG_PATH_OUTPUT_FILE_TEMPLATES)]
    tail = "q" * (24 + ((branch_index + file_index) % 9))
    return template.format(branch=branch_index, file=file_index, tail=tail)


def build_file_entry(
    root: Path,
    path: Path,
    size_bytes: int,
    seed: int,
    materialization: str,
    expected_visible: bool,
) -> dict[str, object]:
    """Builds one manifest entry for a generated file."""

    absolute_path = str(path.resolve())
    return {
        "name": path.name,
        "relative_path": str(path.relative_to(root)).replace("/", "\\"),
        "absolute_path": absolute_path,
        "size_bytes": size_bytes,
        "seed": seed,
        "path_length": len(absolute_path),
        "materialization": materialization,
        "expected_visible": expected_visible,
    }


def summarize_generated_subtree(root: Path, directories: list[Path], files: list[dict[str, object]]) -> dict[str, object]:
    """Summarizes one generated subtree for harness reporting."""

    sorted_by_size = sorted(files, key=lambda entry: (int(entry["size_bytes"]), str(entry["name"]).lower(), str(entry["relative_path"]).lower()))
    sorted_by_name = sorted(files, key=lambda entry: (str(entry["name"]).lower(), str(entry["relative_path"]).lower()))
    visible_files = [entry for entry in files if bool(entry["expected_visible"])]
    visible_sorted_by_size = sorted(
        visible_files,
        key=lambda entry: (int(entry["size_bytes"]), str(entry["name"]).lower(), str(entry["relative_path"]).lower()),
    )
    visible_sorted_by_name = sorted(
        visible_files,
        key=lambda entry: (str(entry["name"]).lower(), str(entry["relative_path"]).lower()),
    )
    directory_paths = [str(path.resolve()) for path in directories]
    file_paths = [str(Path(str(entry["absolute_path"]))) for entry in files]
    return {
        "root": str(root.resolve()),
        "directory_count_including_root": len(directories),
        "file_count": len(files),
        "expected_visible_file_count": len(visible_files),
        "observable_node_count": len(directories) + len(visible_files),
        "max_directory_path_length": max((len(path) for path in directory_paths), default=0),
        "max_file_path_length": max((len(path) for path in file_paths), default=0),
        "directories_over_248_chars": sum(1 for path in directory_paths if len(path) > 248),
        "directories_over_260_chars": sum(1 for path in directory_paths if len(path) > 260),
        "files_over_260_chars": sum(1 for path in file_paths if len(path) > 260),
        "all_file_names": [str(entry["name"]) for entry in sorted_by_name],
        "expected_visible_file_names": [str(entry["name"]) for entry in visible_sorted_by_name],
        "expected_excluded_file_names": [
            str(entry["name"]) for entry in sorted_by_name if not bool(entry["expected_visible"])
        ],
        "smallest_files_by_size": sorted_by_size[:MAX_REPORT_FILES],
        "largest_files_by_size": list(reversed(sorted_by_size[-MAX_REPORT_FILES:])),
        "expected_visible_smallest_files_by_size": visible_sorted_by_size[:MAX_REPORT_FILES],
        "expected_visible_largest_files_by_size": list(reversed(visible_sorted_by_size[-MAX_REPORT_FILES:])),
        "largest_files_by_path_length": sorted(files, key=lambda entry: (-int(entry["path_length"]), str(entry["name"]).lower()))[:MAX_REPORT_FILES],
        "written_file_count": sum(1 for entry in files if entry["materialization"] == "written"),
        "reused_file_count": sum(1 for entry in files if entry["materialization"] == "reused"),
    }


def estimate_shared_files_tree_stress_observable_nodes() -> int:
    """Returns the expected minimum observable tree/list node count for the stress fixture."""

    group_count = (TREE_STRESS_BRANCH_COUNT + TREE_STRESS_GROUP_SIZE - 1) // TREE_STRESS_GROUP_SIZE
    directory_count = 1 + group_count + (TREE_STRESS_BRANCH_COUNT * (1 + TREE_STRESS_EMPTY_CHILDREN_PER_BRANCH))
    file_count = TREE_STRESS_BRANCH_COUNT * TREE_STRESS_FILES_PER_BRANCH
    return directory_count + file_count


def build_long_path_output(root: Path) -> dict[str, object]:
    """Builds the large recursive long-path subtree used for startup profiling."""

    ensure_directory(root)
    directories = [root]
    files: list[dict[str, object]] = []

    for file_name, size_bytes, seed, expected_visible in LONG_PATH_ROOT_FILE_SPECS:
        file_path = root / file_name
        materialization = write_deterministic_file(file_path, size_bytes, seed)
        files.append(build_file_entry(root, file_path, size_bytes, seed, materialization, expected_visible))

    for branch_index, depth in enumerate(LONG_PATH_OUTPUT_BRANCH_DEPTHS, start=1):
        current = root
        for level in range(1, depth + 1):
            current = current / make_branch_segment(branch_index, level)
            ensure_directory(current)
            directories.append(current)

        for file_index in range(1, len(LONG_PATH_OUTPUT_FILE_TEMPLATES) + 1):
            ordinal = ((branch_index - 1) * len(LONG_PATH_OUTPUT_FILE_TEMPLATES)) + file_index
            size_bytes = 196608 + (ordinal * 16384) + branch_index
            seed = 0xC000 + (branch_index * 100) + file_index
            file_path = current / make_long_output_file_name(branch_index, file_index)
            materialization = write_deterministic_file(file_path, size_bytes, seed)
            files.append(build_file_entry(root, file_path, size_bytes, seed, materialization, True))

    summary = summarize_generated_subtree(root, directories, files)
    summary["subtree_name"] = "long_path_output"
    return summary


def build_shared_files_robustness(root: Path) -> dict[str, object]:
    """Builds a richer Shared Files subtree with wider filename and size variation."""

    ensure_directory(root)
    directories = [root]
    realized_directories: set[Path] = {root}
    files: list[dict[str, object]] = []

    for directory_parts in ROBUSTNESS_DIRECTORY_LAYOUT.values():
        current = root
        for part in directory_parts:
            current = current / part
            if current in realized_directories:
                continue
            ensure_directory(current)
            realized_directories.add(current)
            directories.append(current)

    for directory_key, file_name, size_bytes, seed, expected_visible in ROBUSTNESS_FILE_SPECS:
        current = root
        for part in ROBUSTNESS_DIRECTORY_LAYOUT[directory_key]:
            current = current / part
        file_path = current / file_name
        materialization = write_deterministic_file(file_path, size_bytes, seed)
        files.append(build_file_entry(root, file_path, size_bytes, seed, materialization, expected_visible))

    summary = summarize_generated_subtree(root, directories, files)
    summary["subtree_name"] = "shared_files_robustness"
    return summary


def make_tree_stress_file_name(branch_index: int, file_index: int) -> str:
    """Returns one deterministic file name for the 50k-file tree-refresh fixture."""

    stem = [
        "alpha duplicate-name",
        "beta_[brackets]",
        "gamma,comma;semi",
        "delta_unicode_\u03bb_\u4f8b",
        "epsilon_hash#plus+percent%25",
        "zeta multi.part.name",
        "eta CAPS lower",
        "theta spaces and symbols",
    ][file_index % 8]
    return f"{file_index:03d}_{stem}_branch_{branch_index:03d}.bin"


def build_shared_files_tree_stress(root: Path) -> dict[str, object]:
    """Builds the 50k-file Shared Files tree-refresh stress subtree."""

    ensure_directory(root)
    directories = [root]
    files: list[dict[str, object]] = []
    sample_directories: list[str] = [str(root.resolve())]

    for branch_index in range(TREE_STRESS_BRANCH_COUNT):
        group_index = branch_index // TREE_STRESS_GROUP_SIZE
        group_dir = root / f"group_{group_index:02d}_wide stress"
        if group_dir not in directories:
            ensure_directory(group_dir)
            directories.append(group_dir)

        branch_dir = group_dir / f"branch_{branch_index:03d}_unicode_\u03bb_\u4f8b"
        ensure_directory(branch_dir)
        directories.append(branch_dir)
        for child_index in range(TREE_STRESS_EMPTY_CHILDREN_PER_BRANCH):
            empty_child_dir = branch_dir / f"empty_child_{branch_index:03d}_{child_index:02d}"
            ensure_directory(empty_child_dir)
            directories.append(empty_child_dir)
        if len(sample_directories) < 12:
            sample_directories.append(str(branch_dir.resolve()))

        for file_index in range(TREE_STRESS_FILES_PER_BRANCH):
            size_bytes = 1 + ((branch_index * 17 + file_index * 31) % 4096)
            seed = 0xD00000 + (branch_index * 257) + file_index
            file_path = branch_dir / make_tree_stress_file_name(branch_index, file_index)
            materialization = write_deterministic_file(file_path, size_bytes, seed)
            files.append(build_file_entry(root, file_path, size_bytes, seed, materialization, True))

    summary = summarize_generated_subtree(root, directories, files)
    summary["subtree_name"] = "shared_files_tree_stress"
    summary["stress_branch_count"] = TREE_STRESS_BRANCH_COUNT
    summary["stress_files_per_branch"] = TREE_STRESS_FILES_PER_BRANCH
    summary["stress_empty_children_per_branch"] = TREE_STRESS_EMPTY_CHILDREN_PER_BRANCH
    summary["min_file_count"] = TREE_STRESS_MIN_FILE_COUNT
    summary["min_observable_node_count"] = TREE_STRESS_MIN_OBSERVABLE_NODES
    summary["sample_directories"] = sample_directories
    if int(summary["expected_visible_file_count"]) < TREE_STRESS_MIN_FILE_COUNT:
        raise RuntimeError(
            "Shared Files tree stress fixture has too few shared files: "
            f"{summary['expected_visible_file_count']} < {TREE_STRESS_MIN_FILE_COUNT}"
        )
    if int(summary["observable_node_count"]) < TREE_STRESS_MIN_OBSERVABLE_NODES:
        raise RuntimeError(
            "Shared Files tree stress fixture is undersized: "
            f"{summary['observable_node_count']} < {TREE_STRESS_MIN_OBSERVABLE_NODES}"
        )
    return summary


def ensure_fixture(shared_root: Path | str = DEFAULT_SHARED_ROOT, *, include_tree_stress: bool = False) -> dict[str, object]:
    """Ensures the deterministic generated long-path fixture tree exists and returns its manifest."""

    resolved_root = Path(shared_root).resolve()
    ensure_directory(resolved_root)

    long_path_output = build_long_path_output(resolved_root / "long_path_output")
    shared_files_robustness = build_shared_files_robustness(resolved_root / "shared_files_robustness")
    subtrees = {
        "long_path_output": long_path_output,
        "shared_files_robustness": shared_files_robustness,
    }
    if include_tree_stress:
        subtrees["shared_files_tree_stress"] = build_shared_files_tree_stress(
            resolved_root / "shared_files_tree_stress_50k"
        )

    manifest_path = resolved_root / MANIFEST_FILENAME
    manifest = {
        "fixture_version": FIXTURE_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "shared_root": str(resolved_root),
        "manifest_path": str(manifest_path),
        "subtrees": subtrees,
    }
    write_json(manifest_path, manifest)
    return manifest


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for generating the deterministic long-path fixture tree."""

    parser = argparse.ArgumentParser(
        description="Generate deterministic long-path fixture trees for Shared Files live testing."
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=str(DEFAULT_SHARED_ROOT),
        help="Destination root to populate. Defaults to C:\\tmp\\00_long_paths",
    )
    parser.add_argument(
        "--include-tree-stress",
        action="store_true",
        help="Also materialize the 50k-file Shared Files tree-refresh stress subtree.",
    )
    args = parser.parse_args(argv)

    manifest = ensure_fixture(args.root, include_tree_stress=args.include_tree_stress)
    print(f"Generated fixture root: {manifest['shared_root']}")
    print(f"Manifest: {manifest['manifest_path']}")
    for subtree_name, subtree in manifest["subtrees"].items():
        print(
            f"{subtree_name}: "
            f"dirs={subtree['directory_count_including_root']} "
            f"files={subtree['file_count']} "
            f"max_dir_len={subtree['max_directory_path_length']} "
            f"max_file_len={subtree['max_file_path_length']} "
            f"written={subtree['written_file_count']} reused={subtree['reused_file_count']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
