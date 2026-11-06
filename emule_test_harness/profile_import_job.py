"""Workspace-independent stock/MFC import orchestration; never reads payloads."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import uuid

from . import emule_profile_export as export
from . import profile_import_audit as audit
from .profile_exchange import write_exchange


@dataclass(frozen=True)
class ImportJob:
    """Host-side job; Docker mappings distinguish stock, host, and container paths."""
    exchange: export.ExportJob
    backend: str
    profile: Path
    output: Path
    binary: Path | None
    image: str | None
    distribution: str
    hosts: tuple[export.PathMapping, ...]
    timeout: int


def contains_physical_path(parent: Path, candidate: Path) -> bool:
    """Compare resolved paths and existing ancestor identities, including volume aliases."""
    parent, candidate = parent.resolve(), candidate.resolve()
    if candidate.is_relative_to(parent):
        return True
    if parent.exists():
        for ancestor in (candidate, *candidate.parents):
            if ancestor.exists() and ancestor.samefile(parent):
                return True
    return False


def paths_overlap(first: Path, second: Path) -> bool:
    """Reject containment in either direction, independent of junction spelling."""
    return contains_physical_path(first, second) or contains_physical_path(second, first)


def load_job(config: Path) -> ImportJob:
    """Validate all job fields without creating the destination or output."""
    config = config.resolve()
    with config.open("rb") as stream:
        data = export.tomllib.load(stream)
    export._require_keys(data, {"schema_version", "source", "target", "output", "path_mappings"}, "job")
    if data.get("schema_version") != 1:
        raise ValueError("schema_version must be 1")
    source, target, output = (export._require_table(data, key) for key in ("source", "target", "output"))
    export._require_keys(source, {"profile", "flavor"}, "source")
    export._require_keys(target, {"backend", "profile", "binary", "image", "distribution", "timeout_seconds"}, "target")
    export._require_keys(output, {"directory"}, "output")
    resolve = lambda value: export._resolve_job_path(config, value)
    source_path = export.resolve_emule_config_dir(resolve(export._require_string(source, "profile")))
    flavor = source.get("flavor", "auto")
    if flavor not in export.SUPPORTED_FLAVORS:
        raise ValueError("source.flavor must be auto, stock, or mfc")
    backend = export._require_string(target, "backend")
    if backend not in {"windows", "docker", "wsl-docker"}:
        raise ValueError("target.backend must be windows, docker, or wsl-docker")
    if (backend in {"windows", "wsl-docker"}) != (os.name == "nt"):
        raise ValueError("selected backend does not match the host OS")
    profile = resolve(export._require_string(target, "profile"))
    out = resolve(export._require_string(output, "directory"))
    if profile.exists() and not profile.is_dir():
        raise ValueError("destination must be a directory")
    mappings, hosts = [], []
    seen_sources, seen_targets = set(), set()
    raw = data.get("path_mappings", [])
    if not isinstance(raw, list):
        raise ValueError("path_mappings must be an array of tables")
    for item in raw:
        export._require_keys(item, {"source", "host", "target"}, "path mapping")
        stock = export._normalize_windows_absolute(export._require_string(item, "source"))
        destination = export._normalize_target_absolute(export._require_string(item, "target"), "windows" if backend == "windows" else "unix")
        host = resolve(export._require_string(item, "host"))
        if not host.is_dir():
            raise ValueError("a mapped host directory is inaccessible")
        key = export.ntpath.normcase(stock)
        if key in seen_sources or destination in seen_targets:
            raise ValueError("duplicate mapping source or target")
        if backend != "windows" and (destination == "/" or any(
            PurePosixPath(destination).is_relative_to(p) or PurePosixPath(p).is_relative_to(destination)
            for p in ("/profile", "/import", "/usr", "/etc", "/proc", "/sys", "/dev")
        )):
            raise ValueError("mapping overlaps a reserved container path")
        if backend == "windows" and not Path(destination).samefile(host):
            raise ValueError("Windows mapping host and target must identify the same directory")
        seen_sources.add(key)
        seen_targets.add(destination)
        mappings.append(export.PathMapping(stock, destination))
        hosts.append(export.PathMapping(str(host), destination))
    if backend != "windows" and not mappings:
        raise ValueError("Docker jobs require explicit path_mappings")
    mappings.sort(key=lambda m: len(m.source), reverse=True)
    job = export.ExportJob(config, source_path, flavor, "windows" if backend == "windows" else "unix", out / "unused.sqlite", tuple(mappings))
    roots = export.discover_shared_roots(source_path, export.detect_profile_flavor(source_path))
    for root in roots:
        mapped = export.map_shared_root(root.path, job)
        if backend == "windows":
            if not Path(mapped).is_dir():
                raise ValueError("a stock shared directory is inaccessible")
        else:
            audit.source_path_for_binding("unix", mapped.encode(), tuple(hosts)).stat()
    # WHY: profile writes and report output must never enter a shared/source tree.
    protected = [source_path] + [Path(h.source) for h in hosts]
    if backend == "windows":
        protected += [Path(export.map_shared_root(r.path, job)) for r in roots]
    for path in (profile, out):
        if any(paths_overlap(path, p) for p in protected):
            raise ValueError("destination/output overlaps source metadata or shared data")
    if paths_overlap(profile, out):
        raise ValueError("destination and output directories must be separate")
    binary = resolve(export._require_string(target, "binary")) if backend == "windows" else None
    image = export._require_string(target, "image") if backend != "windows" else None
    if binary is not None and not binary.is_file():
        raise ValueError("target.binary does not exist")
    if backend == "windows" and any(k in target for k in ("image", "distribution")):
        raise ValueError("image/distribution apply only to Docker backends")
    if backend != "windows" and "binary" in target:
        raise ValueError("binary applies only to the Windows backend")
    timeout = target.get("timeout_seconds", 7200)
    if type(timeout) is not int or timeout <= 0:
        raise ValueError("timeout_seconds must be a positive integer")
    distribution = target.get("distribution", "Ubuntu")
    if not isinstance(distribution, str) or not distribution.strip():
        raise ValueError("distribution must be a nonempty string")
    if backend != "wsl-docker" and "distribution" in target:
        raise ValueError("distribution applies only to wsl-docker")
    return ImportJob(job, backend, profile, out, binary, image, distribution, tuple(hosts), timeout)


def checked(command: list[str], timeout: int) -> None:
    """Run a bounded setup command without shell interpretation."""
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "backend command failed")


def command_prefix(job: ImportJob, report: Path, cleanup: ExitStack) -> list[str]:
    """Prepare isolated containers and own only temporary mounts created here."""
    if job.backend == "windows":
        return [str(job.binary), "--profile", str(job.profile)]
    wsl = ["wsl.exe", "-d", job.distribution] if job.backend == "wsl-docker" else []
    docker = wsl + (["--"] if wsl else []) + ["docker"]
    checked(docker + ["image", "inspect", job.image], job.timeout)
    mounts = [(job.profile, "/profile", False), (report, "/import", True)]
    mounts += [(Path(m.source), m.target, True) for m in job.hosts]
    user = "1000:1000" if wsl else f"{os.getuid()}:{os.getgid()}"
    token = uuid.uuid4().hex
    name = "emulebb-import-" + token
    prefix = docker + ["run", "--rm", "--name", name, "--network", "none", "--no-healthcheck",
                       "--user", user, "--entrypoint", "/usr/lib/emulebb-rust/emulebb-rust"]
    for index, (host, target, readonly) in enumerate(mounts):
        source = str(host)
        if wsl:
            source = f"/mnt/emulebb-import-{token}-{index}"
            root = wsl + ["-u", "root", "--"]
            checked(root + ["mkdir", source], job.timeout)
            cleanup.callback(checked, root + ["rmdir", source], job.timeout)
            options = "ro" if readonly else "metadata,uid=1000,gid=1000,umask=077"
            checked(root + ["mount", "-t", "drvfs", "-o", options, host.as_posix(), source], job.timeout)
            cleanup.callback(checked, root + ["umount", source], job.timeout)
        if "," in source or "," in target:
            raise ValueError("Docker bind paths cannot contain commas")
        prefix += ["--mount", f"type=bind,src={source},dst={target}" + (",readonly" if readonly else "")]
    # WHY: killing a timed-out Docker CLI does not necessarily stop its container.
    # Register last so the owned container is removed before unmount callbacks.
    cleanup.callback(remove_container, docker, name, job.timeout)
    return prefix + [job.image, "--profile", "/profile"]


def remove_container(docker: list[str], name: str, timeout: int) -> None:
    """Clean up only this job's named container, including after CLI interruption."""
    result = subprocess.run(docker + ["rm", "--force", name], capture_output=True, text=True, timeout=timeout)
    if result.returncode and "no such container" not in result.stderr.lower():
        raise RuntimeError("could not remove the import container: " + result.stderr.strip())


def run_job(job: ImportJob) -> tuple[int, dict]:
    """Apply one offline import/merge and retain a diagnostic on failure."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    report_dir = job.output / stamp
    report_dir.mkdir(parents=True)
    report = {"schema": "emulebb.profile-import-job.v1", "backend": job.backend,
              "destinationModified": False, "networkStarted": False,
              "report": str(report_dir / "summary.json")}
    code = 1
    try:
        archive = report_dir / "hashes.sqlite"
        report["export"] = write_exchange(export.replace(job.exchange, output_manifest=archive), host_mappings=job.hosts)["summary"]
        job.profile.mkdir(parents=True, exist_ok=True)
        with ExitStack() as cleanup:
            prefix = command_prefix(job, report_dir, cleanup)
            report["destinationModified"] = True
            path = str(archive) if job.backend == "windows" else "/import/hashes.sqlite"
            report["import"] = audit.run_json(prefix + ["import-emule-profile", path], job.timeout)
            report["hashValidation"] = audit.validate_imported_hashes(
                job.profile, archive, rejected_recovery_sets=report["import"]["rejectedRecoverySets"],
            )
            report["stockValidation"] = audit.validate_stock_records(job.profile, job.exchange.source_profile, archive)
            progress = report["reconciliation"] = audit.run_json(prefix + ["reconcile-shared-files"], job.timeout)
            audit.validate_reconciliation(progress)
            report["bindingValidation"] = audit.validate_native_bindings(
                job.profile, job.exchange, exchange=archive, host_mappings=job.hosts if job.hosts else None,
                allow_unrelated=True, conflicting_paths=report["import"].get("conflictingPaths",0),
            )
            report["counts"] = audit.profile_counts(job.profile)
            attention = any(progress[k] for k in ("plannedHashCount", "statFailedCount", "skippedFailedCount", "skippedIntakeCount"))
            attention |= progress.get("scannedCount", 0) == 0
            attention |= bool(report["import"].get("unmatchedPaths",0) or report["import"].get("conflictingPaths",0))
            attention |= bool(report["export"]["recoveryMissingSets"] or report["export"]["skippedKnown"]
                              or report["import"]["rejectedRecoverySets"])
            code = 2 if attention else 0
            report["status"] = "needs-attention" if attention else "complete-reuse"
    except (Exception, KeyboardInterrupt) as error:
        report.update(status="failed", error=str(error))
        code = 1
    finally:
        report["exitCode"] = code
        (report_dir / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return code, report


def main(argv: list[str] | None = None) -> int:
    """Run the TOML-only operator interface without workspace discovery."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        code, report = run_job(load_job(args.config))
    except Exception as error:
        print(f"Preflight failed: {error}")
        return 1
    progress = report.get("reconciliation", {})
    print(f"Result: {report['status']}; reused={progress.get('reusedCount', 0)}; "
          f"pending hashing={progress.get('plannedHashCount', 0)}; "
          f"unresolved={progress.get('skippedFailedCount', 0)}; "
          f"stat failures={progress.get('statFailedCount', 0)}")
    print(f"AICH recovery sets: imported={report.get('import', {}).get('importedRecoverySets', 0)}; "
          f"missing={report.get('export', {}).get('recoveryMissingSets', 0)}; "
          f"rejected={report.get('import', {}).get('rejectedRecoverySets', 0)}")
    print(f"Report: {report['report']}")
    if "error" in report:
        print(f"Error: {report['error']}")
    return code
