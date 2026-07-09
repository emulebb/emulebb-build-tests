"""Ephemeral secondary LAN IP aliases for the local parity swarm.

The local MFC-vs-rust swarm gives every client its own source IP so the ed2k
server and the uploader treat each instance as a distinct host (per-IP upload
slot caps, source dedup, and same-IP anti-abuse all key on the source IP). We
alias a small pool of free addresses onto the LAN interface that already holds
``X_LOCAL_IP`` (all P2P + REST binding stays on that one physical interface,
never loopback -- loopback is broken by the hide.me split tunnel), then remove
them again on teardown. Requires an elevated process (``New-NetIPAddress``).
"""

from __future__ import annotations

import ipaddress
import subprocess
from dataclasses import dataclass, field


def _powershell(script: str) -> str:
    """Runs a PowerShell snippet and returns stdout (raises on non-zero exit)."""

    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"PowerShell failed ({completed.returncode}): {completed.stderr.strip() or completed.stdout.strip()}"
        )
    return completed.stdout.strip()


def resolve_interface_index(lan_ip: str) -> int:
    """Returns the interface index of the adapter that holds ``lan_ip``."""

    out = _powershell(
        f"(Get-NetIPAddress -IPAddress '{lan_ip}' -AddressFamily IPv4 -ErrorAction Stop).InterfaceIndex"
    )
    return int(out.splitlines()[0].strip())


def _assigned_ips(interface_index: int) -> set[str]:
    """Returns the IPv4 addresses currently assigned to the interface."""

    out = _powershell(
        "Get-NetIPAddress -InterfaceIndex "
        f"{interface_index} -AddressFamily IPv4 | ForEach-Object {{ $_.IPAddress }}"
    )
    return {line.strip() for line in out.splitlines() if line.strip()}


def _is_free(ip: str) -> bool:
    """Best-effort check that ``ip`` is not answering on the LAN (ping sweep)."""

    # Windows PowerShell 5.1's Test-Connection has no -TimeoutSeconds; -Count 1
    # -Quiet is enough for a best-effort "is this address answering" probe.
    out = _powershell(f"[bool](Test-Connection -ComputerName '{ip}' -Count 1 -Quiet)")
    return out.strip().lower() != "true"


@dataclass
class LanIpPool:
    """Provisions/removes a pool of secondary IPv4 aliases on one LAN interface.

    Only addresses this pool actually adds are removed on ``release`` -- an IP
    that was already assigned (e.g. ``X_LOCAL_IP`` itself) is never touched.
    """

    lan_ip: str
    prefix_length: int = 24
    first_octet4: int = 211
    last_octet4: int = 250
    interface_index: int = field(init=False)
    _added: list[str] = field(default_factory=list, init=False)
    _saved_dad_transmits: int | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self.interface_index = resolve_interface_index(self.lan_ip)

    def _candidates(self) -> list[str]:
        network = ipaddress.ip_interface(f"{self.lan_ip}/{self.prefix_length}").network
        base = str(self.lan_ip).rsplit(".", 1)[0]
        out: list[str] = []
        for octet in range(self.first_octet4, self.last_octet4 + 1):
            ip = f"{base}.{octet}"
            if ipaddress.ip_address(ip) in network:
                out.append(ip)
        return out

    def _disable_dad(self) -> None:
        """Disables Duplicate Address Detection so new aliases are usable at once.

        A freshly aliased IPv4 sits in the ``Tentative`` state while DAD runs;
        rust's REST/P2P socket bind fails on a Tentative address (WSAEADDRNOTAVAIL
        / os error 10049) even though .NET tolerates it. These are known-free lab
        addresses, so we skip DAD (DadTransmits 0) -> aliases come up ``Preferred``
        immediately -> then restore the original setting on release.
        """

        if self._saved_dad_transmits is not None:
            return
        out = _powershell(
            "(Get-NetIPInterface -InterfaceIndex "
            f"{self.interface_index} -AddressFamily IPv4).DadTransmits"
        )
        try:
            self._saved_dad_transmits = int(out.splitlines()[0].strip())
        except (ValueError, IndexError):
            self._saved_dad_transmits = 1
        _powershell(
            "Set-NetIPInterface -InterfaceIndex "
            f"{self.interface_index} -AddressFamily IPv4 -DadTransmits 0"
        )

    def _restore_dad(self) -> None:
        if self._saved_dad_transmits is None:
            return
        try:
            _powershell(
                "Set-NetIPInterface -InterfaceIndex "
                f"{self.interface_index} -AddressFamily IPv4 -DadTransmits {self._saved_dad_transmits}"
            )
        except RuntimeError:
            pass
        self._saved_dad_transmits = None

    def acquire(self, count: int) -> list[str]:
        """Aliases ``count`` free addresses onto the interface and returns them."""

        self._disable_dad()
        assigned = _assigned_ips(self.interface_index)
        acquired: list[str] = []
        for ip in self._candidates():
            if len(acquired) >= count:
                break
            if ip in assigned or ip == self.lan_ip:
                continue
            if not _is_free(ip):
                continue
            _powershell(
                "New-NetIPAddress -InterfaceIndex "
                f"{self.interface_index} -IPAddress '{ip}' -PrefixLength {self.prefix_length} "
                "-ErrorAction Stop | Out-Null"
            )
            self._added.append(ip)
            acquired.append(ip)
        if len(acquired) < count:
            self.release()
            raise RuntimeError(
                f"could only provision {len(acquired)}/{count} free LAN IP aliases in "
                f"{self.lan_ip}/{self.prefix_length}"
            )
        return acquired

    def release(self) -> None:
        """Removes every alias this pool added (idempotent, best-effort)."""

        while self._added:
            ip = self._added.pop()
            try:
                _powershell(
                    f"Remove-NetIPAddress -IPAddress '{ip}' -InterfaceIndex "
                    f"{self.interface_index} -Confirm:$false -ErrorAction SilentlyContinue"
                )
            except RuntimeError:
                pass
        self._restore_dad()

    def __enter__(self) -> "LanIpPool":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()
