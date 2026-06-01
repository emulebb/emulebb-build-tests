"""Shared Windows VM guest profile helpers."""

from __future__ import annotations

from pathlib import Path

DEFAULT_HIDEME_VPN_GUARD_PUBLIC_IP_CIDRS = (
    "176.10.104.0/22",
    "149.88.27.0/24",
    "98.98.148.0/23",
)
DEFAULT_HIDEME_VPN_GUARD_ALLOWED_PUBLIC_IP_CIDRS = ",".join(DEFAULT_HIDEME_VPN_GUARD_PUBLIC_IP_CIDRS)


def write_preferences_ini(config_dir: Path, text: str) -> None:
    """Writes the VM guest eMule preferences file with Windows-compatible UTF-16 encoding."""

    (config_dir / "preferences.ini").write_text(text, encoding="utf-16")


def local_ed2k_preferences_text(
    *,
    target: str,
    incoming_dir: Path,
    temp_dir: Path,
    tcp_port: int,
    udp_port: int,
    bind_addr: str,
    rest_port: int,
    api_key: str,
) -> str:
    """Builds the eMuleBB profile used by the local VM transfer test."""

    return "\n".join(
        [
            "[eMule]",
            f"Nick={target}-vm",
            "ConfirmExit=0",
            f"IncomingDir={incoming_dir}",
            f"TempDir={temp_dir}",
            f"Port={tcp_port}",
            f"UDPPort={udp_port}",
            "ServerUDPPort=65535",
            f"BindAddr={bind_addr}",
            "BindInterface=",
            "BlockNetworkWhenBindUnavailableAtStartup=1",
            "NetworkED2K=1",
            "NetworkKademlia=0",
            "Autoconnect=0",
            "Reconnect=0",
            "SafeServerConnect=0",
            "FilterBadIPs=0",
            "AllowLocalHostIP=1",
            "GeoLocationLookupEnabled=0",
            "IPFilterEnabled=0",
            "SaveLogToDisk=1",
            "SaveDebugToDisk=1",
            "Verbose=1",
            "FullVerbose=1",
            "[WebServer]",
            "Enabled=1",
            f"ApiKey={api_key}",
            f"Port={rest_port}",
            "BindAddr=127.0.0.1",
            "UseHTTPS=0",
            "[UPnP]",
            "EnableUPnP=0",
            "",
        ]
    )


def hideme_live_preferences_text(
    *,
    target: str,
    incoming_dir: Path,
    temp_dir: Path,
    tcp_port: int,
    udp_port: int,
    rest_port: int,
    lan_bind_addr: str,
    api_key: str,
) -> str:
    """Builds the eMuleBB profile used by the public hide.me VM live-wire test."""

    return "\n".join(
        [
            "[eMule]",
            f"Nick={target}-vm-hideme",
            "ConfirmExit=0",
            f"IncomingDir={incoming_dir}",
            f"TempDir={temp_dir}",
            f"Port={tcp_port}",
            f"UDPPort={udp_port}",
            "BindAddr=",
            "BindInterface=hide.me",
            "NetworkED2K=1",
            "NetworkKademlia=0",
            "Autoconnect=0",
            "Reconnect=0",
            "SafeServerConnect=0",
            "FilterBadIPs=1",
            "IPFilterEnabled=0",
            "GeoLocationLookupEnabled=0",
            "VpnGuardMode=Block",
            f"VpnGuardAllowedPublicIpCidrs={DEFAULT_HIDEME_VPN_GUARD_ALLOWED_PUBLIC_IP_CIDRS}",
            "SaveLogToDisk=1",
            "SaveDebugToDisk=1",
            "Verbose=1",
            "FullVerbose=1",
            "[WebServer]",
            "Enabled=1",
            f"ApiKey={api_key}",
            f"Port={rest_port}",
            f"BindAddr={lan_bind_addr}",
            "UseHTTPS=0",
            "[UPnP]",
            "EnableUPnP=1",
            "",
        ]
    )
