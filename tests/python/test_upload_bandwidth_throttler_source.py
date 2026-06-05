from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_control_packets_wake_upload_throttler_wait_domains() -> None:
    source = (app_source_root() / "UploadBandwidthThrottler.cpp").read_text(encoding="utf-8", errors="ignore")

    queue_block = source[
        source.index("void UploadBandwidthThrottler::QueueForSendingControlPacket") :
        source.index("void UploadBandwidthThrottler::RemoveFromAllQueuesNoLock")
    ]
    assert "bool bQueuedControlPacket = false;" in queue_block
    assert "bQueuedControlPacket = true;" in queue_block
    assert "control work can arrive while the throttler is waiting" in queue_block
    assert "m_eventDataAvailable.SetEvent();" in queue_block
    assert "m_eventSocketAvailable.SetEvent();" in queue_block


def test_upload_throttler_pacing_wait_is_interruptible_by_new_data() -> None:
    source = (app_source_root() / "UploadBandwidthThrottler.cpp").read_text(encoding="utf-8", errors="ignore")

    wait_block = source[
        source.index("if (timeSinceLastLoop < sleepTime)") :
        source.index("if (!HelperThreadLaunchSeams::IsFlagSet(m_bRun))")
    ]
    assert "::WaitForSingleObject(m_eventDataAvailable, dwSleep);" in wait_block
    assert "::WaitForSingleObject(m_eventSocketAvailable, dwSleep);" in wait_block
    assert "::Sleep(dwSleep);" not in wait_block
