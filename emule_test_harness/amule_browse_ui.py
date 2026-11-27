"""Exercise the frozen monolithic aMule transfer source's native View Files action."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path


def browse_rust_shares(
    *, process_id: int, peer_name: str, anchor_name: str, file_name: str,
    timeout_seconds: float = 90.0, expected_count: int | None = None,
) -> dict[str, object]:
    """Select a newly browsed file for download in isolated monolithic aMule."""
    if not 0 < timeout_seconds <= 300:
        raise ValueError("Peer browse timeout must be positive and at most 300 seconds")
    arguments = {
        "process_id": process_id, "peer_name": peer_name, "anchor_name": anchor_name,
        "file_name": file_name,
        "timeout_seconds": timeout_seconds,
        "expected_count": expected_count,
    }
    # Bound synchronous Win32 calls even if the GUI stops pumping messages.
    # The worker only attaches to the existing GUI; a timeout kills only the worker.
    child = subprocess.run(
        [sys.executable, "-B", str(Path(__file__).resolve())],
        input=json.dumps(arguments), text=True, capture_output=True, timeout=timeout_seconds + 2,
    )
    if child.returncode:
        raise RuntimeError(child.stderr.strip()[-1200:] or "aMule browse UI worker failed")
    return json.loads(child.stdout)


def _read_native_browse(*, process_id, peer_name, anchor_name, file_name, timeout_seconds, expected_count=None):
    """Drive the frozen Windows controls from a PID-scoped pywinauto connection."""
    import psutil
    from pywinauto import Application
    from pywinauto.win32defines import WM_CHAR, WM_COMMAND

    if Path(psutil.Process(process_id).exe()).name.lower() != "amule.exe":
        raise ValueError("Peer browse UI requires the isolated monolithic amule.exe PID")
    if not anchor_name or not peer_name or not re.fullmatch(r"[a-zA-Z0-9.]+", file_name):
        raise ValueError("Peer browse requires fixture identities and a plain ASCII canary name")
    app = Application(backend="win32").connect(process=process_id)
    deadline = time.monotonic() + timeout_seconds

    def wait(description, read):
        while time.monotonic() < deadline:
            result = read()
            if result is not None:
                return result
            time.sleep(0.15)
        raise TimeoutError(f"aMule GUI timed out waiting for {description}")

    def unique(windows):
        if len(windows) > 1:
            raise RuntimeError("Ambiguous control in isolated aMule process")
        return windows[0] if windows else None

    def by_id(owner, control_id):
        return unique([w for w in owner.descendants() if w.control_id() == control_id and w.is_visible()])

    main = wait("main window", lambda: unique([
        w for w in app.windows() if w.is_visible() and w.descendants(class_name="ToolbarWindow32")
    ]))

    def switch_page(command):
        for toolbar in main.descendants(class_name="ToolbarWindow32"):
            if toolbar.is_visible():
                for index in range(toolbar.button_count()):
                    if toolbar.get_button_struct(index).idCommand == command:
                        toolbar.button(index).click()
                        return
        raise RuntimeError("aMule toolbar does not expose the requested page")

    def list_body(control):
        # wxGenericListCtrl owns separate header and scrollable-body windows.
        # The body is below the header and occupies most of the list.
        children = [child for child in control.children() if child.is_visible()]
        if len(children) != 2:
            return None
        header, body = sorted(children, key=lambda child: child.rectangle().top)
        return body if body.rectangle().height() > max(12, header.rectangle().height()) else None

    def body_by_id(owner, control_id):
        control = by_id(owner, control_id)
        return list_body(control) if control else None

    def row_command(body, command):
        # The popup command belongs to the wx list, while its child renders
        # the rows. Select through the child and post the menu's native command
        # to its owner without taking foreground input from the desktop.
        body.click(coords=(25, 8))
        body.parent().post_message(WM_COMMAND, command)

    def press_button(button):
        button.parent().post_message(WM_COMMAND, button.control_id(), button.handle)

    def check_details(title, field_id, close_id, expected):
        dialog = wait(title, lambda: unique([w for w in app.windows(title=title) if w.is_visible()]))
        try:
            field = wait(title + " identity", lambda: by_id(dialog, field_id))
            if field.window_text() != expected:
                raise RuntimeError(f"aMule {title} does not identify the expected fixture")
        finally:
            close_button = by_id(dialog, close_id)
            if close_button:
                press_button(close_button)
            else:
                dialog.close()
        wait(title + " dismissal", lambda: True if main.is_enabled() else None)

    # IDs are from frozen muuli_wdr.h. wx stores peer/transfer names only in
    # the model; their native Details dialogs surface them as real static text.
    switch_page(10347)  # Searches
    notebook = wait("search notebook", lambda: by_id(main, 10024))
    # Frozen SearchDlg.cpp creates CSearchListCtrl with wxID_HIGHEST + 667.
    result_id = 6666
    if any(w.control_id() == result_id for w in notebook.descendants()):
        raise RuntimeError("Isolated aMule already has a search result before View Files")
    switch_page(10348)  # Transfers
    anchor = wait("isolated download anchor list", lambda: body_by_id(main, 10028))
    # Menu IDs from frozen src/include/common/MenuIDs.h (wxID_HIGHEST=5999).
    row_command(anchor, 6036)  # MP_METINFO
    check_details("File Details", 10033, 5100, anchor_name)
    anchor.click(coords=(25, 8))
    peers = wait("anchor's source list", lambda: body_by_id(main, 10031))
    row_command(peers, 6001)  # MP_DETAIL
    check_details("Client Details", 10091, 10112, peer_name)
    row_command(peers, 6004)  # MP_SHOWLIST
    switch_page(10347)  # Searches
    result = wait("new peer browse result list", lambda: body_by_id(notebook, result_id))

    if expected_count is not None:
        from pywinauto.controls.common_controls import TabControlWrapper

        tab = TabControlWrapper(notebook.element_info)
        expected_label = f"{peer_name} ({expected_count})"

        def complete_count():
            # Frozen SearchDlg.cpp displays the count in the CMuleNotebook tab.
            if tab.tab_count() == 1:
                return expected_count if tab.get_tab_text(0) == expected_label else None
            accessible = Application(backend="uia").connect(process=process_id)
            labels = accessible.window(handle=notebook.handle).descendants(control_type="TabItem")
            return expected_count if any(item.element_info.name == expected_label for item in labels) else None

        wait(f"exact result tab {expected_label}", complete_count)

    # The native Download button becomes enabled only after the list has
    # received a row and selected it. Then type-to-select the canary.
    def select_result():
        result.click(coords=(25, 8))
        button = by_id(main, 10021)
        return button if button and button.is_enabled() else None

    download = wait("selectable peer browse result", select_result)
    for character in file_name:
        result.post_message(WM_CHAR, ord(character), 1)
    press_button(download)
    return {"peerName": peer_name, "anchorName": anchor_name,
            "resultWindow": result.handle, "processId": process_id,
            **({"resultCount": expected_count} if expected_count is not None else {})}


if __name__ == "__main__":
    try:
        print(json.dumps(_read_native_browse(**json.load(sys.stdin))))
    except Exception as error:
        sys.exit(f"{type(error).__name__}: {error}")
