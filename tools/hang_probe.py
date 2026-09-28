"""Capture a small Windows dump when a chosen GUI process stops responding."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import json
import msvcrt
from pathlib import Path
import sys
import time


PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_DUP_HANDLE = 0x0040
SYNCHRONIZE = 0x00100000
WAIT_TIMEOUT = 0x00000102
MINIDUMP_WITH_HANDLE_DATA = 0x00000004
MINIDUMP_WITH_UNLOADED_MODULES = 0x00000020
MINIDUMP_WITH_THREAD_INFO = 0x00001000


def windows_for_pid(user32: ctypes.WinDLL, pid: int) -> list[dict[str, object]]:
    windows: list[dict[str, object]] = []
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows.argtypes = (callback_type, wintypes.LPARAM)
    user32.EnumWindows.restype = wintypes.BOOL
    user32.GetWindowThreadProcessId.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.DWORD))
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.IsWindowVisible.argtypes = (wintypes.HWND,)
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.GetWindowTextLengthW.argtypes = (wintypes.HWND,)
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.IsHungAppWindow.argtypes = (wintypes.HWND,)
    user32.IsHungAppWindow.restype = wintypes.BOOL

    def visit(hwnd: int, _lparam: int) -> bool:
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value != pid or not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        title = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, title, len(title))
        if not title.value:
            return True
        windows.append({
            "hwnd": int(hwnd),
            "title": title.value,
            "hung": bool(user32.IsHungAppWindow(hwnd)),
        })
        return True

    callback = callback_type(visit)
    if not user32.EnumWindows(callback, 0):
        raise ctypes.WinError()
    return windows


def capture_dump(pid: int, destination: Path) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    dbghelp.MiniDumpWriteDump.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, wintypes.HANDLE, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    )
    dbghelp.MiniDumpWriteDump.restype = wintypes.BOOL

    access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE
    process = kernel32.OpenProcess(access, False, pid)
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("wb") as output:
            flags = (MINIDUMP_WITH_HANDLE_DATA | MINIDUMP_WITH_UNLOADED_MODULES
                     | MINIDUMP_WITH_THREAD_INFO)
            if not dbghelp.MiniDumpWriteDump(process, pid, msvcrt.get_osfhandle(output.fileno()),
                                              flags, None, None, None):
                raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.CloseHandle(process)


def monitor(pid: int, duration: float, interval: float, hang_seconds: float,
            output: Path) -> dict[str, object]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    process = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                   False, pid)
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())

    output.mkdir(parents=True, exist_ok=True)
    events = output / "events.jsonl"
    deadline = time.monotonic() + duration
    hung_since: float | None = None
    saw_window = False
    result: dict[str, object] = {"pid": pid, "outcome": "no-window-observed"}
    try:
        with events.open("w", encoding="utf-8") as log:
            while time.monotonic() < deadline:
                if kernel32.WaitForSingleObject(process, 0) != WAIT_TIMEOUT:
                    result["outcome"] = "process-exited"
                    break
                windows = windows_for_pid(user32, pid)
                saw_window |= bool(windows)
                hung = any(window["hung"] for window in windows)
                now = time.monotonic()
                if hung:
                    hung_since = hung_since or now
                else:
                    hung_since = None
                event = {"time": datetime.now(timezone.utc).isoformat(),
                         "pid": pid, "windows": windows, "hung": hung}
                log.write(json.dumps(event, ensure_ascii=False) + "\n")
                log.flush()
                if hung_since is not None and now - hung_since >= hang_seconds:
                    dump = output / f"hang-{pid}-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.dmp"
                    capture_dump(pid, dump)
                    result.update(outcome="hang-captured", dump=str(dump))
                    break
                time.sleep(interval)
            else:
                if saw_window:
                    result["outcome"] = "no-hang-observed"
    finally:
        kernel32.CloseHandle(process)
    result["events"] = str(events)
    (output / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True, help="Exact client process ID")
    parser.add_argument("--out", type=Path, required=True, help="Local evidence directory")
    parser.add_argument("--duration", type=float, default=300, help="Maximum observation seconds")
    parser.add_argument("--interval", type=float, default=0.25, help="Polling seconds")
    parser.add_argument("--hang-seconds", type=float, default=2, help="Continuous hang before dump")
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Windows is required")
    if args.pid <= 0 or args.duration <= 0 or args.interval <= 0 or args.hang_seconds <= 0:
        parser.error("PID and timing values must be positive")
    print(json.dumps(monitor(args.pid, args.duration, args.interval,
                             args.hang_seconds, args.out), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
