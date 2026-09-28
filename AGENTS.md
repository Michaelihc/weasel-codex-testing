# Weasel testing copy

This repository preserves the history of `Michaelihc/weasel` and is for isolated
diagnostics and regression work. Keep experimental changes here. Do not install
test builds over the user's daily Weasel installation.

For a game hang, select the exact client PID by executable path, then run the
standard-library Windows probe without desktop automation:

```powershell
Get-CimInstance Win32_Process -Filter "name='SCPSL.exe'" |
  Select-Object ProcessId, ExecutablePath, CommandLine
python tools/hang_probe.py --pid <exact-pid> --out <local-evidence-directory>
```

The probe records visible window response state and captures one thread/handle
minidump after a sustained hang. Keep evidence directories and dumps outside the
repository; a dump contains process memory. Inspect `result.json`, `events.jsonl`,
and the dump before assigning a cause. A run with no Weasel composition or candidate
window is inconclusive for the reported bug, even if the process stays responsive.

Run the probe's Windows API check with:

```powershell
python -m unittest discover -s test/diagnostics -v
```
