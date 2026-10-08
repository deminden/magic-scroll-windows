# Validation evidence

Date: 2026-10-08. These are development observations, not a stable-release claim.

| Check | Result |
|---|---|
| OS | Windows 11 Home, 64-bit, build 26300 |
| Mouse identity | Apple Bluetooth VID 004C, PID 0323 |
| Rust unit tests | 6 passed in the final installer source; CLI approval/arity, exact device identity, PE bounds and multi-string validation |
| Rust release build | Passed locally with Windows GNU Rust 1.99.0 |
| Guided download preparation | Final `prepare` command passed end to end: pinned official tools, Apple download, nested extraction, hash/PE checks and Windows kernel-signature verification with revocation checking enabled |
| Apple source package | Boot Camp 041-91731 fetched over HTTPS from swcdn.apple.com |
| Driver extracted from Apple package | Version 6.1.7000.0, 69008 bytes, SHA256 pinned in setup code |
| Original Apple installation file | INF version 6.1.7000.0 lists PIDs 030D, 0310 and 0269; USB-C PID 0323 is absent. The tool attaches the unchanged driver explicitly. |
| Kernel signature | Signature index 1 accepted by Windows DRIVER_ACTION_VERIFY and SDK SignTool `/kp /ds 1` |
| Primary signature | Untrusted Apple build test certificate; deliberately not used or trusted |
| PE checks | x64 native image; NX compatible; page alignment; no writable/executable section |
| Installation preflight | No existing target LowerFilters, Apple mouse kernel service, or system driver file before installation |
| Setup plan | Run successfully without system modifications |
| Memory Integrity | Enabled before and after installation |
| Kernel driver load | Passed with user-approved elevation; service RUNNING; exact target bound and restarted |
| USB-C touch scrolling | Physical Raw Input test recorded 233 vertical and 132 horizontal wheel events; user confirmed vertical scrolling works normally in ordinary content |
| Cursor/click preservation after binding | Recorded 963 motion events, 3 left clicks, and 1 right click |
| Bluetooth reconnect | Passed: user confirmed operation after switching the mouse off for two minutes and back on; second test captured vertical and horizontal wheel input |
| Sleep/wake, cold reboot | **Not tested** |
| Real system rollback | **Not tested** |

A user-approved installation was performed. No security settings were changed.
The physical test counts only device-identified Apple PID 0323 Raw Input events;
no synthetic input was sent. The user confirmed vertical scrolling works normally in ordinary content.
Horizontal content behavior and longer-term reliability remain
to be verified. These results demonstrate wheel input on this machine, not support
for every Windows version or mouse configuration.

Second physical test: 331 movement events, 1 left click, 84 vertical wheel events,
and 86 horizontal wheel events. The user confirmed it still works after the mouse was switched off for two
minutes and turned back on. This passes the initial Bluetooth reconnect check.
