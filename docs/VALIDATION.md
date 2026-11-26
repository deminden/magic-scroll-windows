# Validation evidence

Tests run on 8 October 2026, using one Windows 11 computer and a USB-C Magic Mouse.

| Check | Result |
|---|---|
| OS | Windows 11 Home, 64-bit, build 26300 |
| Mouse identity | Apple Bluetooth VID 004C, PID 0323 |
| Rust unit tests | 6 passed in the final installer source; CLI approval/arity, exact device identity, PE bounds and multi-string validation |
| Rust release build | Passed locally with Windows GNU Rust 1.99.0 |
| Published Windows binaries | GitHub-built MSVC executables ran on the test computer; help, menu exit, and existing-installation checks passed |
| Release verification | ZIP and executable checksums matched; GitHub provenance verified against the source commit and release tag |
| Setup and test executable signing | No Authenticode signature; checksums and GitHub build provenance are provided separately |
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
| USB-C touch scrolling | Physical Raw Input test recorded 233 vertical and 132 horizontal wheel events; vertical scrolling was confirmed working normally in apps |
| Cursor/click preservation after binding | Recorded 963 motion events, 3 left clicks, and 1 right click |
| Bluetooth reconnect | Confirmed working after switching the mouse off for two minutes and back on; the second test captured vertical and horizontal wheel input |
| Horizontal scrolling in apps | Pending |
| Sleep/wake, cold reboot | Pending |
| Removal on hardware | Pending |

Installation used administrator access with approval. Windows security settings
were unchanged. Physical scrolling was recorded before the final guided-menu and
Windows-binding refactor. Checks for the final package cover builds, linting,
unit tests, command-line behaviour, and download verification; a full installation
through the new menu is pending.

The physical test counts input attributed to Apple PID 0323 and sends no synthetic
input. Vertical scrolling was confirmed in normal apps. The pending checks above
cover the remaining hardware validation.

Second physical test: 331 movement events, 1 left click, 84 vertical wheel events,
and 86 horizontal wheel events. Scrolling after two minutes off and back on
was confirmed, completing the initial Bluetooth reconnect check.
