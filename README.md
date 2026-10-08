# Magic Scroll for Windows

**Get touch scrolling on the USB-C Apple Magic Mouse using Apple's existing signed driver.**

The Boot Camp driver we tested does not list the USB-C mouse in its installation
file. Installing it normally can leave you with a working pointer and no scrolling.
Magic Scroll attaches that unchanged driver to the USB-C model explicitly.

- **Free, with no subscription or developer certificate to buy.**
- **Download and double-click.** Guided setup; no Rust or terminal required.
- **Keep Windows protection enabled.** Memory Integrity, Secure Boot, certificate
  stores and driver-signing settings stay as they are.
- **Verify before installing; keep a removal option.** Exact file hashes, Windows
  kernel signature checks, device matching and a local removal journal.
- **No background app.** Once installed, Apple's driver handles scrolling.

[Download the Windows x64 ZIP](https://github.com/deminden/magic-scroll-windows/releases)
· [What we tested](docs/VALIDATION.md) · [MIT licence](LICENSE)

> Experimental: verified on one Windows 11 computer. Vertical scrolling and
> reconnection worked; sleep/wake, cold reboot and removal still need physical tests.

## Start here

You need **Windows x64**, the **USB-C Magic Mouse paired over Bluetooth**, internet
access and about **2.5 GB** of free space. ARM64 and older Magic Mouse models are
not supported by this installer.

1. Download `magic-scroll-windows-x64-v…zip` from **Releases** and extract it to a
   folder you can keep. Run the extracted programs, not the files inside the ZIP.
2. Double-click **`magic-scroll-setup.exe`** and choose **1: Download and check**.
   It obtains the driver from Apple and portable extraction tools from 7-zip.org.
   No system installation happens at this step.
3. Read the displayed plan. Close setup, right-click **`magic-scroll-setup.exe`**,
   choose **Run as administrator**, then **2: Install**. Type **INSTALL** only
   when you approve the displayed changes.
4. Slide your finger up and down in a page or document. Check movement and clicks.
   Double-click **`magic-scroll.exe`** for the optional physical input test.

The mouse may briefly disconnect during installation. Windows must permit the
driver to load before the tool attaches it. If loading fails, setup stops and
attempts to undo its changes; follow any reported cleanup instructions.

**Keep `magic-scroll.state.json` in the extracted folder.** It is the removal
journal and contains a private device identifier. Do not upload it to GitHub.
Leave this folder in place if you want the menu to find the download and journal.

The Rust executables are unsigned. GitHub releases include checksums and build
provenance; those do not replace Windows code signing. If Windows blocks an
executable or the driver, stop and inspect the message; do not disable protection.

## Does it actually work?

On **Windows 11 Home x64, build 26300**, with an Apple Bluetooth **VID 004C / PID
0323**, the user confirmed vertical scrolling works normally in ordinary content.
It still worked after switching the mouse off for two minutes and back on.
**Memory Integrity remained enabled.**

| Check | Result |
|---|---|
| Vertical touch scrolling in ordinary content | Confirmed working |
| Horizontal wheel input | Recorded in both physical tests |
| Pointer movement and left/right clicks | Recorded in the first test |
| Bluetooth reconnect after two minutes off | Confirmed working |
| Horizontal scrolling in ordinary content | Still needs a user check |
| Sleep/wake, cold reboot and removal | Not yet tested |

The test program observes input identified as the USB-C Magic Mouse. It sends no
fake mouse events. Counts appear in its title bar; closing it prints the results.
Use another app to judge scrolling direction, speed and feel. Recorded events
alone do not prove the experience is correct. [Full evidence](docs/VALIDATION.md).

## Why more than the Apple driver alone?

The inspected Apple **6.1.7000.0** installation file lists PIDs `030D`, `0310` and
`0269`; **USB-C PID `0323` is missing**. This tool supplies that device attachment,
verifies the exact driver and provides a preview, physical test and removal path.
It preserves the signed driver bytes and does not edit the INF.

Scrolling itself comes from Apple. This is an independently written Rust
implementation of a [previously published attachment method](THIRD_PARTY.md),
with no claim of better scrolling performance or a new touch engine.

Reddit users also reported that ordinary Boot Camp installation did not enable
scrolling on the USB-C model: [December 2024](https://www.reddit.com/r/applehelp/comments/1hmre4r/scroll_on_new_magic_mouse_not_working/)
and [June 2026](https://www.reddit.com/r/applehelp/comments/1tw4b9r/apple_mouse_3_usb_c_a3204_doesnt_scroll_in/).
Those reports are anecdotal; the inspected INF and physical tests support this
project's compatibility claim.

## Remove it

Right-click **`magic-scroll-setup.exe` → Run as administrator**, choose **4:
Remove**, then type **REMOVE**. It uses the journal to detach this installation,
stop its service and remove its driver. Unrelated filter entries are preserved.

Removal has not yet been physically tested. Recovery from a crash or power loss
during installation is also an open test case. Keep the journal if cleanup fails.
Never substitute a journal from another computer.

## Troubleshooting

| Message or symptom | Next step |
|---|---|
| Mouse not found | Connect the USB-C model over Bluetooth; this installer targets PID `0323`. |
| Hash or signature mismatch | Stop. The tool accepts only the reviewed files; changed downloads need a new review. |
| Download folder already exists | Inspect the previous attempt and choose a new folder using the command-line option below. |
| Existing driver, service or filter | Setup refuses to overwrite another installation. If scrolling already works, setup is unnecessary. |
| Administrator access denied | Installation/removal need **Run as administrator**; downloading and testing do not. |
| Windows refuses the driver | Keep protection enabled and read the error and rollback result. |
| Test shows zero counts | Check ordinary content too; the test can reject an unrecognized device identity. |

Report your Windows build, mouse model, step and exact error. Remove device
identifiers from logs and leave the local journal out of the report.

## Build and contribute

Two small Rust programs: `crates/setup` handles driver operations; `crates/app`
records physical input. Comments explain the Windows trust handling, exact device
matching, ownership checks and removal order. No custom kernel driver is built.

Rust **1.88+** and a Windows linker are required to build. The usual MSVC target
needs Microsoft C++ Build Tools; the Windows GNU toolchain is also supported.

```powershell
cargo build --workspace --release --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Command-line use is available for controlled testing:

```powershell
.\magic-scroll-setup.exe prepare ".\driver-download"
.\magic-scroll-setup.exe plan ".\driver-download\apple\mouse\AppleWirelessMouse.sys"
# The next two commands require administrator rights and explicit approval.
.\magic-scroll-setup.exe install ".\driver-download\apple\mouse\AppleWirelessMouse.sys" ".\magic-scroll.state.json" --approve-system-changes
.\magic-scroll-setup.exe rollback ".\magic-scroll.state.json" --approve-system-changes
.\magic-scroll.exe test-scroll
```

`fetch <new-folder> <7z.exe>` is also available when you already have the pinned
7-Zip 25.01 x64 executable/DLL pair. Downloaded files are never redistributed.
See [remaining tests](docs/TESTING.md) and [release instructions](docs/RELEASING.md).

## Licence and credits

By [Denis Demin (@deminden)](https://github.com/deminden). Project source is
[MIT licensed](LICENSE). Apple files have their own licence and are downloaded
separately from Apple's servers. Dependency notices ship with the binary ZIP.
[Sources and credits](THIRD_PARTY.md). Apple and Microsoft do not endorse this project.
