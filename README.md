# Magic Scroll for Windows

**USB-C Magic Mouse scrolling on Windows. Download, extract, and run.**

Magic Scroll is a small Rust installer that downloads, verifies, and attaches
Apple's signed driver to your paired Magic Mouse. Apple's driver handles the
touch scrolling; Magic Scroll takes care of setup.

- **Ready-to-run Windows binaries.** Download the ZIP and open setup. No Rust,
  compiler, terminal commands, or separate 7-Zip installation needed.
- **Automatic driver attachment.** Setup finds the paired mouse and connects it
  to Apple's driver, including the device ID missing from Apple's installer.
- **Verified downloads.** Files come from Apple and 7-zip.org, with hash and
  Windows driver-signature checks built into setup.
- **Free and MIT licensed.** No subscription.
- **No background app.** Once installed, Apple's driver handles scrolling.
- **Windows protection settings stay intact.** Setup preserves Memory Integrity,
  Secure Boot, and driver-signing settings.
- **Installation and removal in one program.** Both are available in the setup menu.

## [↓ Download for Windows (x64)](https://github.com/deminden/magic-scroll-windows/releases/latest/download/magic-scroll-windows-x64.zip)

[Latest release](https://github.com/deminden/magic-scroll-windows/releases/latest)
· [Test results](docs/VALIDATION.md) · [MIT licence](LICENSE)

Vertical touch scrolling and Bluetooth reconnection were confirmed on Windows 11
with Memory Integrity enabled. [Configuration and results](docs/VALIDATION.md).

## Start here

You need **Windows x64**, the **USB-C Magic Mouse paired over Bluetooth**, internet
access and about **2.5 GB** of free space. ARM64 and older Magic Mouse models are
not supported by this installer.

1. [Download the Windows ZIP](https://github.com/deminden/magic-scroll-windows/releases/latest/download/magic-scroll-windows-x64.zip) and extract it.
2. Double-click **`magic-scroll-setup.exe`** and choose **1: Download and check**.
   Setup downloads and verifies the files before making any system changes.
3. Read the displayed plan. Close setup, right-click **`magic-scroll-setup.exe`**,
   choose **Run as administrator**, then **2: Install**. Type **INSTALL** only
   when you're ready to install.
4. Slide your finger up and down in a page or document. Check movement and clicks.
   Double-click **`magic-scroll.exe`** to see movement, click, and scroll counts.

The mouse may briefly disconnect while setup restarts it. Setup checks that
Windows can load the driver before attaching it to the mouse.

Keep the setup folder after installation. You'll use it if you ever want to
remove the fix.

## Confirmed results

Vertical touch scrolling was confirmed in normal apps on **Windows 11 Home x64,
build 26300**, using a USB-C Magic Mouse. Scrolling also worked after switching
the mouse off for two minutes and back on. **Memory Integrity stayed enabled.**

| Check | Result |
|---|---|
| Vertical touch scrolling in ordinary content | Confirmed working |
| Horizontal wheel input | Recorded in both physical tests |
| Pointer movement and left/right clicks | Recorded in the first test |
| Bluetooth reconnect after two minutes off | Confirmed working |

The test program shows input from the Magic Mouse in its title bar. Close the
window to see the final counts. You can keep it open while scrolling in another
app. [Detailed results](docs/VALIDATION.md).

## How it works

The inspected Apple **6.1.7000.0** installation file lists PIDs `030D`, `0310` and
`0269`; **PID `0323` is missing**. Magic Scroll handles the device attachment
directly, using the unchanged signed driver. The setup menu brings downloading,
verification, installation, testing, and removal together.

The installer is written in Rust and uses an established driver-attachment
method. [Sources and credits](THIRD_PARTY.md).

Reddit users also reported that ordinary Boot Camp installation did not enable
scrolling on the USB-C model: [December 2024](https://www.reddit.com/r/applehelp/comments/1hmre4r/scroll_on_new_magic_mouse_not_working/)
and [June 2026](https://www.reddit.com/r/applehelp/comments/1tw4b9r/apple_mouse_3_usb_c_a3204_doesnt_scroll_in/).

## Remove it

Right-click **`magic-scroll-setup.exe` → Run as administrator**, choose **4:
Remove**, then type **REMOVE**. Setup uses the saved installation details to
detach the driver, stop its service, and remove its file. Other filter entries
are left in place.

## Troubleshooting

| Message or symptom | Next step |
|---|---|
| Mouse not found | Connect the USB-C model over Bluetooth; this installer targets PID `0323`. |
| Hash or signature mismatch | The file differs from the supported version. Include the exact error when reporting it. |
| Download folder already exists | Check the previous download, or choose a new folder with the command-line option below. |
| Existing driver, service or filter | Another installation is already present. Setup leaves it in place. |
| Administrator access denied | Installation/removal need **Run as administrator**; downloading and testing do not. |
| Windows refuses the driver | Check the Windows error and setup's cleanup result. |
| Test shows zero counts | Check scrolling in an app and confirm the USB-C mouse is connected. |

When reporting a problem, include your Windows build, mouse model, and exact error.

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

You can also use the command line:

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
See the [validation checklist](docs/TESTING.md) and [release instructions](docs/RELEASING.md).

## Licence and credits

Project source is [MIT licensed](LICENSE). Apple files have their own licence and
are downloaded separately from Apple's servers. Dependency notices ship with
the binary ZIP. [Sources and credits](THIRD_PARTY.md).
