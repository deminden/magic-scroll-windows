# Sources and dependencies

- **Apple Boot Camp 041-91731** supplies the unchanged proprietary mouse driver,
  version 6.1.7000.0. It is downloaded from `swcdn.apple.com`; neither the driver
  nor an Apple installer is redistributed. Apple's licence applies.
- [sbagirici/apple-magic-mouse-scroll-fix-windows](https://github.com/sbagirici/apple-magic-mouse-scroll-fix-windows)
  and [mo94/magic-devices-windows](https://github.com/mo94/magic-devices-windows)
  describe the lower-filter attachment method. This Rust implementation was
  written independently; their scripts are not copied or executed.
- [Microsoft's windows-rs bindings](https://github.com/microsoft/windows-rs):
  `windows-sys 0.59.0` and `windows-targets 0.52.6`, MIT OR Apache-2.0. The pinned
  version supplies prebuilt import libraries for the supported Windows GNU build.
  APIs include Raw Input, SetupAPI, the Service Control Manager and Windows Trust.
- **sha2 0.10.9**, **serde 1.0.228**, **serde_json 1.0.145** and their transitive
  dependencies. Each package's declared licence and licence files are included in
  the binary ZIP. `Cargo.lock` pins versions and registry checksums.
- [7-Zip](https://www.7-zip.org/): the public-domain `7zr.exe` bootstrap and
  the 25.01 x64 executable/DLL pair are downloaded separately from the official
  site and verified against reviewed SHA-256 hashes before use. The installer
  archive is extracted as data, never installed. No 7-Zip binary is redistributed.

No Linux driver source, Magic Utilities code or custom kernel binary is part of
this project. Project code is MIT; that licence does not relicense Apple's files.
