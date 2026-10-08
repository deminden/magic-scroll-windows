// SPDX-License-Identifier: MIT
//! Original Rust setup tool for an unchanged, Microsoft-signed Apple driver.
//! No custom kernel binary, certificate import, security switch, or INF patch.
use std::{error::Error, ffi::OsString, path::Path};
#[cfg(any(windows, test))]
mod pe;
#[cfg(windows)]
mod platform;

// Pin the one driver image actually audited and tested; newer versions need
// their own review instead of silently being accepted.
pub const HASH: &str = "4b4a64722e3c5d1ac1c26c450d2c5af74aa92bf01c3d7b6eaedb81e00fba5c84";
// Preserve Apple's service name because the device filter refers to this name.
pub const SERVICE: &str = "applewirelessmouse";
// Bluetooth uses Apple VID 004C; the USB-C model is PID 0323. The service UUID
// selects the HID transport node, rather than another Bluetooth service.
pub const HARDWARE: &str = "bthenum\\{00001124-0000-1000-8000-00805f9b34fb}_vid&0001004c_pid&0323";

fn main() {
    if let Err(e) = run() {
        eprintln!("Setup stopped: {e}");
        std::process::exit(1);
    }
}
// Destructive commands require an explicit flag as well as Windows admin rights.
// The flag is a user acknowledgement, not a way around the OS access check.
fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let command = parse(&args)?;
    if command == "help" {
        help();
        return Ok(());
    }
    #[cfg(windows)]
    match command {
        "wizard" => return wizard(),
        "prepare" => platform::prepare(Path::new(&args[1]))?,
        "fetch" => platform::fetch(Path::new(&args[1]), Path::new(&args[2]))?,
        "plan" => platform::plan(Path::new(&args[1]))?,
        "install" => platform::install(Path::new(&args[1]), Path::new(&args[2]))?,
        "rollback" => platform::rollback(Path::new(&args[1]))?,
        _ => unreachable!(),
    }
    #[cfg(not(windows))]
    {
        let _ = (args, Path::new(""));
        Err("Setup requires Windows x64".into())
    }
    #[cfg(windows)]
    {
        Ok(())
    }
}
// Parse only commands and switches as text; paths retain native Windows encoding.
fn parse(args: &[OsString]) -> Result<&'static str, Box<dyn Error>> {
    let command = args.first().and_then(|s| s.to_str());
    match (command, args.len()) {
        (None, 0) => Ok("wizard"),
        (Some("help" | "--help" | "-h"), 1) => Ok("help"),
        (Some("prepare"), 2) => Ok("prepare"),
        (Some("fetch"), 3) => Ok("fetch"),
        (Some("plan"), 2) => Ok("plan"),
        (Some("install"), 4) if args[3] == "--approve-system-changes" => Ok("install"),
        (Some("rollback"), 3) if args[2] == "--approve-system-changes" => Ok("rollback"),
        _ => Err("Invalid arguments. Run magic-scroll-setup --help. System changes require --approve-system-changes.".into()),
    }
}

/// Double-click entry point: no shell commands or separate Rust installation.
/// Elevation remains a deliberate Windows action performed by the user.
#[cfg(windows)]
fn wizard() -> Result<(), Box<dyn Error>> {
    use std::io::{self, Write};
    let home = std::env::current_exe()?
        .parent()
        .ok_or("Missing executable folder")?
        .to_path_buf();
    let folder = home.join("driver-download");
    let driver = folder
        .join("apple")
        .join("mouse")
        .join("AppleWirelessMouse.sys");
    let journal = home.join("magic-scroll.state.json");
    println!("Magic Scroll for Windows — experimental USB-C Magic Mouse setup\n\n1. Download and check (no administrator rights needed)\n2. Install (right-click this program > Run as administrator first)\n3. Test physical mouse input\n4. Remove this installation (administrator rights needed)\n0. Exit\n");
    print!("Choose a number: ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    let result: Result<(), Box<dyn Error>> = (|| {
        match answer.trim() {
            "0" => return Ok(()),
            "1" => {
                if !driver.exists() {
                    platform::prepare(&folder)?;
                }
                platform::plan(&driver)?;
            }
            "2" => {
                platform::plan(&driver)?;
                println!("\nThe actions above change a kernel service and this mouse's device filter.\nWindows will briefly restart the mouse. Keep the local removal journal.\nType INSTALL to approve these changes:");
                answer.clear();
                io::stdin().read_line(&mut answer)?;
                if answer.trim() == "INSTALL" {
                    platform::install(&driver, &journal)?;
                } else {
                    println!("Installation cancelled.");
                }
            }
            "3" => {
                let status = std::process::Command::new(home.join("magic-scroll.exe"))
                    .arg("test-scroll")
                    .status()?;
                if !status.success() {
                    return Err("The physical test stopped with an error".into());
                }
            }
            "4" => {
                println!("Type REMOVE to detach this installation, stop its service, and remove its driver:");
                answer.clear();
                io::stdin().read_line(&mut answer)?;
                if answer.trim() == "REMOVE" {
                    platform::rollback(&journal)?;
                } else {
                    println!("Removal cancelled.");
                }
            }
            _ => return Err("Choose one of the displayed numbers".into()),
        }
        Ok(())
    })();
    if let Err(ref error) = result {
        eprintln!("Setup stopped: {error}");
    }
    println!("\nPress Enter to close.");
    answer.clear();
    io::stdin().read_line(&mut answer)?;
    // The message was already shown before the pause; preserve the failure code.
    if result.is_err() {
        std::process::exit(1);
    }
    Ok(())
}
fn help() {
    println!("Magic Scroll setup — experimental compatibility test\n\
    Double-click, or run without arguments, for guided setup.\n\
    prepare <new-folder>\n  Download verified portable 7-Zip tools, then fetch and check Apple's driver.\n\
    fetch <new-folder> <7z.exe>\n  Fetch the pinned Boot Camp package over HTTPS from Apple and extract only the mouse driver.\n  Requires the audited 7-Zip 25.01 x64 command-line files. No system installation.\n\
    plan <AppleWirelessMouse.sys>\n  Read-only signature, image, target and conflict checks.\n\
    install <AppleWirelessMouse.sys> <new-state-file.json> --approve-system-changes\n  \
    Requires an administrator terminal and explicit approval. Copies the unchanged signed\n  \
    driver, creates its kernel service, tests whether Windows permits it to load, then\n  \
    attaches it only to the connected PID 0323 Bluetooth mouse and restarts that device.\n\
    rollback <state-file.json> --approve-system-changes\n  Removes only this installation, after validating the saved state and current files.\n\n\
    This tool does not elevate itself, modify security, or guarantee USB-C compatibility.");
}

/// Accept only this model's full hardware prefix plus one nonempty instance suffix.
/// A loose substring match could attach a kernel filter to the wrong device.
pub fn validate_instance(instance: &str) -> bool {
    instance
        .rsplit_once('\\')
        .is_some_and(|(hardware, suffix)| {
            hardware.eq_ignore_ascii_case(HARDWARE)
                && !suffix.is_empty()
                && instance.len() <= 1024
                && suffix.is_ascii()
                && !suffix
                    .bytes()
                    .any(|b| b.is_ascii_control() || b == b'\\' || b == b'/')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_missing_approval_and_unknown_arguments() {
        for invalid in [
            vec!["install", "driver", "journal"],
            vec!["rollback", "journal"],
            vec!["install", "driver", "journal", "--approve"],
            vec!["typo"],
            vec!["plan", "driver", "extra"],
        ] {
            assert!(parse(&invalid.iter().map(OsString::from).collect::<Vec<_>>()).is_err());
        }
        assert_eq!(parse(&[]).unwrap(), "wizard");
        assert_eq!(parse(&["--help".into()]).unwrap(), "help");
        assert_eq!(
            parse(&[
                "install".into(),
                "driver".into(),
                "journal".into(),
                "--approve-system-changes".into()
            ])
            .unwrap(),
            "install"
        );
    }
    #[test]
    fn restricts_to_exact_mouse_node() {
        assert!(validate_instance(&format!(
            "{}\\8&ABCD&0&EXAMPLE_C00000000",
            HARDWARE.to_uppercase()
        )));
        for wrong in [
            HARDWARE.to_owned(),
            format!("{HARDWARE}\\"),
            format!("{HARDWARE}extra\\x"),
            format!("{HARDWARE}\\x\\y"),
            format!("{}\\x", HARDWARE.replace("0323", "0324")),
            format!("{}\\x", HARDWARE.replace("004c", "1234")),
            format!("{HARDWARE}\\x\n"),
            format!("{HARDWARE}\\é"),
        ] {
            assert!(!validate_instance(&wrong), "{wrong}");
        }
    }
}
