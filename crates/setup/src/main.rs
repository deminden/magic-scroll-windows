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
    fn answer() -> io::Result<Option<String>> {
        io::stdout().flush()?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line)? == 0 {
            return Ok(None);
        }
        Ok(Some(line.trim().to_owned()))
    }

    enum Flow {
        Home,
        Pause,
        Exit,
    }

    fn finish(had_error: bool) -> Result<(), Box<dyn Error>> {
        if had_error {
            std::process::exit(1);
        }
        Ok(())
    }

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
    let administrator = platform::is_administrator()?;
    let mut had_error = false;
    loop {
        println!("\nMagic Scroll for Windows — experimental USB-C Magic Mouse setup\n");
        platform::print_download_option(driver.try_exists()?)?;
        platform::print_administrator_option(2, "Install", administrator)?;
        platform::print_cyan_option("3. Test physical mouse input")?;
        platform::print_administrator_option(4, "Remove this installation", administrator)?;
        println!("0. Exit\n");
        if !administrator {
            println!("To install or remove, close setup and run it as administrator.");
        }
        print!("Choose a number: ");
        let Some(selection) = answer()? else {
            return finish(had_error);
        };
        let result: Result<Flow, Box<dyn Error>> = (|| {
            match selection.as_str() {
                "0" => return Ok(Flow::Exit),
                "1" => {
                    if !driver.try_exists()? {
                        platform::prepare(&folder)?;
                    }
                    platform::check_download(&driver)?;
                }
                "2" => {
                    let choices = platform::choices(&journal)?;
                    if choices.is_empty() {
                        return Err("No paired USB-C Magic Mouse device nodes found. Pair each mouse with this PC first.".into());
                    }
                    println!(
                        "\nMatching mouse device nodes (device IDs are private; entries may be stale):"
                    );
                    platform::show_choices(&choices)?;
                    println!("Enter a number to select a mouse or install for all eligible mice:");
                    let Some(selection) = answer()? else {
                        return Ok(Flow::Exit);
                    };
                    if selection == "0" {
                        return Ok(Flow::Home);
                    }
                    let selected = platform::select_choices(&choices, &selection)?;
                    platform::plan_selected(&driver, &journal, &selected)?;
                    println!("\nThe actions above change a kernel service and the selected devices' filters.\nWindows will briefly restart devices that are present. Keep the local removal journal.\nType INSTALL to approve these changes, or 0 to return to the main menu:");
                    let Some(approval) = answer()? else {
                        return Ok(Flow::Exit);
                    };
                    if approval == "INSTALL" {
                        platform::install_selected(&driver, &journal, &selected)?;
                    } else {
                        println!("Installation cancelled.");
                        return Ok(Flow::Home);
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
                    let choices = platform::removal_choices(&journal)?;
                    println!("\nMice recorded in this setup folder (device IDs are private):");
                    platform::show_removal_choices(&choices)?;
                    println!("Enter a number to select a mouse or remove all recorded mice:");
                    let Some(selection) = answer()? else {
                        return Ok(Flow::Exit);
                    };
                    if selection == "0" {
                        return Ok(Flow::Home);
                    }
                    let selected = platform::select_removal(&choices, &selection)?;
                    match &selected {
                        platform::RemovalSelection::One(instance) => println!(
                            "\nRemove the attachment for:\n  {instance}\nThe shared driver and service will remain in place."
                        ),
                        platform::RemovalSelection::All => println!(
                            "\nRemove all recorded mouse attachments. Only a driver and service created by this installation will be removed."
                        ),
                    }
                    println!("Type REMOVE to approve, or 0 to return to the main menu:");
                    let Some(approval) = answer()? else {
                        return Ok(Flow::Exit);
                    };
                    if approval == "REMOVE" {
                        platform::remove_selected(&journal, selected)?;
                    } else {
                        println!("Removal cancelled.");
                        return Ok(Flow::Home);
                    }
                }
                _ => return Err("Choose one of the displayed numbers".into()),
            }
            Ok(Flow::Pause)
        })();
        let pause = match result {
            Ok(Flow::Exit) => return finish(had_error),
            Ok(Flow::Home) => false,
            Ok(Flow::Pause) => true,
            Err(error) => {
                eprintln!("Setup stopped: {error}");
                had_error = true;
                true
            }
        };
        if pause {
            println!("\nPress Enter to return to the main menu.");
            if answer()?.is_none() {
                return finish(had_error);
            }
        }
    }
}
fn help() {
    println!("Magic Scroll setup — experimental compatibility test\n\
    Double-click, or run without arguments, for guided setup.\n\
    prepare <new-folder>\n  Download verified portable 7-Zip tools, then fetch and check Apple's driver.\n\
    fetch <new-folder> <7z.exe>\n  Fetch the pinned Boot Camp package over HTTPS from Apple and extract only the mouse driver.\n  Requires the audited 7-Zip 25.01 x64 command-line files. No system installation.\n\
    plan <AppleWirelessMouse.sys>\n  Read-only signature, image, target and conflict checks.\n\
    install <AppleWirelessMouse.sys> <state-file.json> --approve-system-changes\n  \
    Requires an administrator terminal and explicit approval. Installs the unchanged\n  \
    signed driver or reuses a matching existing driver and service, then attaches it\n  \
    to the only present PID 0323 Bluetooth mouse. Use the guided menu to\n  \
    choose individual or multiple mice, including previously paired disconnected devices.\n\
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
