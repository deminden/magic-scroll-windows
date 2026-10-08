// SPDX-License-Identifier: MIT
//! Small entry point for the physical input test.
//! Driver installation lives in the separate setup executable.
#[cfg(windows)]
mod test_window;

fn main() {
    let interactive = std::env::args_os().len() == 1;
    let result = run();
    if let Err(ref error) = result {
        eprintln!("magic-scroll: {error}");
    }
    // Keep both results and errors visible when opened from File Explorer.
    if interactive {
        println!("Press Enter to close.");
        let mut answer = String::new();
        let _ = std::io::stdin().read_line(&mut answer);
    }
    if result.is_err() {
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let interactive = args.is_empty();
    if interactive || args.as_slice() == ["test-scroll"] {
        #[cfg(windows)]
        test_window::run()?;
        #[cfg(not(windows))]
        return Err("The physical scrolling test requires Windows".into());
    } else if args.len() == 1 && ["--help", "-h", "help"].iter().any(|s| args[0] == *s) {
        println!(
            "Magic Scroll : physical Magic Mouse input test\n\
            Usage: magic-scroll test-scroll\n\n\
            Counts device-identified movement, clicks and wheel events.\n\
            Use magic-scroll-setup to install or remove the Apple driver."
        );
    } else {
        return Err("Invalid arguments. Run magic-scroll --help.".into());
    }
    Ok(())
}
