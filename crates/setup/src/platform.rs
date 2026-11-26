// SPDX-License-Identifier: MIT
//! Windows operations behind the setup CLI: audit, fetch, attach and undo.
//! Plan and installation share the same driver and device checks.
use super::{pe, validate_instance, HASH, SERVICE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    ffi::c_void,
    fs::{File, OpenOptions},
    io::{self, IsTerminal, Read, Write},
    mem::{size_of, zeroed},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::{
    core::GUID,
    Win32::{
        Devices::DeviceAndDriverInstallation::{
            SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
            SetupDiGetDeviceInstanceIdW, SetupDiGetDeviceRegistryPropertyW,
            SetupDiSetDeviceRegistryPropertyW, DIGCF_ALLCLASSES, DIGCF_PRESENT, HDEVINFO,
            SPDRP_LOWERFILTERS, SP_DEVINFO_DATA as DevInfo,
        },
        Foundation::{FreeLibrary, HANDLE as Handle},
        Security::{
            CheckTokenMembership, CreateWellKnownSid, WinBuiltinAdministratorsSid, WinTrust::*,
            SECURITY_MAX_SID_SIZE,
        },
        System::{
            Console::{
                GetConsoleScreenBufferInfo, SetConsoleTextAttribute, CONSOLE_SCREEN_BUFFER_INFO,
                FOREGROUND_BLUE, FOREGROUND_GREEN, FOREGROUND_INTENSITY, FOREGROUND_RED,
            },
            LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32},
            Services::{
                CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
                OpenServiceW, QueryServiceConfigW, QueryServiceStatus, StartServiceW,
                QUERY_SERVICE_CONFIGW as ServiceConfig, SC_MANAGER_CONNECT,
                SC_MANAGER_CREATE_SERVICE, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                SERVICE_KERNEL_DRIVER, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
                SERVICE_START, SERVICE_STATUS as ServiceStatus, SERVICE_STOP, SERVICE_STOPPED,
            },
            SystemInformation::GetSystemDirectoryW,
        },
    },
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn download_option(downloaded: bool) -> (String, u16) {
    let (status, foreground) = if downloaded {
        ("downloaded", FOREGROUND_GREEN)
    } else {
        ("not downloaded", FOREGROUND_RED)
    };
    (
        format!("1. Download and check (no administrator rights needed) [{status}]"),
        foreground,
    )
}

pub fn print_download_option(downloaded: bool) -> Result<()> {
    let (text, foreground) = download_option(downloaded);
    print_colored_line(&text, foreground)
}

pub fn is_administrator() -> Result<bool> {
    let mut sid = [0u32; SECURITY_MAX_SID_SIZE as usize / size_of::<u32>()];
    let mut size = SECURITY_MAX_SID_SIZE;
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            null_mut(),
            sid.as_mut_ptr().cast(),
            &mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let mut member = 0;
    if unsafe { CheckTokenMembership(null_mut(), sid.as_mut_ptr().cast(), &mut member) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(member != 0)
}

fn administrator_option(number: u8, label: &str, administrator: bool) -> (String, u16) {
    let (status, color) = if administrator {
        ("running as administrator", FOREGROUND_GREEN)
    } else {
        ("not running as administrator", FOREGROUND_RED)
    };
    (format!("{number}. {label} [{status}]"), color)
}

pub fn print_administrator_option(number: u8, label: &str, administrator: bool) -> Result<()> {
    let (text, color) = administrator_option(number, label, administrator);
    print_colored_line(&text, color)
}

pub fn print_cyan_option(text: &str) -> Result<()> {
    print_colored_line(text, FOREGROUND_GREEN | FOREGROUND_BLUE)
}

fn print_colored_line(text: &str, foreground: u16) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if !stdout.is_terminal() {
        writeln!(output, "{text}")?;
        return Ok(());
    }

    let handle = stdout.as_raw_handle() as Handle;
    let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { zeroed() };
    if unsafe { GetConsoleScreenBufferInfo(handle, &mut info) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let color = (info.wAttributes
        & !(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY))
        | foreground
        | FOREGROUND_INTENSITY;
    if unsafe { SetConsoleTextAttribute(handle, color) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let result = writeln!(output, "{text}").and_then(|()| output.flush());
    let restored = unsafe { SetConsoleTextAttribute(handle, info.wAttributes) };
    if restored == 0 {
        return Err(io::Error::last_os_error().into());
    }
    result?;
    Ok(())
}

struct TrustLibrary {
    module: Handle,
    verify: unsafe extern "system" fn(Handle, *mut GUID, *mut c_void) -> i32,
}
impl Drop for TrustLibrary {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.module);
        }
    }
}
impl TrustLibrary {
    fn load() -> Result<Self> {
        let name = wide("wintrust.dll");
        let module =
            unsafe { LoadLibraryExW(name.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if module.is_null() {
            return Err(io::Error::last_os_error().into());
        }
        let Some(proc) = (unsafe { GetProcAddress(module, c"WinVerifyTrust".as_ptr().cast()) })
        else {
            let error = io::Error::last_os_error();
            unsafe {
                FreeLibrary(module);
            }
            return Err(error.into());
        };
        // SAFETY: only the named Windows System32 trust-provider export is loaded.
        Ok(Self {
            module,
            verify: unsafe {
                std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    unsafe extern "system" fn(Handle, *mut GUID, *mut c_void) -> i32,
                >(proc)
            },
        })
    }
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
fn fail(message: impl Into<String>) -> Box<dyn Error> {
    message.into().into()
}
// SCM handles need CloseServiceHandle rather than the general CloseHandle API.
struct ScHandle(Handle);
impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}
fn manager(access: u32) -> Result<ScHandle> {
    let h = unsafe { OpenSCManagerW(null(), null(), access) };
    if h.is_null() {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(ScHandle(h))
    }
}
fn service(manager: &ScHandle, access: u32) -> Result<Option<ScHandle>> {
    let name = wide(SERVICE);
    let h = unsafe { OpenServiceW(manager.0, name.as_ptr(), access) };
    if h.is_null() {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(1060) {
            Ok(None)
        } else {
            Err(e.into())
        }
    } else {
        Ok(Some(ScHandle(h)))
    }
}
fn system_dir() -> Result<PathBuf> {
    let mut b = [0u16; 32768];
    let n = unsafe { GetSystemDirectoryW(b.as_mut_ptr(), b.len() as u32) } as usize;
    if n == 0 || n >= b.len() {
        return Err(io::Error::last_os_error().into());
    }
    Ok(PathBuf::from(String::from_utf16(&b[..n])?))
}
fn destination() -> Result<PathBuf> {
    Ok(system_dir()?.join("drivers").join("applewirelessmouse.sys"))
}

/// Evaluate embedded signatures using Windows kernel-driver policy.
/// Passing this check does not guarantee that Windows will load the driver.
fn trust(file: &File, path: &Path) -> Result<u32> {
    let library = TrustLibrary::load()?;
    let path = wide(&path.to_string_lossy());
    let mut info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: file.as_raw_handle(),
        pgKnownSubject: null_mut(),
    };
    let mut action = DRIVER_ACTION_VERIFY;
    let mut sig: WINTRUST_SIGNATURE_SETTINGS = unsafe { zeroed() };
    sig.cbStruct = size_of::<WINTRUST_SIGNATURE_SETTINGS>() as u32;
    sig.dwFlags = WSS_GET_SECONDARY_SIG_COUNT;
    let mut data: WINTRUST_DATA = unsafe { zeroed() };
    data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    data.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous.pFile = &mut info;
    data.pSignatureSettings = &mut sig;
    // Every VERIFY state must be closed, including rejected signatures.
    let mut verify = |data: &mut WINTRUST_DATA| {
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.hWVTStateData = null_mut();
        let result = unsafe {
            (library.verify)(
                (-1isize) as Handle,
                &mut action,
                (data as *mut WINTRUST_DATA).cast(),
            )
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe {
            (library.verify)(
                (-1isize) as Handle,
                &mut action,
                (data as *mut WINTRUST_DATA).cast(),
            );
        }
        result
    };
    // An Apple package can include an untrusted primary test certificate and a
    // valid secondary WHQL signature. Windows must accept a specific signature.
    verify(&mut data);
    if sig.cSecondarySigs > 16 {
        return Err(fail("Too many signature records"));
    }
    for index in 0..=sig.cSecondarySigs {
        sig.dwIndex = index;
        sig.dwFlags = WSS_VERIFY_SPECIFIC;
        data.pSignatureSettings = &mut sig;
        if verify(&mut data) == 0 {
            return Ok(index);
        }
    }
    Err(fail("Windows kernel signature verification refused every signature. No trust-store change will be attempted."))
}

// Retaining this file keeps its share-mode lock alive through installation.
struct Audited {
    bytes: Vec<u8>,
    _locked: File,
    signature: u32,
}
/// Check the exact bytes, architecture and Windows trust before kernel loading.
fn audit(path: &Path) -> Result<Audited> {
    if !cfg!(target_arch = "x86_64") {
        return Err(fail("Only Windows x64 is supported"));
    }
    let path = std::fs::canonicalize(path)?;
    // Deny concurrent writes/deletes while both hashing and signature verification.
    let mut file = OpenOptions::new().read(true).share_mode(1).open(&path)?;
    if file.metadata()?.len() != 69008 {
        return Err(fail(
            "Unsupported driver size; only the audited Apple 6.1.7000.0 image is accepted",
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let hash = format!("{:x}", Sha256::digest(&bytes));
    if hash != HASH {
        return Err(fail(format!(
            "Unsupported or modified driver SHA-256: {hash}"
        )));
    }
    let image = pe::inspect(&bytes).map_err(fail)?;
    if !image.nx || !image.page_aligned || image.writable_executable {
        return Err(fail(
            "Driver fails basic executable-memory compatibility checks",
        ));
    }
    let signature = trust(&file, &path)?;
    Ok(Audited {
        bytes,
        _locked: file,
        signature,
    })
}

fn file_hash(path: &Path) -> Result<String> {
    let mut file = OpenOptions::new().read(true).share_mode(1).open(path)?;
    let mut hash = Sha256::new();
    let mut bytes = [0; 65536];
    loop {
        let n = file.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

// Return a read lock so the bytes verified here cannot change before use.
fn download(path: &Path, url: &str, hash: &str) -> Result<File> {
    let status = std::process::Command::new(system_dir()?.join("curl.exe"))
        .args([
            "--fail",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--location",
            "--connect-timeout",
            "30",
            "--max-time",
            "1800",
            "--output",
        ])
        .arg(path)
        .arg(url)
        .status()?;
    if !status.success() {
        return Err(fail(
            "Download failed; partial files were retained for inspection",
        ));
    }
    let locked = OpenOptions::new().read(true).share_mode(1).open(path)?;
    if file_hash(path)? != hash {
        return Err(fail(
            "Download integrity mismatch; execution and extraction refused",
        ));
    }
    Ok(locked)
}

/// Bootstrap an audited portable extractor without installing 7-Zip system-wide.
/// The setup archive is opened as data; its installer is never executed.
pub fn prepare(folder: &Path) -> Result<()> {
    std::fs::create_dir(folder)?;
    let folder = std::fs::canonicalize(folder)?;
    let bootstrap = folder.join("7zr.exe");
    let archive = folder.join("7z-setup.exe");
    println!("Downloading verified portable 7-Zip tools from 7-zip.org. No system installation.");
    let _bootstrap_lock = download(
        &bootstrap,
        "https://www.7-zip.org/a/7zr.exe",
        "256feca8e274e5da655e2a284fabafd9f554365eb164862089dacd4e8276d282",
    )?;
    let _archive_lock = download(
        &archive,
        "https://www.7-zip.org/a/7z2501-x64.exe",
        "78afa2a1c773caf3cf7edf62f857d2a8a5da55fb0fff5da416074c0d28b2b55f",
    )?;
    let tools = folder.join("tools");
    std::fs::create_dir(&tools)?;
    let status = std::process::Command::new(&bootstrap)
        .arg("e")
        .arg(&archive)
        .args(["7z.exe", "7z.dll", "-y"])
        .arg(format!("-o{}", tools.display()))
        .status()?;
    if !status.success() {
        return Err(fail("Portable extractor preparation failed"));
    }
    fetch(&folder.join("apple"), &tools.join("7z.exe"))
}

/// Download and extract data without executing an Apple package or installer.
/// A new folder prevents mixing verified files with leftovers from an older run.
pub fn fetch(folder: &Path, extractor: &Path) -> Result<()> {
    let extractor = std::fs::canonicalize(extractor)?;
    // Keep the verified executable and DLL immutable until extraction finishes.
    let _extractor_lock = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&extractor)?;
    let _dll_lock = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(extractor.with_file_name("7z.dll"))?;
    if file_hash(&extractor)? != "4cd7d776c686427226a151789d2d61f0b2ed2c392148cc4e69c0238362fafecf"
        || file_hash(&extractor.with_file_name("7z.dll"))?
            != "5bd20fb38499d95c39594f41d4781b6181b3304b7f1f4d06b0182f514e7eaa74"
    {
        return Err(fail("Extractor hash mismatch. This build supports only the audited official 7-Zip 25.01 x64 7z.exe and 7z.dll pair."));
    }
    std::fs::create_dir(folder)?;
    let folder = std::fs::canonicalize(folder)?;
    let package = folder.join("BootCampESD.pkg");
    let url="https://swcdn.apple.com/content/downloads/23/15/041-91731-A_LBI7Q8UWOG/juk1ng0hm623gxh3jv4qxt190ga1h5p0lw/BootCampESD.pkg";
    println!("Downloading 548 MB from Apple's HTTPS server into a new local folder. Apple's software licence applies.");
    let _package_lock = download(
        &package,
        url,
        "d655289ac44a00d3abc20d01134acf7b38aad2ad98bb3c46c9da4c12e1f28d85",
    )?;
    let extract = |archive: &Path, output: &Path, extra: &[&str]| -> Result<()> {
        std::fs::create_dir(output)?;
        let output_arg = format!("-o{}", output.display());
        let status = std::process::Command::new(&extractor)
            .arg("e")
            .arg(archive)
            .args(extra)
            .arg(output_arg)
            .arg("-y")
            .status()?;
        if !status.success() {
            return Err(fail(
                "Archive extraction failed; files were retained and no installer was run",
            ));
        }
        Ok(())
    };
    // Boot Camp nests XAR -> compressed payload -> archive -> DMG. Force XAR
    // here; autodetection can otherwise skip the named outer Payload layer.
    let xar = folder.join("xar");
    extract(&package, &xar, &["-tXar", "Payload"])?;
    let payload = folder.join("payload");
    extract(&xar.join("Payload"), &payload, &[])?;
    let dmg = folder.join("dmg");
    extract(
        &payload.join("Payload~"),
        &dmg,
        &["-ir!*WindowsSupport.dmg"],
    )?;
    let mouse = folder.join("mouse");
    extract(
        &dmg.join("WindowsSupport.dmg"),
        &mouse,
        &["-ir!*AppleWirelessMouse*"],
    )?;
    audit(&mouse.join("AppleWirelessMouse.sys"))?;
    println!("Verified unchanged Apple driver ready at {}. No installer, service, or registry change was run.",mouse.join("AppleWirelessMouse.sys").display());
    Ok(())
}

struct DeviceSet(HDEVINFO);
impl Drop for DeviceSet {
    fn drop(&mut self) {
        unsafe {
            SetupDiDestroyDeviceInfoList(self.0);
        }
    }
}
struct Mouse {
    set: DeviceSet,
    info: DevInfo,
    instance: String,
}
fn device_set(present_only: bool) -> Result<DeviceSet> {
    let set = DeviceSet(unsafe {
        SetupDiGetClassDevsW(
            null(),
            null(),
            null_mut(),
            DIGCF_ALLCLASSES | if present_only { DIGCF_PRESENT } else { 0 },
        )
    });
    if set.0 as isize == -1 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(set)
}

fn enumerate(set: &DeviceSet) -> Result<Vec<(DevInfo, String)>> {
    let mut found = Vec::new();
    for index in 0.. {
        let mut info: DevInfo = unsafe { zeroed() };
        info.cbSize = size_of::<DevInfo>() as u32;
        if unsafe { SetupDiEnumDeviceInfo(set.0, index, &mut info) } == 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(259) {
                break;
            }
            return Err(e.into());
        }
        let mut id = [0u16; 4096];
        let mut needed = 0;
        if unsafe {
            SetupDiGetDeviceInstanceIdW(set.0, &info, id.as_mut_ptr(), id.len() as u32, &mut needed)
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        if needed == 0 || needed as usize > id.len() {
            return Err(fail("Invalid device ID size"));
        }
        let instance = String::from_utf16(&id[..needed as usize - 1])?;
        if !validate_instance(&instance) {
            continue;
        }
        found.push((info, instance));
    }
    Ok(found)
}

fn mouse(instance: &str) -> Result<Mouse> {
    let set = device_set(false)?;
    let mut matches = enumerate(&set)?
        .into_iter()
        .filter(|(_, id)| id.eq_ignore_ascii_case(instance));
    let (info, instance) = matches
        .next()
        .ok_or_else(|| fail("The selected mouse device node was not found"))?;
    if matches.next().is_some() {
        return Err(fail("Duplicate mouse device instance ID"));
    }
    Ok(Mouse {
        set,
        info,
        instance,
    })
}

#[derive(Clone, Debug)]
pub struct MouseChoice {
    instance: String,
    present: bool,
    installed: bool,
    tracked: bool,
    attached: bool,
}

fn present_instances() -> Result<Vec<String>> {
    Ok(enumerate(&device_set(true)?)?
        .into_iter()
        .map(|(_, instance)| instance)
        .collect())
}

fn contains_instance(instances: &[String], instance: &str) -> bool {
    instances.iter().any(|id| id.eq_ignore_ascii_case(instance))
}

pub fn choices(journal: &Path) -> Result<Vec<MouseChoice>> {
    let state = if journal.try_exists()? {
        Some(load_state(journal)?)
    } else {
        None
    };
    let present = present_instances()?;
    let set = device_set(false)?;
    let mut choices = Vec::new();
    for (_, instance) in enumerate(&set)? {
        let tracked = state.as_ref().is_some_and(|state| {
            state.devices.iter().any(|device| {
                device.filter_added && device.instance.eq_ignore_ascii_case(&instance)
            })
        });
        let attached = filters(&mouse(&instance)?)?
            .iter()
            .any(|entry| entry.eq_ignore_ascii_case(SERVICE));
        choices.push(MouseChoice {
            present: contains_instance(&present, &instance),
            installed: attached || tracked,
            tracked,
            attached,
            instance,
        });
    }
    choices.sort_by(|a, b| {
        a.instance
            .to_ascii_lowercase()
            .cmp(&b.instance.to_ascii_lowercase())
    });
    Ok(choices)
}

fn choice_option(index: usize, choice: &MouseChoice) -> (String, u16) {
    let status = match (choice.tracked, choice.attached) {
        (true, true) => "attached; tracked here",
        (true, false) => "not attached; tracked here; filter missing",
        (false, true) => "already attached; not tracked here",
        (false, false) => "not attached",
    };
    (
        format!(
            "{}. {} [{status}]\n   {}",
            index + 1,
            if choice.present {
                "Present in Windows"
            } else {
                "Not currently present in Windows"
            },
            choice.instance
        ),
        if choice.attached {
            FOREGROUND_GREEN
        } else {
            FOREGROUND_RED
        },
    )
}

pub fn show_choices(choices: &[MouseChoice]) -> Result<()> {
    for (index, choice) in choices.iter().enumerate() {
        let (text, foreground) = choice_option(index, choice);
        print_colored_line(&text, foreground)?;
    }
    print_cyan_option(&format!(
        "{}. Install for all eligible mice (already attached or tracked entries are skipped)",
        choices.len() + 1
    ))?;
    println!("0. Return to main menu");
    Ok(())
}

pub fn select_choices(choices: &[MouseChoice], answer: &str) -> Result<Vec<String>> {
    let all = answer.eq_ignore_ascii_case("all")
        || answer.parse::<usize>().ok() == Some(choices.len() + 1);
    let selected: Vec<_> = if all {
        choices.iter().filter(|choice| !choice.installed).collect()
    } else {
        let index: usize = answer
            .parse()
            .map_err(|_| fail("Choose a displayed number or ALL"))?;
        let choice = index
            .checked_sub(1)
            .and_then(|index| choices.get(index))
            .ok_or("Choose a displayed number or ALL")?;
        if choice.installed {
            return Err(fail("That mouse is already installed"));
        }
        vec![choice]
    };
    if selected.is_empty() {
        return Err(fail("No new mice available to install"));
    }
    Ok(selected
        .into_iter()
        .map(|choice| choice.instance.clone())
        .collect())
}

pub struct RemovalChoice {
    instance: String,
    present: bool,
    attached: Option<bool>,
}

pub enum RemovalSelection {
    One(String),
    All,
}

pub fn removal_choices(journal: &Path) -> Result<Vec<RemovalChoice>> {
    if !journal.try_exists()? {
        return Err(fail("No removal journal was found in this setup folder. Use the folder that recorded the installation."));
    }
    let state = load_state(journal)?;
    let present = present_instances()?;
    let instances: Vec<_> = enumerate(&device_set(false)?)?
        .into_iter()
        .map(|(_, instance)| instance)
        .collect();
    let mut choices = Vec::new();
    for device in state.devices.iter().filter(|device| device.filter_added) {
        let attached = if contains_instance(&instances, &device.instance) {
            Some(
                filters(&mouse(&device.instance)?)?
                    .iter()
                    .any(|entry| entry.eq_ignore_ascii_case(SERVICE)),
            )
        } else {
            None
        };
        choices.push(RemovalChoice {
            present: contains_instance(&present, &device.instance),
            attached,
            instance: device.instance.clone(),
        });
    }
    Ok(choices)
}

pub fn show_removal_choices(choices: &[RemovalChoice]) -> Result<()> {
    for (index, choice) in choices.iter().enumerate() {
        let (status, color) = match choice.attached {
            Some(true) => ("attached", FOREGROUND_GREEN),
            Some(false) => ("filter missing; retry removal", FOREGROUND_RED),
            None => (
                "device node missing; removal requires the node",
                FOREGROUND_RED,
            ),
        };
        print_colored_line(
            &format!(
                "{}. {} [{status}]\n   {}",
                index + 1,
                if choice.present {
                    "Present in Windows"
                } else {
                    "Not currently present in Windows"
                },
                choice.instance
            ),
            color,
        )?;
    }
    print_cyan_option(&format!(
        "{}. Remove all recorded mice and owned shared components",
        choices.len() + 1
    ))?;
    println!("0. Return to main menu");
    Ok(())
}

pub fn select_removal(choices: &[RemovalChoice], answer: &str) -> Result<RemovalSelection> {
    if answer.eq_ignore_ascii_case("all") || answer.parse::<usize>().ok() == Some(choices.len() + 1)
    {
        return Ok(RemovalSelection::All);
    }
    let index: usize = answer
        .parse()
        .map_err(|_| fail("Choose a displayed number or ALL"))?;
    let choice = index
        .checked_sub(1)
        .and_then(|index| choices.get(index))
        .ok_or("Choose a displayed number or ALL")?;
    Ok(RemovalSelection::One(choice.instance.clone()))
}

fn restart_if_present(mouse: &Mouse) -> Result<()> {
    if contains_instance(&present_instances()?, &mouse.instance) {
        restart(mouse)?;
    } else {
        println!(
            "Device is not currently present; its filter change takes effect when it reconnects."
        );
    }
    Ok(())
}
// REG_MULTI_SZ is a list of UTF-16 strings ending in a double NUL. Validate
// that termination before editing, so malformed properties are not overwritten.
fn decode_multi(bytes: &[u8]) -> Result<Vec<String>> {
    if !bytes.len().is_multiple_of(2) {
        return Err(fail("Invalid LowerFilters value length"));
    }
    let words: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    if words.len() < 2 || words[words.len() - 2..] != [0, 0] {
        return Err(fail("Unterminated LowerFilters value"));
    }
    let mut values = Vec::new();
    let mut start = 0;
    for (i, &c) in words.iter().enumerate() {
        if c == 0 {
            if i == start {
                if words[i..].iter().any(|&v| v != 0) {
                    return Err(fail("Data after LowerFilters terminator"));
                }
                break;
            }
            values.push(String::from_utf16(&words[start..i])?);
            start = i + 1;
        }
    }
    Ok(values)
}
fn encode_multi(values: &[String]) -> Result<Vec<u8>> {
    let mut words = Vec::new();
    for value in values {
        if value.is_empty() || value.contains('\0') {
            return Err(fail("Invalid filter name"));
        }
        words.extend(value.encode_utf16());
        words.push(0);
    }
    words.push(0);
    if words.len() == 1 {
        words.push(0);
    }
    Ok(words.into_iter().flat_map(u16::to_le_bytes).collect())
}
fn filters(mouse: &Mouse) -> Result<Vec<String>> {
    let mut kind = 0;
    let mut needed = 0;
    let ok = unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            mouse.set.0,
            &mouse.info,
            SPDRP_LOWERFILTERS,
            &mut kind,
            null_mut(),
            0,
            &mut needed,
        )
    };
    if ok == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(13) {
            return Ok(Vec::new());
        }
        if error.raw_os_error() != Some(122) {
            return Err(error.into());
        }
    }
    if needed > 65536 {
        return Err(fail("Oversized LowerFilters value"));
    }
    let mut bytes = vec![0; needed as usize];
    if unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            mouse.set.0,
            &mouse.info,
            SPDRP_LOWERFILTERS,
            &mut kind,
            bytes.as_mut_ptr(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    if kind != 7 {
        return Err(fail("LowerFilters is not REG_MULTI_SZ"));
    }
    if needed as usize > bytes.len() {
        return Err(fail("LowerFilters changed size during query"));
    }
    decode_multi(&bytes[..needed as usize])
}
fn set_filters(mouse: &Mouse, values: &[String]) -> Result<()> {
    let bytes = encode_multi(values)?;
    // NULL/0 deletes this property when the original value did not exist.
    let (ptr, len) = if values.is_empty() {
        (null(), 0)
    } else {
        (bytes.as_ptr(), bytes.len() as u32)
    };
    let mut info = mouse.info;
    if unsafe {
        SetupDiSetDeviceRegistryPropertyW(mouse.set.0, &mut info, SPDRP_LOWERFILTERS, ptr, len)
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
struct Preflight {
    audited: Audited,
    mice: Vec<Mouse>,
    state: Option<State>,
    reuse: bool,
    external: bool,
}

fn reuse_existing(file_exists: bool, service_exists: bool, has_journal: bool) -> Result<bool> {
    match (file_exists, service_exists, has_journal) {
        (true, true, _) => Ok(true),
        (false, false, false) => Ok(false),
        _ => Err(fail("The existing driver file and service are incomplete or inconsistent; refusing to alter them.")),
    }
}

fn check_journal_for_install(state: &State) -> Result<()> {
    if !state.external_shared && (!state.file_created || !state.service_created) {
        return Err(fail("The existing journal does not describe a complete installation. Remove or recover it before adding mice."));
    }
    if state.devices.iter().any(|device| !device.filter_added) {
        return Err(fail("The existing journal records an incomplete device attachment. Remove or recover it before adding mice."));
    }
    Ok(())
}

fn preflight(path: &Path, journal: &Path, selected: &[String]) -> Result<Preflight> {
    if selected.is_empty() {
        return Err(fail("No new mice selected"));
    }
    if journal.with_extension("pending.json").try_exists()? {
        return Err(fail("A pending journal exists. Preserve it and resolve the previous incomplete operation before continuing."));
    }
    let manager = manager(SC_MANAGER_CONNECT)?;
    let destination = destination()?;
    let state = if journal.try_exists()? {
        let state = load_state(journal)?;
        check_journal_for_install(&state)?;
        for device in state.devices.iter().filter(|device| device.filter_added) {
            let current = filters(&mouse(&device.instance)?)?;
            if !current
                .iter()
                .any(|entry| entry.eq_ignore_ascii_case(SERVICE))
            {
                return Err(fail("An installed mouse no longer has the recorded filter. Remove or recover the installation first."));
            }
        }
        Some(state)
    } else {
        None
    };
    let existing_file = destination.try_exists()?;
    let existing_service = service(&manager, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)?;
    let reuse = reuse_existing(existing_file, existing_service.is_some(), state.is_some())?;
    let external = state.as_ref().map_or(reuse, |state| state.external_shared);
    let audited = if reuse {
        let service = existing_service.as_ref().ok_or("Driver service missing")?;
        if !service_binary_matches(&service_binary(service)?, &destination) {
            return Err(fail(
                "The existing service points to a different driver; refusing to reuse it",
            ));
        }
        let current = status(service)?.dwCurrentState;
        if current != SERVICE_RUNNING && current != SERVICE_STOPPED {
            return Err(fail(
                "The driver service is changing state. Try again when it has stopped or started.",
            ));
        }
        audit(&destination)?
    } else {
        audit(path)?
    };
    let mut mice = Vec::new();
    for (index, instance) in selected.iter().enumerate() {
        if !validate_instance(instance) || contains_instance(&selected[..index], instance) {
            return Err(fail("Invalid or duplicate selected mouse"));
        }
        if state.as_ref().is_some_and(|state| {
            state
                .devices
                .iter()
                .any(|device| device.instance.eq_ignore_ascii_case(instance))
        }) {
            return Err(fail("A selected mouse is already recorded in the journal"));
        }
        let mouse = mouse(instance)?;
        if !filters(&mouse)?.is_empty() {
            return Err(fail("A selected mouse already has a lower filter. Refusing to replace or combine drivers."));
        }
        mice.push(mouse);
    }
    Ok(Preflight {
        audited,
        mice,
        state,
        reuse,
        external,
    })
}

pub fn check_download(path: &Path) -> Result<()> {
    let audited = audit(path)?;
    println!("Driver verified; Windows accepted signature #{}. Choose Install to select mice and review the plan.", audited.signature);
    Ok(())
}

pub fn plan_selected(path: &Path, journal: &Path, selected: &[String]) -> Result<()> {
    let plan = preflight(path, journal, selected)?;
    println!("Read-only plan ready:\n  Driver: Apple 6.1.7000.0, unchanged, SHA-256 matched\n  Windows kernel signature policy: accepted signature #{}\n  Selected mouse nodes: {}\n  Shared driver: {}\n\nProposed administrator actions:\n  Save a local rollback journal, {} the shared driver service,\n  attach the filter to each selected mouse and restart those present in Windows.\n  Disconnected mice need testing after reconnection.\n\nSecure Boot, Memory Integrity, test-signing, certificate stores, and INF files stay unchanged.\nScrolling is unverified until a physical test.",plan.audited.signature,plan.mice.len(),destination()?.display(),if plan.reuse { "reuse and start if needed" } else { "create and start" });
    if plan.external {
        println!("\nThe existing driver and service are not owned by this journal. Removal will leave them and previously attached mice unchanged.");
    }
    Ok(())
}

fn single_present() -> Result<Vec<String>> {
    let present = present_instances()?;
    match present.len() {
        0 => Err(fail(
            "The exact PID 0323 Bluetooth HID mouse node was not found",
        )),
        1 => Ok(present),
        _ => Err(fail(
            "Multiple target mice found; use the guided menu to select mice",
        )),
    }
}

pub fn plan(path: &Path) -> Result<()> {
    // The CLI plan uses the guided setup's journal when it exists.
    let journal = std::env::current_exe()?.with_file_name("magic-scroll.state.json");
    plan_selected(path, &journal, &single_present()?)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    hash: String,
    file_created: bool,
    service_created: bool,
    #[serde(default)]
    external_shared: bool,
    devices: Vec<DeviceState>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceState {
    instance: String,
    filter_added: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyState {
    version: u32,
    hash: String,
    instance: String,
    file_created: bool,
    service_created: bool,
    filter_added: bool,
}

fn decode_state(bytes: &[u8]) -> Result<State> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let state = match value.get("version").and_then(|v| v.as_u64()) {
        Some(1) => {
            let legacy: LegacyState = serde_json::from_value(value)?;
            if legacy.version != 1 {
                return Err(fail("Invalid legacy journal version"));
            }
            State {
                version: 3,
                hash: legacy.hash,
                file_created: legacy.file_created,
                service_created: legacy.service_created,
                external_shared: false,
                devices: vec![DeviceState {
                    instance: legacy.instance,
                    filter_added: legacy.filter_added,
                }],
            }
        }
        Some(2) => {
            let mut state: State = serde_json::from_value(value)?;
            if state.external_shared {
                return Err(fail("Invalid version 2 rollback journal"));
            }
            state.version = 3;
            state
        }
        Some(3) => serde_json::from_value(value)?,
        _ => return Err(fail("Invalid or unsupported rollback journal version")),
    };
    validate_state(&state)?;
    Ok(state)
}

fn validate_state(state: &State) -> Result<()> {
    if state.version != 3
        || state.hash != HASH
        || (state.external_shared && (state.file_created || state.service_created))
    {
        return Err(fail("Invalid or unsupported rollback journal"));
    }
    for (index, device) in state.devices.iter().enumerate() {
        if !validate_instance(&device.instance)
            || state.devices[..index]
                .iter()
                .any(|previous| previous.instance.eq_ignore_ascii_case(&device.instance))
        {
            return Err(fail("Invalid or duplicate mouse in rollback journal"));
        }
    }
    Ok(())
}

fn load_state(journal: &Path) -> Result<State> {
    let file = File::open(journal)?;
    if file.metadata()?.len() > 262144 {
        return Err(fail("Oversized rollback journal"));
    }
    let mut bytes = Vec::new();
    file.take(262145).read_to_end(&mut bytes)?;
    if bytes.len() > 262144 {
        return Err(fail("Oversized rollback journal"));
    }
    decode_state(&bytes)
}
// Sync the next journal image before replacing the previous one. A crash
// between a system mutation and this save is still an open recovery case;
// see docs/TESTING.md before claiming crash-safe installation.
fn save(path: &Path, state: &State, initial: bool) -> Result<()> {
    let temp = if initial {
        path.to_path_buf()
    } else {
        path.with_extension("pending.json")
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    serde_json::to_writer_pretty(&mut file, state)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    if !initial {
        std::fs::rename(&temp, path)?;
    }
    Ok(())
}
fn restart(mouse: &Mouse) -> Result<()> {
    let status = std::process::Command::new(system_dir()?.join("pnputil.exe"))
        .args(["/restart-device", &mouse.instance])
        .output()?;
    if !status.status.success() {
        return Err(fail(
            "Windows could not restart the target mouse. Installation has not been verified.",
        ));
    }
    Ok(())
}
fn status(service: &ScHandle) -> Result<ServiceStatus> {
    let mut s: ServiceStatus = unsafe { zeroed() };
    if unsafe { QueryServiceStatus(service.0, &mut s) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(s)
}

pub fn install(path: &Path, journal: &Path) -> Result<()> {
    install_selected(path, journal, &single_present()?)
}

#[derive(Debug, PartialEq, Eq)]
struct InstallActions {
    create_journal: bool,
    create_driver: bool,
}

fn install_actions(has_journal: bool, reuse: bool) -> InstallActions {
    InstallActions {
        create_journal: !has_journal,
        create_driver: !reuse,
    }
}

pub fn install_selected(path: &Path, journal: &Path, selected: &[String]) -> Result<()> {
    // Opening SCM with CREATE_SERVICE performs the ordinary administrator access
    // check before creating a journal or touching a system file. No auto-elevation.
    let manager = manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let Preflight {
        audited,
        mice,
        state: existing,
        reuse,
        external,
    } = preflight(path, journal, selected)?;
    let actions = install_actions(existing.is_some(), reuse);
    let mut state = existing.unwrap_or_else(|| State {
        version: 3,
        hash: HASH.into(),
        file_created: false,
        service_created: false,
        external_shared: external,
        devices: Vec::new(),
    });
    let first_new = state.devices.len();
    if actions.create_journal {
        save(journal, &state, true)?;
    }
    let result = (|| -> Result<()> {
        if actions.create_driver {
            let destination = destination()?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&destination)?;
            state.file_created = true;
            let written = file
                .write_all(&audited.bytes)
                .and_then(|()| file.sync_all());
            drop(file);
            if let Err(error) = written {
                // This path was created exclusively by this running transaction.
                // Remove a partial copy before leaving it for the persisted rollback path.
                std::fs::remove_file(&destination)?;
                state.file_created = false;
                return Err(error.into());
            }
            save(journal, &state, false)?;
            // Verify the copied file before any kernel load attempt.
            audit(&destination)?;
            let name = wide(SERVICE);
            let display = wide("Apple Wireless Mouse — Magic Scroll setup");
            let binary = wide(&destination.to_string_lossy());
            let raw = unsafe {
                CreateServiceW(
                    manager.0,
                    name.as_ptr(),
                    display.as_ptr(),
                    0x10000
                        | SERVICE_QUERY_CONFIG
                        | SERVICE_QUERY_STATUS
                        | SERVICE_START
                        | SERVICE_STOP,
                    SERVICE_KERNEL_DRIVER,
                    SERVICE_DEMAND_START,
                    SERVICE_ERROR_NORMAL,
                    binary.as_ptr(),
                    null(),
                    null_mut(),
                    null(),
                    null(),
                    null(),
                )
            };
            if raw.is_null() {
                return Err(io::Error::last_os_error().into());
            }
            let service = ScHandle(raw);
            state.service_created = true;
            save(journal, &state, false)?;
            // Windows must accept the driver under its current security policy
            // before we change the mouse binding. Refusal keeps that binding intact.
            if unsafe { StartServiceW(service.0, 0, null()) } == 0 {
                return Err(fail(format!(
                    "Windows refused to start the unchanged driver: {}",
                    io::Error::last_os_error()
                )));
            }
            if status(&service)?.dwCurrentState != SERVICE_RUNNING {
                return Err(fail(
                    "Driver did not reach RUNNING; device filter was not changed",
                ));
            }
        } else {
            let service = service(&manager, SERVICE_QUERY_STATUS | SERVICE_START)?
                .ok_or("The existing driver service disappeared")?;
            if status(&service)?.dwCurrentState == SERVICE_STOPPED
                && unsafe { StartServiceW(service.0, 0, null()) } == 0
            {
                return Err(fail(format!(
                    "Windows refused to start the existing driver: {}",
                    io::Error::last_os_error()
                )));
            }
            if status(&service)?.dwCurrentState != SERVICE_RUNNING {
                return Err(fail("The existing driver did not reach RUNNING"));
            }
        }
        // Another installer could have changed this since preflight: recheck
        // immediately before writing rather than overwrite its changes.
        for mouse in &mice {
            if !filters(mouse)?.is_empty() {
                return Err(fail(
                    "Mouse filter state changed during installation; refusing to overwrite it",
                ));
            }
            set_filters(mouse, &[SERVICE.into()])?;
            state.devices.push(DeviceState {
                instance: mouse.instance.clone(),
                filter_added: true,
            });
            save(journal, &state, false)?;
            restart_if_present(mouse)?;
            if filters(mouse)? != vec![SERVICE.to_owned()] {
                return Err(fail("Device filter verification failed"));
            }
        }
        let service =
            service(&manager, SERVICE_QUERY_STATUS)?.ok_or("Driver service disappeared")?;
        if status(&service)?.dwCurrentState != SERVICE_RUNNING {
            return Err(fail("Driver is not RUNNING after device restart"));
        }
        println!("Driver bound to {} mouse node(s). Physical scrolling, clicks, movement and reconnect still require testing. Rollback journal: {}",mice.len(),journal.display());
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("Installation failed: {error}. Attempting rollback of only this transaction.");
        let rollback = if actions.create_journal {
            undo(&mut state)
        } else {
            let result = undo_devices(&mut state, first_new);
            if result.is_ok() {
                state.devices.truncate(first_new);
            }
            result
        };
        match rollback {
            Ok(()) => {
                save(journal, &state, false)?;
                eprintln!("Transaction rolled back.");
            }
            Err(e) => {
                if let Err(save_error) = save(journal, &state, false) {
                    eprintln!("Could not save rollback progress: {save_error}. Preserve the journal and any pending journal.");
                }
                eprintln!(
                    "Rollback incomplete: {e}. Preserve the journal; a restart may be needed."
                );
            }
        }
        return Err(error);
    }
    Ok(())
}

// QueryServiceConfig points into the caller's buffer. Check pointer bounds and
// UTF-16 alignment before constructing a slice from that native pointer.
fn service_binary(service: &ScHandle) -> Result<String> {
    let mut needed = 0;
    unsafe {
        QueryServiceConfigW(service.0, null_mut(), 0, &mut needed);
    }
    if needed < size_of::<ServiceConfig>() as u32 || needed > 32768 {
        return Err(fail("Invalid service configuration size"));
    }
    let mut buffer = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    let config = buffer.as_mut_ptr().cast::<ServiceConfig>();
    if unsafe { QueryServiceConfigW(service.0, config, needed, &mut needed) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    if needed as usize > buffer.len() * size_of::<usize>() {
        return Err(fail("Service configuration changed size during query"));
    }
    let c = unsafe { &*config };
    if c.dwServiceType != SERVICE_KERNEL_DRIVER {
        return Err(fail("Service is no longer a kernel driver"));
    }
    let start = c.lpBinaryPathName as usize;
    let low = buffer.as_ptr() as usize;
    let high = low + needed as usize;
    if start < low || start >= high || !start.is_multiple_of(2) {
        return Err(fail("Invalid service binary pointer"));
    }
    let chars = unsafe { std::slice::from_raw_parts(c.lpBinaryPathName, (high - start) / 2) };
    let end = chars
        .iter()
        .position(|&x| x == 0)
        .ok_or_else(|| fail("Unterminated service binary path"))?;
    Ok(String::from_utf16(&chars[..end])?)
}

fn service_binary_matches(binary: &str, destination: &Path) -> bool {
    binary
        .strip_prefix(r"\??\")
        .unwrap_or(binary)
        .eq_ignore_ascii_case(&destination.to_string_lossy())
}

fn undo(state: &mut State) -> Result<()> {
    // Validate everything before modifying anything during rollback.
    validate_state(state)?;
    let service = if state.service_created {
        let manager = manager(SC_MANAGER_CONNECT)?;
        service(
            &manager,
            0x10000 | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP,
        )?
    } else {
        None
    };
    let destination = destination()?;
    // A newly revoked or blocked signature must not prevent removal of our
    // own byte-identical file. Rollback verifies ownership by the pinned hash.
    if state.file_created && destination.exists() && file_hash(&destination)? != HASH {
        return Err(fail(
            "Driver file changed. Refusing to remove an unrelated or modified file.",
        ));
    }
    if state.service_created {
        if let Some(ref s) = service {
            if !service_binary_matches(&service_binary(s)?, &destination) {
                return Err(fail(
                    "Service binary path changed. Refusing to delete another installation.",
                ));
            }
        }
        for (_, instance) in enumerate(&device_set(false)?)? {
            if !state
                .devices
                .iter()
                .any(|device| device.instance.eq_ignore_ascii_case(&instance))
                && filters(&mouse(&instance)?)?
                    .iter()
                    .any(|entry| entry.eq_ignore_ascii_case(SERVICE))
            {
                return Err(fail("Another matching mouse uses this service but is not in the journal. Refusing to remove the shared driver."));
            }
        }
    }
    undo_devices(state, 0)?;
    if state.service_created {
        for (_, instance) in enumerate(&device_set(false)?)? {
            if filters(&mouse(&instance)?)?
                .iter()
                .any(|entry| entry.eq_ignore_ascii_case(SERVICE))
            {
                return Err(fail(
                    "A matching mouse still uses the shared driver. Refusing to unload it.",
                ));
            }
        }
        if let Some(ref service) = service {
            if status(service)?.dwCurrentState != SERVICE_STOPPED {
                let mut result: ServiceStatus = unsafe { zeroed() };
                if unsafe { ControlService(service.0, 1, &mut result) } == 0 {
                    return Err(fail(format!(
                        "Could not unload driver: {}. Restart and retry rollback.",
                        io::Error::last_os_error()
                    )));
                }
                if status(service)?.dwCurrentState != SERVICE_STOPPED {
                    return Err(fail(
                        "Driver is still stopping. Retry rollback after it stops.",
                    ));
                }
            }
            if unsafe { DeleteService(service.0) } == 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        state.service_created = false;
    }
    drop(service);
    if state.file_created {
        if destination.exists() {
            std::fs::remove_file(destination)?;
        }
        state.file_created = false;
    }
    Ok(())
}

fn undo_devices(state: &mut State, first: usize) -> Result<()> {
    // Keep the shared service until every recorded attachment is removed.
    undo_recorded_devices(state, first, detach_mouse)
}

fn detach_mouse(instance: &str) -> Result<()> {
    let mouse = mouse(instance)?;
    let mut current = filters(&mouse)?;
    current.retain(|f| !f.eq_ignore_ascii_case(SERVICE));
    set_filters(&mouse, &current)?;
    restart_if_present(&mouse)
}

fn undo_recorded_devices(
    state: &mut State,
    first: usize,
    mut detach: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    for device in state.devices[first..].iter_mut().rev() {
        if device.filter_added {
            detach(&device.instance)?;
            device.filter_added = false;
        }
    }
    Ok(())
}

fn remove_recorded_device(
    state: &mut State,
    instance: &str,
    detach: impl FnOnce(&str) -> Result<()>,
    persist: impl FnOnce(&State) -> Result<()>,
) -> Result<()> {
    validate_state(state)?;
    let index = state
        .devices
        .iter()
        .position(|device| device.filter_added && device.instance.eq_ignore_ascii_case(instance))
        .ok_or("The selected mouse is not recorded as attached in this journal")?;
    detach(&state.devices[index].instance).map_err(|error| {
        fail(format!("Could not finish removing the mouse: {error}. The journal still records it; preserve the journal and retry removal."))
    })?;
    let removed = state.devices.remove(index);
    if let Err(error) = persist(state) {
        state.devices.insert(index, removed);
        return Err(fail(format!("The mouse was detached, but updating the journal failed: {error}. Preserve the journal and any pending journal for recovery.")));
    }
    Ok(())
}

pub fn remove_selected(journal: &Path, selection: RemovalSelection) -> Result<()> {
    match selection {
        RemovalSelection::All => rollback(journal),
        RemovalSelection::One(instance) => {
            if journal.with_extension("pending.json").try_exists()? {
                return Err(fail("A pending journal exists. Preserve it and resolve the previous incomplete operation before continuing."));
            }
            let mut state = load_state(journal)?;
            let destination = destination()?;
            if destination.try_exists()? && file_hash(&destination)? != HASH {
                return Err(fail("The shared driver file changed. Refusing to detach a potentially unrelated filter."));
            }
            let manager = manager(SC_MANAGER_CONNECT)?;
            if let Some(service) = service(&manager, SERVICE_QUERY_CONFIG)? {
                if !service_binary_matches(&service_binary(&service)?, &destination) {
                    return Err(fail("The shared service points to a different driver. Refusing to detach a potentially unrelated filter."));
                }
            }
            remove_recorded_device(&mut state, &instance, detach_mouse, |state| {
                save(journal, state, false)
            })?;
            println!("The selected mouse was removed. The shared driver and service remain in place; use Remove all to clean up owned shared components.");
            Ok(())
        }
    }
}

pub fn rollback(journal: &Path) -> Result<()> {
    if !journal.try_exists()? {
        return Err(fail("No removal journal was found. Existing mouse attachments and drivers cannot safely be removed without their installation records."));
    }
    let mut state = load_state(journal)?;
    let result = undo(&mut state);
    save(journal, &state, false)?;
    result?;
    if state.external_shared {
        println!("Recorded mouse attachments were removed. The existing shared driver and service were left in place.");
    } else {
        println!("This installation was removed. Unrelated filter entries were preserved.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn administrator_options_indicate_effective_privileges() {
        let (elevated, elevated_color) = administrator_option(2, "Install", true);
        assert!(elevated.contains("[running as administrator]"));
        assert_eq!(elevated_color, FOREGROUND_GREEN);
        let (unelevated, unelevated_color) = administrator_option(4, "Remove", false);
        assert!(unelevated.contains("[not running as administrator]"));
        assert_eq!(unelevated_color, FOREGROUND_RED);
    }

    #[test]
    fn service_binary_accepts_windows_kernel_path_prefix_only_for_expected_file() {
        let expected = Path::new(r"C:\Windows\System32\drivers\applewirelessmouse.sys");
        assert!(service_binary_matches(
            r"\??\C:\WINDOWS\system32\drivers\applewirelessmouse.sys",
            expected
        ));
        assert!(service_binary_matches(
            r"C:\Windows\System32\drivers\applewirelessmouse.sys",
            expected
        ));
        assert!(!service_binary_matches(
            r"\??\C:\other\applewirelessmouse.sys",
            expected
        ));
    }

    fn choice(suffix: &str, present: bool, installed: bool) -> MouseChoice {
        MouseChoice {
            instance: format!("{}\\{suffix}", crate::HARDWARE),
            present,
            installed,
            tracked: installed,
            attached: installed,
        }
    }

    #[test]
    fn selection_includes_offline_and_skips_installed_mice() {
        let mut choices = vec![
            choice("one", true, true),
            choice("two", false, false),
            choice("three", true, false),
        ];
        choices[0].tracked = false;
        assert_eq!(
            select_choices(&choices, "2").unwrap(),
            vec![choices[1].instance.clone()]
        );
        assert_eq!(
            select_choices(&choices, "all").unwrap(),
            vec![choices[1].instance.clone(), choices[2].instance.clone()]
        );
        assert_eq!(
            select_choices(&choices, "4").unwrap(),
            vec![choices[1].instance.clone(), choices[2].instance.clone()]
        );
        for invalid in ["0", "1", "5", "-1", "invalid"] {
            assert!(select_choices(&choices, invalid).is_err());
        }
        assert!(select_choices(&choices[..1], "all").is_err());
        assert!(select_choices(&choices[..1], "2").is_err());
    }

    #[test]
    fn mouse_option_color_follows_actual_filter_not_journal() {
        let mut mouse = choice("one", true, true);
        assert_eq!(choice_option(0, &mouse).1, FOREGROUND_GREEN);
        mouse.attached = false;
        let (text, color) = choice_option(0, &mouse);
        assert_eq!(color, FOREGROUND_RED);
        assert!(text.contains("not attached; tracked here; filter missing"));
        mouse.tracked = false;
        let (text, color) = choice_option(0, &mouse);
        assert_eq!(color, FOREGROUND_RED);
        assert!(text.contains("[not attached]"));
    }

    #[test]
    fn removal_menu_selects_one_or_all_recorded_mice() {
        let choices = vec![
            RemovalChoice {
                instance: format!("{}\\one", crate::HARDWARE),
                present: true,
                attached: Some(true),
            },
            RemovalChoice {
                instance: format!("{}\\two", crate::HARDWARE),
                present: false,
                attached: Some(true),
            },
        ];
        match select_removal(&choices, "2").unwrap() {
            RemovalSelection::One(instance) => assert_eq!(instance, choices[1].instance),
            RemovalSelection::All => panic!("Selected all instead of one"),
        }
        assert!(matches!(
            select_removal(&choices, "3").unwrap(),
            RemovalSelection::All
        ));
        assert!(matches!(
            select_removal(&[], "1").unwrap(),
            RemovalSelection::All
        ));
        for invalid in ["0", "4", "invalid"] {
            assert!(select_removal(&choices, invalid).is_err());
        }
    }

    #[test]
    fn removing_one_keeps_other_mouse_and_shared_components() {
        let mut state = State {
            version: 3,
            hash: HASH.into(),
            file_created: true,
            service_created: true,
            external_shared: false,
            devices: ["one", "two"]
                .into_iter()
                .map(|suffix| DeviceState {
                    instance: format!("{}\\{suffix}", crate::HARDWARE),
                    filter_added: true,
                })
                .collect(),
        };
        let selected = state.devices[0].instance.clone();
        let retained = state.devices[1].instance.clone();
        let mut detached = Vec::new();
        let mut saved = Vec::new();
        remove_recorded_device(
            &mut state,
            &selected.to_uppercase(),
            |id| {
                detached.push(id.to_owned());
                Ok(())
            },
            |state| {
                saved = serde_json::to_vec(state)?;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(detached, vec![selected]);
        let persisted = decode_state(&saved).unwrap();
        assert_eq!(persisted.devices.len(), 1);
        assert_eq!(persisted.devices[0].instance, retained);
        assert!(persisted.devices[0].filter_added);
        assert!(persisted.file_created && persisted.service_created);
        remove_recorded_device(&mut state, &retained, |_| Ok(()), |_| Ok(())).unwrap();
        assert!(state.devices.is_empty());
        assert!(state.file_created && state.service_created);
        assert!(check_journal_for_install(&state).is_ok());
    }

    #[test]
    fn failed_individual_removal_keeps_its_journal_record() {
        let mut state = State {
            version: 3,
            hash: HASH.into(),
            file_created: false,
            service_created: false,
            external_shared: true,
            devices: vec![DeviceState {
                instance: format!("{}\\one", crate::HARDWARE),
                filter_added: true,
            }],
        };
        let selected = state.devices[0].instance.clone();
        assert!(remove_recorded_device(
            &mut state,
            &selected,
            |_| Err(fail("restart failed")),
            |_| { panic!("Must not save after detach failure") }
        )
        .is_err());
        assert!(state.devices[0].filter_added);
        assert!(remove_recorded_device(
            &mut state,
            &selected,
            |_| Ok(()),
            |_| Err(fail("write failed"))
        )
        .is_err());
        assert_eq!(state.devices[0].instance, selected);
        assert!(state.devices[0].filter_added);
        assert!(remove_recorded_device(
            &mut state,
            "untracked",
            |_| { panic!("Must not detach an untracked mouse") },
            |_| Ok(())
        )
        .is_err());
    }

    #[test]
    fn existing_driver_requires_both_file_and_service() {
        assert!(reuse_existing(true, true, false).unwrap());
        assert!(!reuse_existing(false, false, false).unwrap());
        for (file, service, journal) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            assert!(reuse_existing(file, service, journal).is_err());
        }
    }

    #[test]
    fn new_journal_reuses_existing_driver_without_creating_another() {
        assert_eq!(
            install_actions(false, true),
            InstallActions {
                create_journal: true,
                create_driver: false,
            }
        );
        assert_eq!(
            install_actions(false, false),
            InstallActions {
                create_journal: true,
                create_driver: true,
            }
        );
        assert_eq!(
            install_actions(true, true),
            InstallActions {
                create_journal: false,
                create_driver: false,
            }
        );
    }

    #[test]
    fn empty_external_journal_can_retry_but_incomplete_owned_state_cannot() {
        let mut state = State {
            version: 3,
            hash: HASH.into(),
            file_created: false,
            service_created: false,
            external_shared: true,
            devices: Vec::new(),
        };
        assert!(check_journal_for_install(&state).is_ok());
        state.devices.push(DeviceState {
            instance: format!("{}\\one", crate::HARDWARE),
            filter_added: false,
        });
        assert!(check_journal_for_install(&state).is_err());
        state.devices.clear();
        state.external_shared = false;
        assert!(check_journal_for_install(&state).is_err());
    }

    #[test]
    fn external_journal_never_claims_shared_components() {
        let id = format!("{}\\external", crate::HARDWARE);
        let mut state = State {
            version: 3,
            hash: HASH.into(),
            file_created: false,
            service_created: false,
            external_shared: true,
            devices: vec![DeviceState {
                instance: id,
                filter_added: true,
            }],
        };
        let decoded = decode_state(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(decoded.external_shared);
        assert!(!decoded.file_created && !decoded.service_created);
        state.service_created = true;
        assert!(validate_state(&state).is_err());
        state.service_created = false;
        state.file_created = true;
        assert!(validate_state(&state).is_err());
    }

    #[test]
    fn legacy_journal_migrates_and_keeps_ownership() {
        let id = format!("{}\\legacy", crate::HARDWARE);
        let bytes = serde_json::to_vec(&serde_json::json!({
            "version": 1, "hash": HASH, "instance": id,
            "file_created": true, "service_created": true, "filter_added": true
        }))
        .unwrap();
        let state = decode_state(&bytes).unwrap();
        assert!(state.file_created && state.service_created);
        assert_eq!(state.devices.len(), 1);
        assert_eq!(state.devices[0].instance, id);
        assert!(state.devices[0].filter_added);
        let round_trip = decode_state(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert_eq!(round_trip.devices[0].instance, id);
    }

    #[test]
    fn rejects_invalid_and_duplicate_journal_devices() {
        let id = format!("{}\\device", crate::HARDWARE);
        let journal = |devices: serde_json::Value| {
            serde_json::to_vec(&serde_json::json!({
                "version": 2, "hash": HASH, "file_created": true,
                "service_created": true, "devices": devices
            }))
            .unwrap()
        };
        assert!(decode_state(&journal(serde_json::json!([
            {"instance": id, "filter_added": true},
            {"instance": id.to_uppercase(), "filter_added": true}
        ])))
        .is_err());
        assert!(decode_state(&journal(serde_json::json!([
            {"instance": "not-a-mouse", "filter_added": true}
        ])))
        .is_err());
    }

    #[test]
    fn incremental_rollback_preserves_existing_mice_and_retries_failed_detach() {
        let mut state = State {
            version: 3,
            hash: HASH.into(),
            file_created: true,
            service_created: true,
            external_shared: false,
            devices: ["old", "new1", "new2"]
                .into_iter()
                .map(|suffix| DeviceState {
                    instance: format!("{}\\{suffix}", crate::HARDWARE),
                    filter_added: true,
                })
                .collect(),
        };
        let mut attempted = Vec::new();
        let result = undo_recorded_devices(&mut state, 1, |instance| {
            attempted.push(instance.to_owned());
            if instance.ends_with("new1") {
                Err(fail("restart failed"))
            } else {
                Ok(())
            }
        });
        assert!(result.is_err());
        assert_eq!(attempted.len(), 2);
        assert!(state.devices[0].filter_added);
        assert!(state.devices[1].filter_added);
        assert!(!state.devices[2].filter_added);
        assert!(state.file_created && state.service_created);

        attempted.clear();
        undo_recorded_devices(&mut state, 1, |instance| {
            attempted.push(instance.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(attempted, vec![state.devices[1].instance.clone()]);
        assert!(state.devices[0].filter_added);
        assert!(!state.devices[1].filter_added && !state.devices[2].filter_added);
    }

    #[test]
    fn download_option_reports_presence_with_matching_color() {
        let (missing, missing_color) = download_option(false);
        assert!(missing.contains("[not downloaded]"));
        assert_eq!(missing_color, FOREGROUND_RED);
        let (present, present_color) = download_option(true);
        assert!(present.contains("[downloaded]"));
        assert_eq!(present_color, FOREGROUND_GREEN);
    }

    #[test]
    fn multisz_roundtrip_and_validation() {
        for values in [vec![], vec!["one".into()], vec!["one".into(), "two".into()]] {
            assert_eq!(
                decode_multi(&encode_multi(&values).unwrap()).unwrap(),
                values
            );
        }
        assert!(decode_multi(&[1]).is_err());
        assert!(decode_multi(&[1, 0]).is_err());
        assert!(encode_multi(&["bad\0value".into()]).is_err());
        assert!(decode_multi(&[0, 0, 1, 0, 0, 0]).is_err());
    }
}
