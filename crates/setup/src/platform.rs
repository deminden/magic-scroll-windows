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
    io::{self, Read, Write},
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
        Security::WinTrust::*,
        System::{
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

fn download(path: &Path, url: &str, hash: &str) -> Result<()> {
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
    if file_hash(path)? != hash {
        return Err(fail(
            "Download integrity mismatch; execution and extraction refused",
        ));
    }
    Ok(())
}

/// Bootstrap an audited portable extractor without installing 7-Zip system-wide.
/// The setup archive is opened as data; its installer is never executed.
pub fn prepare(folder: &Path) -> Result<()> {
    std::fs::create_dir(folder)?;
    let folder = std::fs::canonicalize(folder)?;
    let bootstrap = folder.join("7zr.exe");
    let archive = folder.join("7z-setup.exe");
    println!("Downloading verified portable 7-Zip tools from 7-zip.org. No system installation.");
    download(
        &bootstrap,
        "https://www.7-zip.org/a/7zr.exe",
        "256feca8e274e5da655e2a284fabafd9f554365eb164862089dacd4e8276d282",
    )?;
    download(
        &archive,
        "https://www.7-zip.org/a/7z2501-x64.exe",
        "78afa2a1c773caf3cf7edf62f857d2a8a5da55fb0fff5da416074c0d28b2b55f",
    )?;
    // Deny writes/deletion of the verified executable until its process exits.
    let _locked = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&bootstrap)?;
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
    download(
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
// Install searches present devices. Rollback can find a disconnected node by
// its saved instance ID. More than one match is refused rather than guessed.
fn mouse(saved: Option<&str>) -> Result<Mouse> {
    let set = DeviceSet(unsafe {
        SetupDiGetClassDevsW(
            null(),
            null(),
            null_mut(),
            DIGCF_ALLCLASSES | if saved.is_some() { 0 } else { DIGCF_PRESENT },
        )
    });
    if set.0 as isize == -1 {
        return Err(io::Error::last_os_error().into());
    }
    let mut found = None;
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
        if !validate_instance(&instance)
            || saved.is_some_and(|s| !s.eq_ignore_ascii_case(&instance))
        {
            continue;
        }
        if found.is_some() {
            return Err(fail(
                "Multiple target mice found; no automatic choice is made",
            ));
        }
        found = Some((info, instance));
    }
    let (info, instance) =
        found.ok_or_else(|| fail("The exact PID 0323 Bluetooth HID mouse node was not found"))?;
    Ok(Mouse {
        set,
        info,
        instance,
    })
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
// Own a new installation only. Existing filters, files and services can belong
// to another package, so neither plan nor install replaces them.
fn preflight(path: &Path) -> Result<(Audited, Mouse)> {
    let audited = audit(path)?;
    let mouse = mouse(None)?;
    if !filters(&mouse)?.is_empty() {
        return Err(fail(
            "An existing lower filter is installed. Refusing to replace or combine drivers.",
        ));
    }
    if destination()?.exists() {
        return Err(fail(
            "A system Apple driver file already exists. Refusing to overwrite it.",
        ));
    }
    let manager = manager(SC_MANAGER_CONNECT)?;
    if service(&manager, SERVICE_QUERY_CONFIG)?.is_some() {
        return Err(fail(
            "An Apple mouse service already exists. Refusing to alter it.",
        ));
    }
    Ok((audited, mouse))
}
pub fn plan(path: &Path) -> Result<()> {
    let (audited, _) = preflight(path)?;
    println!("Read-only plan ready:\n  Driver: Apple 6.1.7000.0, unchanged, SHA-256 matched\n  Windows kernel signature policy: accepted signature #{}\n  Exact target: Apple Bluetooth HID PID 0323 (device identifiers omitted)\n  No existing service, driver file, or lower-filter conflict\n  Basic PE memory checks: passed (not proof of HVCI compatibility)\n\nProposed administrator actions:\n  1. Save a local rollback journal\n  2. Copy the verified driver to {}\n  3. Create and start the {} kernel service\n  4. Abort and roll back if Windows refuses to load it\n  5. Attach only to the target mouse and restart that device\n\nSecure Boot, Memory Integrity, test-signing, certificate stores, and INF files stay unchanged.\nUSB-C scrolling is unverified until a physical test.",audited.signature,destination()?.display(),SERVICE);
    Ok(())
}

// Record ownership: rollback removes only things this transaction created.
// The device identity is private, so this journal stays on the user's machine.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    hash: String,
    instance: String,
    file_created: bool,
    service_created: bool,
    filter_added: bool,
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
    // Opening SCM with CREATE_SERVICE performs the ordinary administrator access
    // check before creating a journal or touching a system file. No auto-elevation.
    let manager = manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let (audited, mouse) = preflight(path)?;
    if journal.exists() || journal.with_extension("pending.json").exists() {
        return Err(fail("Rollback journal or pending journal already exists"));
    }
    let mut state = State {
        version: 1,
        hash: HASH.into(),
        instance: mouse.instance.clone(),
        file_created: false,
        service_created: false,
        filter_added: false,
    };
    save(journal, &state, true)?;
    let result = (|| -> Result<()> {
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
        // Another installer could have changed this since preflight: recheck
        // immediately before writing rather than overwrite its changes.
        if !filters(&mouse)?.is_empty() {
            return Err(fail(
                "Mouse filter state changed during installation; refusing to overwrite it",
            ));
        }
        set_filters(&mouse, &[SERVICE.into()])?;
        state.filter_added = true;
        save(journal, &state, false)?;
        restart(&mouse)?;
        if status(&service)?.dwCurrentState != SERVICE_RUNNING {
            return Err(fail("Driver is not RUNNING after device restart"));
        }
        if filters(&mouse)? != vec![SERVICE.to_owned()] {
            return Err(fail("Device filter verification failed"));
        }
        println!("Driver loaded and bound. Physical scrolling, clicks, movement and reconnect still require testing. Rollback journal: {}",journal.display());
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("Installation failed: {error}. Attempting rollback of only this transaction.");
        match undo(&mut state) {
            Ok(()) => {
                save(journal, &state, false)?;
                eprintln!("Transaction rolled back.");
            }
            Err(e) => {
                let _ = save(journal, &state, false);
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
fn undo(state: &mut State) -> Result<()> {
    // Validate everything before modifying anything during rollback.
    if state.version != 1 || state.hash != HASH || !validate_instance(&state.instance) {
        return Err(fail("Invalid or unsupported rollback journal"));
    }
    let manager = manager(SC_MANAGER_CONNECT)?;
    let service = service(
        &manager,
        0x10000 | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP,
    )?;
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
            if !service_binary(s)?.eq_ignore_ascii_case(&destination.to_string_lossy()) {
                return Err(fail(
                    "Service binary path changed. Refusing to delete another installation.",
                ));
            }
        }
    }
    // Detach and restart before unloading the driver and removing its file.
    // Preserve any unrelated filter entries added after this installation.
    if state.filter_added {
        let mouse = mouse(Some(&state.instance))?;
        let mut current = filters(&mouse)?;
        current.retain(|f| !f.eq_ignore_ascii_case(SERVICE));
        set_filters(&mouse, &current)?;
        // Remains marked until the native device has restarted successfully.
        restart(&mouse)?;
        state.filter_added = false;
    }
    if state.service_created {
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
pub fn rollback(journal: &Path) -> Result<()> {
    let file = File::open(journal)?;
    if file.metadata()?.len() > 16384 {
        return Err(fail("Oversized rollback journal"));
    }
    let mut state: State = serde_json::from_reader(file.take(16385))?;
    let result = undo(&mut state);
    save(journal, &state, false)?;
    result?;
    println!("This installation was removed. Unrelated filter entries were preserved.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
