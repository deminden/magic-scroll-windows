// SPDX-License-Identifier: MIT
//! A visible, explicitly launched physical-input check, scoped to Apple PID 0323.
//! Counts only Raw Input events associated with that device. SendInput events
//! with no device identity cannot count as a successful Magic Mouse scroll test.
use std::{
    io,
    mem::{size_of, zeroed},
    ptr::{null, null_mut},
    sync::atomic::{AtomicI32, AtomicU64, Ordering},
};
use windows_sys::Win32::{
    Foundation::HANDLE as Handle,
    System::LibraryLoader::GetModuleHandleW,
    UI::{
        Input::{
            GetRawInputData, GetRawInputDeviceInfoW, RegisterRawInputDevices,
            RAWINPUTDEVICE as RawDevice, RAWINPUTHEADER as RawHeader, RAWMOUSE, RIDEV_INPUTSINK,
            RIDI_DEVICENAME, RID_INPUT, RIM_TYPEMOUSE,
        },
        WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, LoadCursorW,
            PostQuitMessage, RegisterClassW, SetWindowTextW, TranslateMessage, CW_USEDEFAULT,
            IDC_ARROW, MSG as Message, WM_DESTROY, WM_INPUT, WNDCLASSW as Class, WS_CHILD,
            WS_OVERLAPPEDWINDOW, WS_VISIBLE,
        },
    },
};
// Aggregate counters are not an input history. Relaxed ordering is sufficient:
// they do not synchronize memory or control how mouse input is delivered.
static MOVES: AtomicU64 = AtomicU64::new(0);
static LEFT: AtomicU64 = AtomicU64::new(0);
static RIGHT: AtomicU64 = AtomicU64::new(0);
static V_EVENTS: AtomicU64 = AtomicU64::new(0);
static H_EVENTS: AtomicU64 = AtomicU64::new(0);
static V_UNITS: AtomicI32 = AtomicI32::new(0);
static H_UNITS: AtomicI32 = AtomicI32::new(0);
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}
fn target(device: Handle) -> bool {
    // Without a device identity, this cannot count as hardware evidence.
    // In particular, synthetic SendInput must not prove Magic Mouse support.
    if device.is_null() {
        return false;
    }
    let mut needed = 0;
    unsafe {
        GetRawInputDeviceInfoW(device, RIDI_DEVICENAME, null_mut(), &mut needed);
    }
    if needed == 0 || needed > 32768 {
        return false;
    }
    let mut name = vec![0u16; needed as usize + 1];
    if unsafe {
        GetRawInputDeviceInfoW(
            device,
            RIDI_DEVICENAME,
            name.as_mut_ptr().cast(),
            &mut needed,
        )
    } == u32::MAX
    {
        return false;
    }
    let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    let path = String::from_utf16_lossy(&name[..end]).to_lowercase();
    // Do not print the path or Bluetooth identity; use it only for attribution.
    (path.contains("pid&0323") || path.contains("pid_0323"))
        && (path.contains("vid&0001004c") || path.contains("vid_05ac"))
}
fn consume(window: Handle, input: Handle) {
    let mut needed = 0;
    let hs = size_of::<RawHeader>() as u32;
    unsafe {
        GetRawInputData(input, RID_INPUT, null_mut(), &mut needed, hs);
    }
    if needed < hs + size_of::<RAWMOUSE>() as u32 || needed > 65536 {
        return;
    }
    // u64 storage provides alignment for RAWINPUTHEADER, including its pointers.
    let mut storage = vec![0u64; (needed as usize).div_ceil(8)];
    let count = unsafe {
        GetRawInputData(
            input,
            RID_INPUT,
            storage.as_mut_ptr().cast(),
            &mut needed,
            hs,
        )
    };
    if count == u32::MAX
        || count < hs + size_of::<RAWMOUSE>() as u32
        || count as usize > storage.len() * 8
    {
        return;
    }
    let header = unsafe { &*storage.as_ptr().cast::<RawHeader>() };
    if header.dwType != RIM_TYPEMOUSE || header.dwSize != count || !target(header.hDevice) {
        return;
    }
    // The header and RAWMOUSE payload are bounded above. Use Microsoft's layout
    // rather than maintain offsets into the native button union ourselves.
    let mouse = unsafe {
        storage
            .as_ptr()
            .cast::<u8>()
            .add(hs as usize)
            .cast::<RAWMOUSE>()
            .read_unaligned()
    };
    let buttons = unsafe { mouse.Anonymous.Anonymous };
    let flags = buttons.usButtonFlags;
    let units = buttons.usButtonData as i16 as i32;
    let (dx, dy) = (mouse.lLastX, mouse.lLastY);
    if dx != 0 || dy != 0 {
        MOVES.fetch_add(1, Ordering::Relaxed);
    }
    // Count button-down transitions; a press and release is one click.
    if flags & 1 != 0 {
        LEFT.fetch_add(1, Ordering::Relaxed);
    }
    if flags & 4 != 0 {
        RIGHT.fetch_add(1, Ordering::Relaxed);
    }
    // RI_MOUSE_WHEEL (0x400) and RI_MOUSE_HWHEEL (0x800) carry signed units.
    // Count packets and sum units separately: opposite directions can cancel.
    if flags & 0x400 != 0 {
        V_EVENTS.fetch_add(1, Ordering::Relaxed);
        V_UNITS.fetch_add(units, Ordering::Relaxed);
    }
    if flags & 0x800 != 0 {
        H_EVENTS.fetch_add(1, Ordering::Relaxed);
        H_UNITS.fetch_add(units, Ordering::Relaxed);
    }
    let title = wide(&format!(
        "Magic Mouse test | Move {} | Left {} | Right {} | Vertical {} | Horizontal {}",
        MOVES.load(Ordering::Relaxed),
        LEFT.load(Ordering::Relaxed),
        RIGHT.load(Ordering::Relaxed),
        V_EVENTS.load(Ordering::Relaxed),
        H_EVENTS.load(Ordering::Relaxed)
    ));
    unsafe {
        SetWindowTextW(window, title.as_ptr());
    }
}
unsafe extern "system" fn proc(
    window: Handle,
    message: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    if message == WM_INPUT {
        consume(window, lparam as Handle);
    }
    if message == WM_DESTROY {
        unsafe {
            PostQuitMessage(0);
        }
        return 0;
    }
    // DefWindowProc performs the documented WM_INPUT foreground cleanup.
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}
pub fn run() -> io::Result<()> {
    let instance = unsafe { GetModuleHandleW(null()) };
    let name = wide("MagicScrollPhysicalInputCheck");
    let class = Class {
        lpfnWndProc: Some(proc),
        hInstance: instance,
        hCursor: unsafe { LoadCursorW(null_mut(), IDC_ARROW) },
        hbrBackground: 6usize as Handle,
        lpszClassName: name.as_ptr(),
        ..unsafe { zeroed() }
    };
    if unsafe { RegisterClassW(&class) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let title = wide("Magic Mouse physical input test");
    let window = unsafe {
        CreateWindowExW(
            0,
            name.as_ptr(),
            title.as_ptr(),
            WS_VISIBLE | WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            950,
            250,
            null_mut(),
            null_mut(),
            instance,
            null_mut(),
        )
    };
    if window.is_null() {
        return Err(io::Error::last_os_error());
    }
    let static_class = wide("STATIC");
    let text=wide("Use your Magic Mouse: move it, click left and right, then slide your finger vertically and horizontally.\r\n\r\nThe counts appear in the title bar. Only input identified as your USB-C Magic Mouse counts.\r\nClose this window when finished.");
    let label = unsafe {
        CreateWindowExW(
            0,
            static_class.as_ptr(),
            text.as_ptr(),
            WS_CHILD | WS_VISIBLE,
            20,
            25,
            890,
            140,
            window,
            null_mut(),
            instance,
            null_mut(),
        )
    };
    if label.is_null() {
        return Err(io::Error::last_os_error());
    }
    // RIDEV_INPUTSINK also receives input while the user scrolls another app.
    // We observe it without disabling that app's normal mouse messages.
    let raw = RawDevice {
        usUsagePage: 1,
        usUsage: 2,
        dwFlags: RIDEV_INPUTSINK,
        hwndTarget: window,
    };
    if unsafe { RegisterRawInputDevices(&raw, 1, size_of::<RawDevice>() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    println!("Physical Magic Mouse input test started. No synthetic input will be sent.");
    // The Win32 message pump delivers WM_INPUT to our window procedure.
    // Closing the window ends the test and prints its aggregate results.
    loop {
        let mut message: Message = unsafe { zeroed() };
        let result = unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };
        if result == 0 {
            break;
        }
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    println!("{{\"source\":\"Apple PID 0323 raw input\",\"movement_events\":{},\"left_clicks\":{},\"right_clicks\":{},\"vertical_scroll_events\":{},\"horizontal_scroll_events\":{},\"vertical_units\":{},\"horizontal_units\":{}}}",MOVES.load(Ordering::Relaxed),LEFT.load(Ordering::Relaxed),RIGHT.load(Ordering::Relaxed),V_EVENTS.load(Ordering::Relaxed),H_EVENTS.load(Ordering::Relaxed),V_UNITS.load(Ordering::Relaxed),H_UNITS.load(Ordering::Relaxed));
    Ok(())
}
