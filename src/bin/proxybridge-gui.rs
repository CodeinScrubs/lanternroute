#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("ProxyBridge GUI is Windows-only.");
}

#[cfg(windows)]
fn main() {
    if let Err(error) = windows_gui::run() {
        windows_gui::message_box("ProxyBridge RS", &format!("{error:#}"));
    }
}

#[cfg(windows)]
mod windows_gui {
    #![allow(unsafe_op_in_unsafe_fn)]

    use anyhow::{Context, Result, bail};
    use proxybridge_rs::admin::is_elevated;
    use proxybridge_rs::engine::{SING_BOX_VERSION, find_running_owned_engines};
    use proxybridge_rs::gui_support::{
        GuiOptions, build_cli_args, build_path_args, cli_exe_for_gui_exe, load_profile,
        runtime_home_for_gui_exe, save_profile,
    };
    use std::ffi::OsStr;
    use std::io::{BufRead, BufReader, Read};
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::ptr::{null, null_mut};
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::thread;
    use windows_sys::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
    use windows_sys::Win32::Graphics::Gdi::HBRUSH;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::HiDpi::{
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
    };
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        BM_GETCHECK, BM_SETCHECK, BS_AUTOCHECKBOX, BS_GROUPBOX, CW_USEDEFAULT, CreateWindowExW,
        DefWindowProcW, DestroyWindow, DispatchMessageW, ES_AUTOHSCROLL, ES_AUTOVSCROLL,
        ES_MULTILINE, ES_READONLY, ES_WANTRETURN, GWLP_USERDATA, GetClientRect, GetDlgItem,
        GetMessageW, GetWindowTextLengthW, GetWindowTextW, HMENU, IDC_ARROW, LoadCursorW,
        MB_ICONINFORMATION, MB_OK, MINMAXINFO, MSG, MessageBoxW, MoveWindow, PostQuitMessage,
        RegisterClassW, SW_SHOWNORMAL, SendMessageW, SetTimer, SetWindowLongPtrW, SetWindowTextW,
        ShowWindow, TranslateMessage, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_DESTROY,
        WM_GETMINMAXINFO, WM_SIZE, WM_TIMER, WNDCLASSW, WS_BORDER, WS_CHILD, WS_OVERLAPPEDWINDOW,
        WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
    };

    const BST_CHECKED: isize = 1;
    const COLOR_WINDOW: u32 = 5;
    const EM_SETSEL: u32 = 0x00B1;
    const EM_REPLACESEL: u32 = 0x00C2;

    const ID_SOCKS: i32 = 101;
    const ID_DNS: i32 = 102;
    const ID_QUIC: i32 = 103;
    const ID_TCP_ONLY: i32 = 104;
    const ID_NO_RECONNECT: i32 = 105;
    const ID_PROXY_LOCAL_NETWORKS: i32 = 111;
    const ID_BYPASS_PROCESS: i32 = 106;
    const ID_BYPASS_IP: i32 = 107;
    const ID_BYPASS_DOMAIN: i32 = 108;
    const ID_BYPASS_PORT: i32 = 109;
    const ID_START: i32 = 201;
    const ID_STOP: i32 = 202;
    const ID_DOCTOR: i32 = 203;
    const ID_LIVE_TEST: i32 = 204;
    const ID_RESET: i32 = 205;
    const ID_GUIDE: i32 = 206;
    const ID_SAVE_PROFILE: i32 = 207;
    const ID_OPEN_RUNTIME: i32 = 208;
    const ID_CONNECTIONS: i32 = 209;
    const ID_STATUS: i32 = 301;
    const ID_LOG: i32 = 302;
    const ID_GROUP_CONNECTION: i32 = 401;
    const ID_GROUP_ROUTING: i32 = 402;
    const ID_GROUP_EXCEPTIONS: i32 = 403;
    const ID_GROUP_ACTIONS: i32 = 404;
    const ID_GROUP_LOG: i32 = 405;
    const ID_GROUP_RULES: i32 = 406;
    const ID_LABEL_SOCKS: i32 = 501;
    const ID_LABEL_SOCKS_HINT: i32 = 502;
    const ID_LABEL_BYPASS_APPS: i32 = 503;
    const ID_LABEL_BYPASS_CIDRS: i32 = 504;
    const ID_LABEL_APPS_HINT: i32 = 505;
    const ID_LABEL_CIDRS_HINT: i32 = 506;
    const ID_LABEL_STATUS: i32 = 507;
    const ID_LABEL_ROUTING_HINT: i32 = 508;
    const ID_LABEL_BYPASS_DOMAINS: i32 = 509;
    const ID_LABEL_BYPASS_PORTS: i32 = 510;
    const ID_LABEL_DOMAINS_HINT: i32 = 511;
    const ID_LABEL_PORTS_HINT: i32 = 512;
    const ID_LABEL_RULES: i32 = 513;
    const ID_LABEL_RULES_HINT: i32 = 514;
    const ID_RULES: i32 = 110;
    const TIMER_ID: usize = 1;

    enum GuiMessage {
        Log(String),
        Started,
        Ready,
        Exited {
            pid: u32,
            code: i32,
        },
        CommandFinished {
            label: String,
            code: i32,
            pid: Option<u32>,
        },
    }

    struct AppState {
        cli_exe: PathBuf,
        runtime_home: PathBuf,
        tx: Sender<GuiMessage>,
        rx: Receiver<GuiMessage>,
        running: bool,
        stopping: bool,
        one_shot_running: bool,
        profile_options: GuiOptions,
        stop_tx: Option<Sender<()>>,
        active_cli_pid: Option<u32>,
        active_diagnostic_pid: Option<u32>,
    }

    pub fn run() -> Result<()> {
        unsafe {
            let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        }
        if !is_elevated() {
            relaunch_as_admin()?;
            return Ok(());
        }

        let gui_exe = std::env::current_exe().context("finding GUI executable")?;
        let cli_exe = cli_exe_for_gui_exe(&gui_exe);
        let runtime_home = runtime_home_for_gui_exe(&gui_exe);
        let initial_options = load_profile(&runtime_home);
        if !cli_exe.is_file() {
            bail!(
                "Could not find CLI engine controller next to GUI: {}",
                cli_exe.display()
            );
        }

        unsafe {
            let instance = GetModuleHandleW(null());
            let class_name = wide("ProxyBridgeRsGui");
            let window_class = WNDCLASSW {
                style: 0,
                lpfnWndProc: Some(window_proc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: instance,
                hIcon: null_mut(),
                hCursor: LoadCursorW(null_mut(), IDC_ARROW),
                hbrBackground: (COLOR_WINDOW + 1) as HBRUSH,
                lpszMenuName: null(),
                lpszClassName: class_name.as_ptr(),
            };
            if RegisterClassW(&window_class) == 0 {
                bail!("RegisterClassW failed");
            }

            let title = wide("ProxyBridge RS");
            let hwnd = CreateWindowExW(
                0,
                class_name.as_ptr(),
                title.as_ptr(),
                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                1000,
                1020,
                null_mut(),
                null_mut(),
                instance,
                null_mut(),
            );
            if hwnd.is_null() {
                bail!("CreateWindowExW failed");
            }

            create_controls(hwnd, instance, &initial_options);
            let (tx, rx) = mpsc::channel();
            let expected_engine = runtime_home
                .join("engine")
                .join(format!("sing-box-{SING_BOX_VERSION}"))
                .join("sing-box.exe");
            let state = Box::new(AppState {
                cli_exe,
                runtime_home,
                tx: tx.clone(),
                rx,
                running: false,
                stopping: false,
                one_shot_running: false,
                profile_options: initial_options.clone(),
                stop_tx: None,
                active_cli_pid: None,
                active_diagnostic_pid: None,
            });
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(state) as isize);
            SetTimer(hwnd, TIMER_ID, 200, None);
            set_status(hwnd, "Ready");
            append_log(hwnd, "ProxyBridge RS GUI ready.");
            append_log(
                hwnd,
                "Use Doctor first if you want a preflight, then Start.",
            );
            append_log(
                hwnd,
                "Built-in direct: localhost/127.0.0.1/::1 plus v2rayN.exe, v2ray.exe, xray.exe, sing-box.exe, and ProxyBridge RS.",
            );
            append_log(
                hwnd,
                "Settings are saved in the runtime profile. Use Guide for examples and mode advice.",
            );
            let stale_engines = find_running_owned_engines(&expected_engine);
            if !stale_engines.is_empty() {
                append_log(
                    hwnd,
                    "An owned sing-box engine is already running. Use Stop to clean it before starting a new session.",
                );
            }

            ShowWindow(hwnd, SW_SHOWNORMAL);

            let mut message: MSG = std::mem::zeroed();
            while GetMessageW(&mut message, null_mut(), 0, 0) > 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }

        Ok(())
    }

    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_CREATE => 0,
            WM_COMMAND => {
                let id = loword(wparam) as i32;
                handle_command(hwnd, id);
                0
            }
            WM_TIMER => {
                drain_messages(hwnd);
                0
            }
            WM_GETMINMAXINFO => {
                let info = lparam as *mut MINMAXINFO;
                if !info.is_null() {
                    (*info).ptMinTrackSize.x = 920;
                    (*info).ptMinTrackSize.y = 1000;
                }
                0
            }
            WM_SIZE => {
                layout_controls(hwnd);
                0
            }
            WM_CLOSE => {
                save_current_profile(hwnd);
                let should_stop = state_mut(hwnd)
                    .map(|state| state.running || state.stopping || state.one_shot_running)
                    .unwrap_or(false);
                if should_stop {
                    request_stop_sync(hwnd);
                }
                DestroyWindow(hwnd);
                0
            }
            WM_DESTROY => {
                let ptr = SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) as *mut AppState;
                if !ptr.is_null() {
                    drop(Box::from_raw(ptr));
                }
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    unsafe fn create_controls(hwnd: HWND, instance: HINSTANCE, options: &GuiOptions) {
        group_box(hwnd, instance, ID_GROUP_CONNECTION, "Connection");
        group_box(hwnd, instance, ID_GROUP_ROUTING, "Routing policy");
        group_box(hwnd, instance, ID_GROUP_EXCEPTIONS, "Direct exceptions");
        group_box(hwnd, instance, ID_GROUP_RULES, "Ordered rules");
        group_box(hwnd, instance, ID_GROUP_ACTIONS, "Actions");
        group_box(hwnd, instance, ID_GROUP_LOG, "Runtime log");

        label(hwnd, instance, ID_LABEL_SOCKS, "SOCKS endpoint", 0, 0, 0, 0);
        edit(hwnd, instance, ID_SOCKS, &options.socks, 0, 0, 0, 0, false);
        label(
            hwnd,
            instance,
            ID_LABEL_SOCKS_HINT,
            "Example: 127.0.0.1:10808",
            0,
            0,
            0,
            0,
        );

        checkbox(hwnd, instance, ID_DNS, "DNS via proxy", 0, 0, 0, 0);
        checkbox(hwnd, instance, ID_QUIC, "Allow QUIC / HTTP3", 0, 0, 0, 0);
        checkbox(hwnd, instance, ID_TCP_ONLY, "TCP-only mode", 0, 0, 0, 0);
        checkbox(
            hwnd,
            instance,
            ID_NO_RECONNECT,
            "Do not reconnect existing apps",
            0,
            0,
            0,
            0,
        );
        checkbox(
            hwnd,
            instance,
            ID_PROXY_LOCAL_NETWORKS,
            "Proxy local networks",
            0,
            0,
            0,
            0,
        );
        set_checkbox_checked(GetDlgItem(hwnd, ID_DNS), options.dns_via_proxy);
        set_checkbox_checked(GetDlgItem(hwnd, ID_QUIC), options.allow_quic);
        set_checkbox_checked(GetDlgItem(hwnd, ID_TCP_ONLY), options.allow_tcp_only);
        set_checkbox_checked(GetDlgItem(hwnd, ID_NO_RECONNECT), options.no_reconnect_apps);
        set_checkbox_checked(
            GetDlgItem(hwnd, ID_PROXY_LOCAL_NETWORKS),
            options.proxy_local_networks,
        );
        label(
            hwnd,
            instance,
            ID_LABEL_ROUTING_HINT,
            "TCP-only for no UDP relay. DNS via proxy is advanced. Local LAN stays direct unless enabled.",
            0,
            0,
            0,
            0,
        );

        label(
            hwnd,
            instance,
            ID_LABEL_BYPASS_APPS,
            "Bypass apps",
            0,
            0,
            0,
            0,
        );
        edit(
            hwnd,
            instance,
            ID_BYPASS_PROCESS,
            &options.bypass_processes.join(", "),
            0,
            0,
            0,
            0,
            false,
        );
        label(
            hwnd,
            instance,
            ID_LABEL_BYPASS_CIDRS,
            "Bypass CIDRs",
            0,
            0,
            0,
            0,
        );
        edit(
            hwnd,
            instance,
            ID_BYPASS_IP,
            &options.bypass_ips.join(", "),
            0,
            0,
            0,
            0,
            false,
        );
        label(
            hwnd,
            instance,
            ID_LABEL_APPS_HINT,
            "Apps: executable names only, comma-separated",
            0,
            0,
            0,
            0,
        );
        label(
            hwnd,
            instance,
            ID_LABEL_CIDRS_HINT,
            "CIDRs: network/prefix, e.g. 192.168.1.0/24",
            0,
            0,
            0,
            0,
        );
        label(
            hwnd,
            instance,
            ID_LABEL_BYPASS_DOMAINS,
            "Direct domains",
            0,
            0,
            0,
            0,
        );
        edit(
            hwnd,
            instance,
            ID_BYPASS_DOMAIN,
            &options.bypass_domains.join(", "),
            0,
            0,
            0,
            0,
            false,
        );
        label(
            hwnd,
            instance,
            ID_LABEL_BYPASS_PORTS,
            "Direct ports",
            0,
            0,
            0,
            0,
        );
        edit(
            hwnd,
            instance,
            ID_BYPASS_PORT,
            &options.bypass_ports.join(", "),
            0,
            0,
            0,
            0,
            false,
        );
        label(
            hwnd,
            instance,
            ID_LABEL_DOMAINS_HINT,
            "Domains: example.com or .example.com",
            0,
            0,
            0,
            0,
        );
        label(
            hwnd,
            instance,
            ID_LABEL_PORTS_HINT,
            "Ports: 443 or 8000:8100",
            0,
            0,
            0,
            0,
        );
        label(
            hwnd,
            instance,
            ID_LABEL_RULES,
            "First matching rule wins. Built-in loopback and proxy-engine bypasses always stay first.",
            0,
            0,
            0,
            0,
        );
        edit(
            hwnd,
            instance,
            ID_RULES,
            &options.rules.join("\r\n"),
            0,
            0,
            0,
            0,
            false,
        );
        label(
            hwnd,
            instance,
            ID_LABEL_RULES_HINT,
            "Example: block domain=ads.example.com    direct process=game.exe    proxy port=443",
            0,
            0,
            0,
            0,
        );

        button(hwnd, instance, ID_START, "Start", 0, 0, 0, 0);
        button(hwnd, instance, ID_STOP, "Stop", 0, 0, 0, 0);
        button(hwnd, instance, ID_DOCTOR, "Doctor", 0, 0, 0, 0);
        button(hwnd, instance, ID_LIVE_TEST, "Live test", 0, 0, 0, 0);
        button(hwnd, instance, ID_CONNECTIONS, "Connections", 0, 0, 0, 0);
        button(hwnd, instance, ID_RESET, "Reconnect", 0, 0, 0, 0);
        button(hwnd, instance, ID_SAVE_PROFILE, "Save profile", 0, 0, 0, 0);
        button(hwnd, instance, ID_GUIDE, "Guide", 0, 0, 0, 0);
        button(hwnd, instance, ID_OPEN_RUNTIME, "Folder", 0, 0, 0, 0);

        label(hwnd, instance, ID_LABEL_STATUS, "Status", 0, 0, 0, 0);
        edit(hwnd, instance, ID_STATUS, "Ready", 0, 0, 0, 0, true);
        edit(hwnd, instance, ID_LOG, "", 0, 0, 0, 0, true);
        layout_controls(hwnd);
    }

    unsafe fn layout_controls(hwnd: HWND) {
        let mut rect = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        if GetClientRect(hwnd, &mut rect) == 0 {
            return;
        }

        let width = (rect.right - rect.left).max(760);
        let height = (rect.bottom - rect.top).max(1000);
        let inner_width = width - 24;
        let log_height = (height - 760).max(140);

        move_control(hwnd, ID_GROUP_CONNECTION, 12, 8, inner_width, 94);
        move_control(hwnd, ID_GROUP_ROUTING, 12, 110, inner_width, 126);
        move_control(hwnd, ID_GROUP_EXCEPTIONS, 12, 244, inner_width, 184);
        move_control(hwnd, ID_GROUP_RULES, 12, 436, inner_width, 138);
        move_control(hwnd, ID_GROUP_ACTIONS, 12, 582, inner_width, 70);
        move_control(hwnd, ID_GROUP_LOG, 12, 696, inner_width, log_height + 38);

        move_control(hwnd, ID_LABEL_SOCKS, 28, 37, 105, 22);
        move_control(hwnd, ID_SOCKS, 140, 33, 275, 26);
        move_control(hwnd, ID_LABEL_SOCKS_HINT, 430, 37, width - 458, 22);

        move_control(hwnd, ID_DNS, 28, 138, 145, 24);
        move_control(hwnd, ID_TCP_ONLY, 190, 138, 145, 24);
        move_control(hwnd, ID_QUIC, 350, 138, 175, 24);
        move_control(hwnd, ID_NO_RECONNECT, 540, 138, width - 568, 24);
        move_control(hwnd, ID_PROXY_LOCAL_NETWORKS, 28, 172, 220, 24);
        move_control(hwnd, ID_LABEL_ROUTING_HINT, 260, 172, width - 288, 42);

        let split = width / 2;
        move_control(hwnd, ID_LABEL_BYPASS_APPS, 28, 272, 105, 22);
        move_control(hwnd, ID_BYPASS_PROCESS, 140, 268, split - 160, 26);
        move_control(hwnd, ID_LABEL_BYPASS_CIDRS, split + 8, 272, 95, 22);
        move_control(
            hwnd,
            ID_BYPASS_IP,
            split + 110,
            268,
            width - split - 134,
            26,
        );
        move_control(hwnd, ID_LABEL_APPS_HINT, 28, 302, split - 42, 22);
        move_control(
            hwnd,
            ID_LABEL_CIDRS_HINT,
            split + 8,
            302,
            width - split - 32,
            22,
        );
        move_control(hwnd, ID_LABEL_BYPASS_DOMAINS, 28, 334, 105, 22);
        move_control(hwnd, ID_BYPASS_DOMAIN, 140, 330, split - 160, 26);
        move_control(hwnd, ID_LABEL_BYPASS_PORTS, split + 8, 334, 95, 22);
        move_control(
            hwnd,
            ID_BYPASS_PORT,
            split + 110,
            330,
            width - split - 134,
            26,
        );
        move_control(hwnd, ID_LABEL_DOMAINS_HINT, 28, 364, split - 42, 22);
        move_control(
            hwnd,
            ID_LABEL_PORTS_HINT,
            split + 8,
            364,
            width - split - 32,
            22,
        );
        move_control(hwnd, ID_LABEL_RULES, 28, 458, width - 56, 22);
        move_control(hwnd, ID_RULES, 28, 482, width - 56, 68);
        move_control(hwnd, ID_LABEL_RULES_HINT, 28, 552, width - 56, 22);

        let button_width = ((width - 44 - (9 * 6)) / 9).max(72);
        for (index, id) in [
            ID_START,
            ID_STOP,
            ID_DOCTOR,
            ID_LIVE_TEST,
            ID_CONNECTIONS,
            ID_RESET,
            ID_SAVE_PROFILE,
            ID_GUIDE,
            ID_OPEN_RUNTIME,
        ]
        .into_iter()
        .enumerate()
        {
            move_control(
                hwnd,
                id,
                22 + (index as i32 * (button_width + 6)),
                598,
                button_width,
                32,
            );
        }

        move_control(hwnd, ID_LABEL_STATUS, 28, 662, 60, 22);
        move_control(hwnd, ID_STATUS, 96, 658, width - 124, 26);
        move_control(hwnd, ID_LOG, 28, 726, width - 56, log_height);
    }

    unsafe fn move_control(parent: HWND, id: i32, x: i32, y: i32, width: i32, height: i32) {
        let control = GetDlgItem(parent, id);
        if !control.is_null() {
            MoveWindow(control, x, y, width, height, 1);
        }
    }

    unsafe fn handle_command(hwnd: HWND, id: i32) {
        match id {
            ID_QUIC | ID_TCP_ONLY => reconcile_mode_checkboxes(hwnd, id),
            ID_START => start_tunnel(hwnd),
            ID_STOP => request_stop(hwnd),
            ID_DOCTOR => run_one_shot(
                hwnd,
                "Doctor",
                build_cli_args("doctor", &read_options(hwnd)),
            ),
            ID_LIVE_TEST => run_one_shot(
                hwnd,
                "Live Test",
                build_cli_args("smoke-test", &read_options(hwnd)),
            ),
            ID_CONNECTIONS => run_one_shot(hwnd, "Connections", vec!["connections".to_string()]),
            ID_RESET => run_one_shot(hwnd, "Reset Apps", vec!["reset-browsers".to_string()]),
            ID_SAVE_PROFILE => save_current_profile(hwnd),
            ID_GUIDE => show_guide(hwnd),
            ID_OPEN_RUNTIME => open_runtime_folder(hwnd),
            _ => {}
        }
    }

    unsafe fn start_tunnel(hwnd: HWND) {
        let already_active = state_mut(hwnd)
            .map(|state| state.running || state.stopping)
            .unwrap_or(false);
        if already_active {
            append_log(
                hwnd,
                "Tunnel is already running or stopping; wait for the current session to finish.",
            );
            return;
        }

        let options = read_options(hwnd);
        let Some(state) = state_mut(hwnd) else {
            return;
        };
        if let Err(error) = save_profile(&state.runtime_home, &options) {
            append_log(hwnd, &format!("Could not save GUI profile: {error}"));
        } else {
            state.profile_options = options.clone();
        }
        let args = build_cli_args("run", &options);
        let cli = state.cli_exe.clone();
        let runtime_home = state.runtime_home.clone();
        let tx = state.tx.clone();
        append_log(
            hwnd,
            &format!("Starting: {} {}", cli.display(), args.join(" ")),
        );
        set_status(hwnd, "Starting tunnel...");

        match Command::new(&cli)
            .args(&args)
            .env("PROXYBRIDGE_RS_HOME", &runtime_home)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                let active_cli_pid = child.id();
                let (stop_tx, stop_rx) = mpsc::channel();
                state.running = true;
                state.stop_tx = Some(stop_tx);
                state.active_cli_pid = Some(active_cli_pid);
                let _ = tx.send(GuiMessage::Started);
                if let Some(stdout) = child.stdout.take() {
                    spawn_reader(stdout, tx.clone());
                }
                if let Some(stderr) = child.stderr.take() {
                    spawn_reader(stderr, tx.clone());
                }
                thread::spawn(move || {
                    let code = loop {
                        if stop_rx.try_recv().is_ok() {
                            let _ = child.kill();
                            break child
                                .wait()
                                .ok()
                                .and_then(|status| status.code())
                                .unwrap_or(-1);
                        }
                        match child.try_wait() {
                            Ok(Some(status)) => break status.code().unwrap_or(-1),
                            Ok(None) => thread::sleep(std::time::Duration::from_millis(100)),
                            Err(_) => break -1,
                        }
                    };
                    let _ = tx.send(GuiMessage::Exited {
                        pid: active_cli_pid,
                        code,
                    });
                });
            }
            Err(error) => {
                append_log(hwnd, &format!("Start failed: {error}"));
                set_status(hwnd, "Start failed");
            }
        }
    }

    unsafe fn request_stop(hwnd: HWND) {
        let Some(state) = state_mut(hwnd) else {
            return;
        };
        if state.stopping {
            append_log(hwnd, "Tunnel stop is already in progress.");
            return;
        }
        state.stopping = true;
        if let Some(stop_tx) = &state.stop_tx {
            let _ = stop_tx.send(());
            append_log(hwnd, "Stop requested; terminating the active controller...");
            set_status(hwnd, "Stopping tunnel...");
            return;
        }

        if !state.running {
            append_log(
                hwnd,
                "No active GUI session; checking for a stale owned tunnel.",
            );
        }
        let cli = state.cli_exe.clone();
        let runtime_home = state.runtime_home.clone();
        let tx = state.tx.clone();
        set_status(hwnd, "Stopping tunnel...");
        thread::spawn(move || {
            let output = run_stop_command(&cli, &runtime_home);
            send_output(tx, "Stop", None, output);
        });
    }

    unsafe fn request_stop_sync(hwnd: HWND) {
        let Some(state) = state_mut(hwnd) else {
            return;
        };
        if state.stopping {
            append_log(hwnd, "Stopping tunnel before exit...");
        } else {
            state.stopping = true;
            if let Some(stop_tx) = &state.stop_tx {
                let _ = stop_tx.send(());
            }
        }

        set_status(hwnd, "Stopping tunnel...");
        if let Some(pid) = state.active_diagnostic_pid {
            match kill_process_tree(pid) {
                Ok(output) if output.status.success() => append_log(
                    hwnd,
                    &format!("Stopped diagnostic process tree (pid={pid})."),
                ),
                Ok(output) => append_log(
                    hwnd,
                    &format!(
                        "Diagnostic cleanup returned code {} (pid={pid}).",
                        output.status.code().unwrap_or(-1)
                    ),
                ),
                Err(error) => append_log(hwnd, &format!("Diagnostic cleanup failed: {error}")),
            }
            state.active_diagnostic_pid = None;
            state.one_shot_running = false;
        }
        if let Some(pid) = state.active_cli_pid {
            match kill_process_tree(pid) {
                Ok(output) if output.status.success() => {
                    append_log(
                        hwnd,
                        &format!("Stopped controller process tree (pid={pid})."),
                    );
                }
                Ok(output) => append_log(
                    hwnd,
                    &format!(
                        "Controller cleanup returned code {} (pid={pid}).",
                        output.status.code().unwrap_or(-1)
                    ),
                ),
                Err(error) => append_log(hwnd, &format!("Controller cleanup failed: {error}")),
            }
        }
        match run_stop_command(&state.cli_exe, &state.runtime_home) {
            Ok(output) => {
                append_log(
                    hwnd,
                    &format!(
                        "Stop before exit returned code {}",
                        output.status.code().unwrap_or(-1)
                    ),
                );
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                for line in stdout.lines().chain(stderr.lines()) {
                    append_log(hwnd, line);
                }
            }
            Err(error) => append_log(hwnd, &format!("Stop before exit failed: {error}")),
        }
        state.running = false;
        state.stopping = false;
        state.stop_tx = None;
        state.active_cli_pid = None;
    }

    unsafe fn run_one_shot(hwnd: HWND, label: &str, args: Vec<String>) {
        let Some(state) = state_mut(hwnd) else {
            return;
        };
        if state.one_shot_running {
            append_log(hwnd, "Another diagnostic command is already running.");
            return;
        }
        if label == "Live Test" && state.running {
            append_log(hwnd, "Stop the active tunnel before running Live Test.");
            return;
        }
        state.one_shot_running = true;
        let cli = state.cli_exe.clone();
        let runtime_home = state.runtime_home.clone();
        let tx = state.tx.clone();
        append_log(
            hwnd,
            &format!("{label}: {} {}", cli.display(), args.join(" ")),
        );
        set_status(hwnd, &format!("{label} running..."));
        let label = label.to_string();
        match Command::new(&cli)
            .args(&args)
            .env("PROXYBRIDGE_RS_HOME", &runtime_home)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => {
                let pid = child.id();
                state.active_diagnostic_pid = Some(pid);
                thread::spawn(move || {
                    send_output(tx, &label, Some(pid), child.wait_with_output());
                });
            }
            Err(error) => {
                state.one_shot_running = false;
                append_log(hwnd, &format!("{label} failed to start: {error}"));
                set_status(hwnd, &format!("{label} failed"));
            }
        }
    }

    fn spawn_reader<R: Read + Send + 'static>(reader: R, tx: Sender<GuiMessage>) {
        thread::spawn(move || {
            for line in BufReader::new(reader).lines().map_while(Result::ok) {
                if line.contains("ProxyBridgeRS TUN routes are ready") {
                    let _ = tx.send(GuiMessage::Ready);
                }
                let _ = tx.send(GuiMessage::Log(line));
            }
        });
    }

    fn send_output(
        tx: Sender<GuiMessage>,
        label: &str,
        pid: Option<u32>,
        output: std::io::Result<std::process::Output>,
    ) {
        match output {
            Ok(output) => {
                let code = output.status.code().unwrap_or(-1);
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                let _ = tx.send(GuiMessage::Log(format!("{label} exited with code {code}")));
                for line in stdout.lines().chain(stderr.lines()) {
                    let _ = tx.send(GuiMessage::Log(line.to_string()));
                }
                let _ = tx.send(GuiMessage::CommandFinished {
                    label: label.to_string(),
                    code,
                    pid,
                });
            }
            Err(error) => {
                let _ = tx.send(GuiMessage::Log(format!("{label} failed: {error}")));
                let _ = tx.send(GuiMessage::CommandFinished {
                    label: label.to_string(),
                    code: -1,
                    pid,
                });
            }
        }
    }

    fn run_stop_command(
        cli: &std::path::Path,
        runtime_home: &std::path::Path,
    ) -> std::io::Result<std::process::Output> {
        Command::new(cli)
            .args(build_path_args("stop"))
            .env("PROXYBRIDGE_RS_HOME", runtime_home)
            .output()
    }

    fn kill_process_tree(pid: u32) -> std::io::Result<std::process::Output> {
        Command::new("taskkill.exe")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .output()
    }

    unsafe fn drain_messages(hwnd: HWND) {
        let Some(state) = state_mut(hwnd) else {
            return;
        };
        while let Ok(message) = state.rx.try_recv() {
            match message {
                GuiMessage::Log(line) => append_log(hwnd, &line),
                GuiMessage::Started => set_status(hwnd, "Tunnel process running; watch log"),
                GuiMessage::Ready => set_status(hwnd, "Tunnel ready; traffic capture is active"),
                GuiMessage::Exited { pid, code } => {
                    if state.active_cli_pid == Some(pid) {
                        state.running = false;
                        state.stopping = false;
                        state.stop_tx = None;
                        state.active_cli_pid = None;
                        set_status(hwnd, &format!("Tunnel stopped: exit code {code}"));
                        append_log(hwnd, &format!("Tunnel process exited with code {code}"));
                    } else {
                        append_log(
                            hwnd,
                            &format!("Ignored stale tunnel exit notification for pid {pid}"),
                        );
                    }
                }
                GuiMessage::CommandFinished { label, code, pid } => {
                    if label == "Stop" && code == 0 {
                        state.running = false;
                    }
                    if label == "Stop" {
                        state.stopping = false;
                        set_status(hwnd, &format!("{label} finished: exit code {code}"));
                    } else if state.active_diagnostic_pid == pid {
                        state.one_shot_running = false;
                        state.active_diagnostic_pid = None;
                        set_status(hwnd, &format!("{label} finished: exit code {code}"));
                    }
                }
            }
        }
    }

    unsafe fn reconcile_mode_checkboxes(hwnd: HWND, changed_id: i32) {
        if changed_id == ID_QUIC && checkbox_checked(GetDlgItem(hwnd, ID_QUIC)) {
            set_checkbox_checked(GetDlgItem(hwnd, ID_TCP_ONLY), false);
        } else if changed_id == ID_TCP_ONLY && checkbox_checked(GetDlgItem(hwnd, ID_TCP_ONLY)) {
            set_checkbox_checked(GetDlgItem(hwnd, ID_QUIC), false);
        }
    }

    unsafe fn read_options(hwnd: HWND) -> GuiOptions {
        let profile = state_mut(hwnd)
            .map(|state| state.profile_options.clone())
            .unwrap_or_default();
        GuiOptions {
            socks: control_text(GetDlgItem(hwnd, ID_SOCKS)),
            dns_via_proxy: checkbox_checked(GetDlgItem(hwnd, ID_DNS)),
            allow_quic: checkbox_checked(GetDlgItem(hwnd, ID_QUIC)),
            no_reconnect_apps: checkbox_checked(GetDlgItem(hwnd, ID_NO_RECONNECT)),
            allow_tcp_only: checkbox_checked(GetDlgItem(hwnd, ID_TCP_ONLY)),
            proxy_local_networks: checkbox_checked(GetDlgItem(hwnd, ID_PROXY_LOCAL_NETWORKS)),
            bypass_processes: split_csv(control_text(GetDlgItem(hwnd, ID_BYPASS_PROCESS))),
            bypass_ips: split_csv(control_text(GetDlgItem(hwnd, ID_BYPASS_IP))),
            bypass_domains: split_csv(control_text(GetDlgItem(hwnd, ID_BYPASS_DOMAIN))),
            bypass_ports: split_csv(control_text(GetDlgItem(hwnd, ID_BYPASS_PORT))),
            rules: split_lines(control_text(GetDlgItem(hwnd, ID_RULES))),
            log_level: profile.log_level,
            smoke_iterations: profile.smoke_iterations,
        }
    }

    fn split_csv(value: String) -> Vec<String> {
        value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(String::from)
            .collect()
    }

    fn split_lines(value: String) -> Vec<String> {
        value
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(String::from)
            .collect()
    }

    unsafe fn save_current_profile(hwnd: HWND) {
        let options = read_options(hwnd);
        let Some(runtime_home) = state_mut(hwnd).map(|state| state.runtime_home.clone()) else {
            return;
        };
        match save_profile(&runtime_home, &options) {
            Ok(()) => {
                if let Some(state) = state_mut(hwnd) {
                    state.profile_options = options.clone();
                }
                append_log(hwnd, "GUI profile saved.");
                set_status(hwnd, "Profile saved");
            }
            Err(error) => {
                append_log(hwnd, &format!("Profile save failed: {error}"));
                set_status(hwnd, "Profile save failed");
            }
        }
    }

    unsafe fn show_guide(hwnd: HWND) {
        let text = concat!(
            "ProxyBridge RS quick guide\n\n",
            "SOCKS endpoint\n",
            "Write host:port. For your v2rayN setup use 127.0.0.1:10808. Do not write a URL, scheme, or spaces.\n\n",
            "Bypass apps\n",
            "Write executable file names only, separated by commas. Examples: xray.exe, v2rayN.exe, game.exe.\n",
            "Do not write a full path. Find the name in Task Manager > Details. Built-in proxy-engine and loopback bypasses are always included.\n\n",
            "Bypass CIDRs\n",
            "Write an IP network followed by a prefix length. Examples: 192.168.1.0/24 for a LAN, 10.0.0.0/8 for a private network, or 192.168.1.25/32 for one IPv4 address.\n",
            "IPv6 examples: fd00::/8 for a private IPv6 range or 2001:db8::1/128 for one address. Do not write a bare IP.\n\n",
            "Local networks\n",
            "Private LAN ranges stay direct by default so printers, VMs, WSL, and local services keep working. Enable Proxy local networks only when you intentionally want those destinations captured.\n\n",
            "Direct domains and ports\n",
            "Domains may be exact (example.com) or suffixes (.example.com or *.example.com). Ports may be a number (443) or an inclusive range (8000:8100).\n\n",
            "Ordered rules\n",
            "Write one rule per line. The action is proxy, direct, or block, followed by process=, ip=, domain=, port=, or network=. Examples: block domain=ads.example.com; direct process=game.exe; block network=udp.\n",
            "The first matching user rule wins. Blank lines and lines beginning with # are ignored.\n\n",
            "Modes\n",
            "TCP-only is the stable choice when Doctor reports no SOCKS5 UDP relay. It blocks remaining UDP instead of leaking it.\n",
            "Enable DNS via proxy only when your upstream supports it reliably. Allow QUIC/HTTP3 only when UDP relay is proven.\n\n",
            "Connections\n",
            "While the tunnel runs, the Connections button shows the live connection table: process, destination, matched rule, outbound, and per-connection traffic, plus session totals.\n\n",
            "Workflow\n",
            "1. Start v2rayN and leave its SOCKS listener enabled.\n",
            "2. Turn off v2rayN system proxy mode if you want ProxyBridge RS to own routing.\n",
            "3. Run Doctor, then Start. Stop restores the machine when you are done."
        );
        MessageBoxW(
            hwnd,
            wide(text).as_ptr(),
            wide("ProxyBridge RS Guide").as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
    }

    unsafe fn open_runtime_folder(hwnd: HWND) {
        let Some(state) = state_mut(hwnd) else {
            return;
        };
        if let Err(error) = std::fs::create_dir_all(&state.runtime_home) {
            append_log(hwnd, &format!("Could not create runtime folder: {error}"));
            return;
        }
        let operation = wide("open");
        let folder = wide(&state.runtime_home);
        let result = ShellExecuteW(
            hwnd,
            operation.as_ptr(),
            folder.as_ptr(),
            null(),
            null(),
            SW_SHOWNORMAL,
        );
        if result as isize <= 32 {
            append_log(
                hwnd,
                &format!("Could not open runtime folder (ShellExecuteW {result:?})"),
            );
        }
    }

    unsafe fn state_mut(hwnd: HWND) -> Option<&'static mut AppState> {
        let ptr =
            windows_sys::Win32::UI::WindowsAndMessaging::GetWindowLongPtrW(hwnd, GWLP_USERDATA)
                as *mut AppState;
        ptr.as_mut()
    }

    unsafe fn append_log(hwnd: HWND, line: &str) {
        let log = GetDlgItem(hwnd, ID_LOG);
        let text = format!("{line}\r\n");
        let text_wide = wide(&text);
        SendMessageW(log, EM_SETSEL, usize::MAX, -1isize);
        SendMessageW(log, EM_REPLACESEL, 0, text_wide.as_ptr() as isize);

        const MAX_LOG_CHARS: i32 = 200_000;
        let length = GetWindowTextLengthW(log);
        if length > MAX_LOG_CHARS {
            let remove = length - MAX_LOG_CHARS;
            SendMessageW(log, EM_SETSEL, 0, remove as isize);
            SendMessageW(log, EM_REPLACESEL, 0, wide("").as_ptr() as isize);
        }
    }

    unsafe fn set_status(hwnd: HWND, text: &str) {
        SetWindowTextW(GetDlgItem(hwnd, ID_STATUS), wide(text).as_ptr());
    }

    unsafe fn control_text(hwnd: HWND) -> String {
        let length = GetWindowTextLengthW(hwnd);
        let mut buffer = vec![0u16; length as usize + 1];
        GetWindowTextW(hwnd, buffer.as_mut_ptr(), buffer.len() as i32);
        String::from_utf16_lossy(&buffer[..length as usize])
    }

    unsafe fn checkbox_checked(hwnd: HWND) -> bool {
        SendMessageW(hwnd, BM_GETCHECK, 0, 0) == BST_CHECKED
    }

    unsafe fn set_checkbox_checked(hwnd: HWND, checked: bool) {
        SendMessageW(
            hwnd,
            BM_SETCHECK,
            if checked { BST_CHECKED as usize } else { 0 },
            0,
        );
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn label(
        parent: HWND,
        instance: HINSTANCE,
        id: i32,
        text: &str,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    ) {
        create_control(parent, instance, "STATIC", text, 0, x, y, width, height, id);
    }

    unsafe fn group_box(parent: HWND, instance: HINSTANCE, id: i32, text: &str) {
        create_control(
            parent,
            instance,
            "BUTTON",
            text,
            BS_GROUPBOX as u32,
            0,
            0,
            0,
            0,
            id,
        );
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn button(
        parent: HWND,
        instance: HINSTANCE,
        id: i32,
        text: &str,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    ) {
        create_control(
            parent, instance, "BUTTON", text, WS_TABSTOP, x, y, width, height, id,
        );
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn checkbox(
        parent: HWND,
        instance: HINSTANCE,
        id: i32,
        text: &str,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    ) {
        create_control(
            parent,
            instance,
            "BUTTON",
            text,
            WS_TABSTOP | BS_AUTOCHECKBOX as u32,
            x,
            y,
            width,
            height,
            id,
        );
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn edit(
        parent: HWND,
        instance: HINSTANCE,
        id: i32,
        text: &str,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        readonly: bool,
    ) {
        let mut style = WS_TABSTOP | WS_BORDER;
        if readonly {
            style |= ES_READONLY as u32;
        }
        if id == ID_LOG || id == ID_RULES {
            style |=
                ES_MULTILINE as u32 | ES_AUTOVSCROLL as u32 | ES_WANTRETURN as u32 | WS_VSCROLL;
        } else {
            style |= ES_AUTOHSCROLL as u32;
        }
        create_control(
            parent, instance, "EDIT", text, style, x, y, width, height, id,
        );
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn create_control(
        parent: HWND,
        instance: HINSTANCE,
        class_name: &str,
        text: &str,
        extra_style: u32,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        id: i32,
    ) {
        let class_name = wide(class_name);
        let text = wide(text);
        CreateWindowExW(
            0,
            class_name.as_ptr(),
            text.as_ptr(),
            WS_CHILD | WS_VISIBLE | extra_style,
            x,
            y,
            width,
            height,
            parent,
            id as isize as HMENU,
            instance,
            null_mut(),
        );
    }

    fn relaunch_as_admin() -> Result<()> {
        let exe = std::env::current_exe().context("finding GUI executable")?;
        let operation = wide("runas");
        let file = wide(exe.as_os_str());
        let result = unsafe {
            ShellExecuteW(
                null_mut(),
                operation.as_ptr(),
                file.as_ptr(),
                null(),
                null(),
                SW_SHOWNORMAL,
            )
        };
        if result as isize <= 32 {
            bail!(
                "Administrator relaunch was cancelled or failed with ShellExecuteW code {result:?}"
            );
        }

        Ok(())
    }

    pub fn message_box(title: &str, text: &str) {
        unsafe {
            MessageBoxW(null_mut(), wide(text).as_ptr(), wide(title).as_ptr(), MB_OK);
        }
    }

    fn loword(value: usize) -> u16 {
        (value & 0xffff) as u16
    }

    fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
        value.as_ref().encode_wide().chain(Some(0)).collect()
    }
}
