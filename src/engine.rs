use crate::config::{RuntimeOptions, build_sing_box_config};
use crate::endpoint::SocksEndpoint;
use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use sysinfo::{ProcessesToUpdate, System};
use zip::ZipArchive;

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
#[cfg(windows)]
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::CreateMutexW;

#[cfg(windows)]
pub struct EngineLock {
    handle: HANDLE,
}

#[cfg(not(windows))]
pub struct EngineLock;

#[cfg(windows)]
impl Drop for EngineLock {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Serialize owned TUN controllers across separate CLI and GUI processes.
/// The lock is deliberately global because two instances cannot safely own
/// the same Windows route/interface namespace at the same time.
pub fn acquire_engine_lock() -> Result<EngineLock> {
    #[cfg(windows)]
    {
        let name = std::ffi::OsStr::new("Global\\ProxyBridgeRS-Tunnel")
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let handle = unsafe { CreateMutexW(std::ptr::null(), 1, name.as_ptr()) };
        if handle.is_null() {
            bail!("CreateMutexW failed with Win32 error {}", unsafe {
                GetLastError()
            });
        }
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe {
                let _ = CloseHandle(handle);
            }
            bail!("another ProxyBridge RS tunnel controller is already running");
        }
        Ok(EngineLock { handle })
    }

    #[cfg(not(windows))]
    {
        Ok(EngineLock)
    }
}

#[cfg(windows)]
pub struct ProcessJob {
    handle: HANDLE,
}

#[cfg(not(windows))]
pub struct ProcessJob;

#[cfg(windows)]
impl Drop for ProcessJob {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

#[cfg(windows)]
fn attach_child_to_kill_on_parent_exit(child: &Child) -> Result<ProcessJob> {
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        bail!("CreateJobObjectW failed with Win32 error {}", unsafe {
            GetLastError()
        });
    }

    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let configured = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if configured == 0 {
        unsafe {
            let _ = CloseHandle(job);
        }
        bail!(
            "SetInformationJobObject failed with Win32 error {}",
            unsafe { GetLastError() }
        );
    }

    let assigned = unsafe { AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE) };
    if assigned == 0 {
        unsafe {
            let _ = CloseHandle(job);
        }
        bail!(
            "AssignProcessToJobObject failed with Win32 error {}",
            unsafe { GetLastError() }
        );
    }

    Ok(ProcessJob { handle: job })
}

#[cfg(not(windows))]
fn attach_child_to_kill_on_parent_exit(_child: &Child) -> Result<ProcessJob> {
    Ok(ProcessJob)
}

pub const SING_BOX_VERSION: &str = "1.13.14";
pub const SING_BOX_SHA256: &str =
    "f580782c6dd10f7691c66cea1d7c421813c5fbf7e305d1ee7ce0c3a40d196341";
pub const SING_BOX_EXE_SHA256: &str =
    "db0d779948214cf761011d154c3a5da36df20394fa01a9fc798f1dc39fe9d183";
const SING_BOX_DOWNLOAD_URL: &str = "https://github.com/SagerNet/sing-box/releases/download/v1.13.14/sing-box-1.13.14-windows-amd64.zip";
pub const WINTUN_VERSION: &str = "0.14.1";
pub const WINTUN_SHA256: &str = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";
pub const WINTUN_DLL_SHA256: &str =
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";
const WINTUN_DOWNLOAD_URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";

#[derive(Clone, Debug)]
pub struct EnginePaths {
    pub engine_dir: PathBuf,
    pub config_path: PathBuf,
}

impl EnginePaths {
    pub fn new(engine_dir: Option<PathBuf>, config_path: Option<PathBuf>) -> Result<Self> {
        let data_dir = default_data_dir()?;
        Ok(Self {
            engine_dir: engine_dir.unwrap_or_else(|| {
                data_dir
                    .join("engine")
                    .join(format!("sing-box-{SING_BOX_VERSION}"))
            }),
            config_path: config_path
                .unwrap_or_else(|| data_dir.join("runtime").join("sing-box.json")),
        })
    }

    pub fn sing_box_exe(&self) -> PathBuf {
        self.engine_dir.join("sing-box.exe")
    }

    pub fn wintun_dll(&self) -> PathBuf {
        self.engine_dir.join("wintun.dll")
    }

    pub fn log_dir(&self) -> PathBuf {
        self.config_path
            .parent()
            .unwrap_or(&self.engine_dir)
            .join("logs")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningEngine {
    pub pid: u32,
    pub exe_path: PathBuf,
}

pub fn default_data_dir() -> Result<PathBuf> {
    if let Some(value) = std::env::var_os("PROXYBRIDGE_RS_HOME") {
        return Ok(PathBuf::from(value));
    }

    let base =
        dirs::data_local_dir().context("could not find LOCALAPPDATA; set PROXYBRIDGE_RS_HOME")?;
    Ok(base.join("ProxyBridgeRS"))
}

pub fn ensure_sing_box(paths: &EnginePaths) -> Result<PathBuf> {
    let exe = paths.sing_box_exe();
    if exe.is_file() {
        return Ok(exe);
    }

    fs::create_dir_all(&paths.engine_dir)
        .with_context(|| format!("creating engine dir {}", paths.engine_dir.display()))?;

    let client = Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .context("building downloader")?;
    let mut response = client
        .get(SING_BOX_DOWNLOAD_URL)
        .send()
        .context("downloading sing-box")?;
    if !response.status().is_success() {
        bail!("sing-box download failed with HTTP {}", response.status());
    }

    let mut bytes = Vec::new();
    response
        .read_to_end(&mut bytes)
        .context("reading sing-box archive")?;
    validate_sing_box_archive_hash(&bytes)?;

    let mut archive = ZipArchive::new(Cursor::new(bytes)).context("opening sing-box zip")?;
    let mut extracted_exe = false;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .with_context(|| format!("reading archive entry {index}"))?;
        if file.is_dir() {
            continue;
        }

        let Some(name) = file.enclosed_name() else {
            continue;
        };
        let Some(file_name) = name.file_name() else {
            continue;
        };
        let destination = paths.engine_dir.join(file_name);

        let is_engine_exe = file_name.eq_ignore_ascii_case("sing-box.exe");
        let write_destination = if is_engine_exe {
            let pending = paths.engine_dir.join("sing-box.exe.download");
            if pending.exists() {
                fs::remove_file(&pending)
                    .with_context(|| format!("removing stale {}", pending.display()))?;
            }
            pending
        } else {
            destination.clone()
        };

        let mut out = File::create(&write_destination)
            .with_context(|| format!("creating {}", write_destination.display()))?;
        std::io::copy(&mut file, &mut out)
            .with_context(|| format!("extracting {}", write_destination.display()))?;
        out.flush().ok();
        drop(out);

        if is_engine_exe {
            fs::rename(&write_destination, &destination).with_context(|| {
                format!(
                    "promoting {} to {}",
                    write_destination.display(),
                    destination.display()
                )
            })?;
            extracted_exe = true;
        }
    }

    if !extracted_exe || !exe.is_file() {
        bail!("sing-box archive did not contain sing-box.exe");
    }

    Ok(exe)
}

pub fn ensure_sing_box_ready(paths: &EnginePaths) -> Result<PathBuf> {
    let exe = ensure_sing_box(paths)?;
    validate_sing_box_version(&exe)?;
    validate_sing_box_exe_hash(&exe)?;
    ensure_wintun(paths)?;
    Ok(exe)
}

pub fn ensure_wintun(paths: &EnginePaths) -> Result<PathBuf> {
    let dll = paths.wintun_dll();
    if dll.is_file() {
        validate_wintun_dll_hash(&dll)?;
        return Ok(dll);
    }

    fs::create_dir_all(&paths.engine_dir)
        .with_context(|| format!("creating engine dir {}", paths.engine_dir.display()))?;

    let client = Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .context("building Wintun downloader")?;
    let mut response = client
        .get(WINTUN_DOWNLOAD_URL)
        .send()
        .context("downloading Wintun")?;
    if !response.status().is_success() {
        bail!("Wintun download failed with HTTP {}", response.status());
    }

    let mut bytes = Vec::new();
    response
        .read_to_end(&mut bytes)
        .context("reading Wintun archive")?;
    validate_wintun_archive_hash(&bytes)?;

    let mut archive = ZipArchive::new(Cursor::new(bytes)).context("opening Wintun zip")?;
    let pending = paths.engine_dir.join("wintun.dll.download");
    if pending.exists() {
        fs::remove_file(&pending)
            .with_context(|| format!("removing stale {}", pending.display()))?;
    }

    let mut extracted_dll = false;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .with_context(|| format!("reading Wintun archive entry {index}"))?;
        if file.is_dir() {
            continue;
        }

        let Some(name) = file.enclosed_name() else {
            continue;
        };
        if !wintun_archive_entry_is_amd64_dll(&name) {
            continue;
        }

        let mut out =
            File::create(&pending).with_context(|| format!("creating {}", pending.display()))?;
        std::io::copy(&mut file, &mut out)
            .with_context(|| format!("extracting {}", pending.display()))?;
        out.flush().ok();
        drop(out);
        validate_wintun_dll_hash(&pending)?;
        fs::rename(&pending, &dll)
            .with_context(|| format!("promoting {} to {}", pending.display(), dll.display()))?;
        extracted_dll = true;
        break;
    }

    if !extracted_dll || !dll.is_file() {
        bail!("Wintun archive did not contain bin/amd64/wintun.dll");
    }

    Ok(dll)
}

pub fn validate_wintun_archive_hash(bytes: &[u8]) -> Result<()> {
    let actual = sha256_hex(bytes);
    if actual == WINTUN_SHA256 {
        return Ok(());
    }

    bail!("Wintun archive SHA256 mismatch: expected {WINTUN_SHA256}, got {actual}");
}

pub fn validate_sing_box_archive_hash(bytes: &[u8]) -> Result<()> {
    let actual = sha256_hex(bytes);
    if actual == SING_BOX_SHA256 {
        return Ok(());
    }

    bail!("sing-box archive SHA256 mismatch: expected {SING_BOX_SHA256}, got {actual}");
}

pub fn validate_sing_box_exe_hash(path: &Path) -> Result<()> {
    let bytes = fs::read(path)
        .with_context(|| format!("reading {} for hash validation", path.display()))?;
    let actual = sha256_hex(&bytes);
    if actual == SING_BOX_EXE_SHA256 {
        return Ok(());
    }

    bail!(
        "sing-box executable SHA256 mismatch: expected {SING_BOX_EXE_SHA256}, got {actual} for {}",
        path.display()
    );
}

pub fn validate_wintun_dll_hash(path: &Path) -> Result<()> {
    let bytes = fs::read(path)
        .with_context(|| format!("reading {} for hash validation", path.display()))?;
    let actual = sha256_hex(&bytes);
    if actual == WINTUN_DLL_SHA256 {
        return Ok(());
    }

    bail!(
        "Wintun DLL SHA256 mismatch: expected {WINTUN_DLL_SHA256}, got {actual} for {}",
        path.display()
    );
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn wintun_archive_entry_is_amd64_dll(path: &Path) -> bool {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    normalized.ends_with("/bin/amd64/wintun.dll")
}

pub fn tun_start_failure_hint(stderr: &str, wintun_path: &Path) -> Option<String> {
    let normalized = stderr.to_ascii_lowercase();
    if !normalized.contains("configure tun interface")
        || !normalized.contains("cannot find the file specified")
    {
        return None;
    }

    Some(format!(
        "TUN interface creation failed before proxying started. This usually means Windows could not load the Wintun dependency or driver. Expected wintun.dll at {}. Run ensure-engine/Doctor again, then retry from Administrator PowerShell.",
        wintun_path.display()
    ))
}

pub fn write_runtime_config(paths: &EnginePaths, options: &RuntimeOptions) -> Result<()> {
    let parent = paths
        .config_path
        .parent()
        .context("config path has no parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let config = build_sing_box_config(options);
    let body = serde_json::to_string_pretty(&config).context("serializing sing-box config")?;
    fs::write(&paths.config_path, body)
        .with_context(|| format!("writing {}", paths.config_path.display()))
}

pub fn check_sing_box_config(exe: &Path, config_path: &Path) -> Result<()> {
    let output = Command::new(exe)
        .arg("check")
        .arg("-c")
        .arg(config_path)
        .output()
        .with_context(|| format!("running {} check", exe.display()))?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    bail!("sing-box config check failed\nstdout:\n{stdout}\nstderr:\n{stderr}");
}

pub fn sing_box_version(exe: &Path) -> Result<String> {
    let output = Command::new(exe)
        .arg("version")
        .output()
        .with_context(|| format!("running {} version", exe.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("sing-box version failed: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.lines().next().unwrap_or("sing-box").to_string())
}

pub fn validate_sing_box_version(exe: &Path) -> Result<()> {
    let line = sing_box_version(exe)?;
    validate_sing_box_version_line(&line)
        .with_context(|| format!("validating sing-box engine {}", exe.display()))
}

pub fn validate_sing_box_version_line(line: &str) -> Result<()> {
    let Some(rest) = line.trim().strip_prefix("sing-box version ") else {
        bail!(
            "unsupported sing-box version output: expected sing-box version {SING_BOX_VERSION}, got {line:?}"
        );
    };
    let actual = rest.split_whitespace().next().unwrap_or("");
    if actual == SING_BOX_VERSION {
        return Ok(());
    }

    bail!("unsupported sing-box version: expected {SING_BOX_VERSION}, got {actual}");
}

pub fn socks_is_listening(endpoint: &SocksEndpoint, timeout: Duration) -> bool {
    let Ok(addrs) = endpoint.to_string().to_socket_addrs() else {
        return false;
    };
    for addr in addrs {
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            return true;
        }
    }
    false
}

pub fn run_sing_box_foreground(exe: &Path, config_path: &Path) -> Result<ExitStatus> {
    let (mut child, _job) = start_sing_box_foreground(exe, config_path)?;

    let (tx, rx) = mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .context("installing Ctrl+C handler")?;

    loop {
        if let Some(status) = child.try_wait().context("checking sing-box status")? {
            return Ok(status);
        }

        if rx.try_recv().is_ok() {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if let Some(status) = child.try_wait().context("waiting for sing-box to stop")? {
                    return Ok(status);
                }
                std::thread::sleep(Duration::from_millis(100));
            }

            child.kill().context("stopping sing-box")?;
            return child.wait().context("waiting for killed sing-box");
        }

        std::thread::sleep(Duration::from_millis(200));
    }
}

pub fn start_sing_box_foreground(exe: &Path, config_path: &Path) -> Result<(Child, ProcessJob)> {
    ensure_no_running_owned_engine(exe)?;

    let child = Command::new(exe)
        .arg("run")
        .arg("-c")
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("starting {}", exe.display()))?;
    let job = match attach_child_to_kill_on_parent_exit(&child) {
        Ok(job) => job,
        Err(error) => {
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            return Err(error).context("attaching sing-box to the Windows cleanup job");
        }
    };
    Ok((child, job))
}

pub fn start_sing_box_quiet(exe: &Path, config_path: &Path) -> Result<(Child, ProcessJob)> {
    ensure_no_running_owned_engine(exe)?;

    let child = Command::new(exe)
        .arg("run")
        .arg("-c")
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("starting {}", exe.display()))?;
    let job = match attach_child_to_kill_on_parent_exit(&child) {
        Ok(job) => job,
        Err(error) => {
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            return Err(error).context("attaching sing-box to the Windows cleanup job");
        }
    };
    Ok((child, job))
}

pub fn start_sing_box_quiet_with_logs(
    exe: &Path,
    config_path: &Path,
    log_dir: &Path,
) -> Result<(Child, ProcessJob)> {
    ensure_no_running_owned_engine(exe)?;
    fs::create_dir_all(log_dir).with_context(|| format!("creating {}", log_dir.display()))?;
    let stdout_path = log_dir.join("sing-box.stdout.log");
    let stderr_path = log_dir.join("sing-box.stderr.log");
    let stdout = File::create(&stdout_path)
        .with_context(|| format!("creating {}", stdout_path.display()))?;
    let stderr = File::create(&stderr_path)
        .with_context(|| format!("creating {}", stderr_path.display()))?;

    let child = Command::new(exe)
        .arg("run")
        .arg("-c")
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| {
            format!(
                "starting {}; stdout={}, stderr={}",
                exe.display(),
                stdout_path.display(),
                stderr_path.display()
            )
        })?;
    let job = match attach_child_to_kill_on_parent_exit(&child) {
        Ok(job) => job,
        Err(error) => {
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            return Err(error).context("attaching sing-box to the Windows cleanup job");
        }
    };
    Ok((child, job))
}

pub fn stop_sing_box_child(child: &mut Child) -> Result<()> {
    if child
        .try_wait()
        .context("checking sing-box status")?
        .is_some()
    {
        return Ok(());
    }

    child.kill().context("stopping sing-box")?;
    child.wait().context("waiting for stopped sing-box")?;
    Ok(())
}

pub fn ensure_no_running_owned_engine(exe: &Path) -> Result<()> {
    let running = find_running_owned_engines(exe);
    if running.is_empty() {
        return Ok(());
    }

    bail!("{}", format_running_engine_conflict(&running));
}

pub fn find_running_owned_engines(exe: &Path) -> Vec<RunningEngine> {
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);
    let expected = exe.to_string_lossy().to_string();

    system
        .processes()
        .iter()
        .filter_map(|(pid, process)| {
            let actual = process.exe()?;
            if !process_path_is_owned_engine(&expected, actual.to_string_lossy()) {
                return None;
            }

            Some(RunningEngine {
                pid: pid.as_u32(),
                exe_path: actual.to_path_buf(),
            })
        })
        .collect()
}

pub fn format_running_engine_conflict(running: &[RunningEngine]) -> String {
    let details = running
        .iter()
        .map(|engine| format!("pid={} path={}", engine.pid, engine.exe_path.display()))
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "ProxyBridge RS sing-box engine is already running ({details}). Stop the existing tunnel first."
    )
}

pub fn stop_owned_engines(exe: &Path) -> Result<(Vec<RunningEngine>, Vec<u32>)> {
    let running = find_running_owned_engines(exe);
    let mut stopped = Vec::new();
    for engine in &running {
        stop_pid(engine.pid)?;
        stopped.push(engine.pid);
    }

    if !running.is_empty() {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if find_running_owned_engines(exe).is_empty() {
                return Ok((running, stopped));
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let remaining = find_running_owned_engines(exe);
        if !remaining.is_empty() {
            bail!(
                "owned sing-box process did not exit after stop: {}",
                format_running_engine_conflict(&remaining)
            );
        }
    }

    Ok((running, stopped))
}

fn stop_pid(pid: u32) -> Result<()> {
    let args = build_taskkill_args(pid);
    let output = Command::new("taskkill.exe")
        .args(&args)
        .output()
        .with_context(|| format!("running taskkill for pid {pid}"))?;
    if output.status.success() {
        return Ok(());
    }

    bail!(
        "taskkill failed for pid {pid}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn build_taskkill_args(pid: u32) -> Vec<String> {
    ["/PID", &pid.to_string(), "/T", "/F"]
        .into_iter()
        .map(String::from)
        .collect()
}

pub fn format_stop_summary(running: &[RunningEngine], stopped_pids: &[u32]) -> String {
    if running.is_empty() {
        return "No owned sing-box engine is running.".to_string();
    }

    let stopped = stopped_pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!("Stopped owned sing-box engine pid(s): {stopped}")
}

pub fn process_paths_match(expected: impl AsRef<str>, actual: impl AsRef<str>) -> bool {
    normalize_process_path(expected.as_ref()) == normalize_process_path(actual.as_ref())
}

pub fn process_path_is_owned_engine(expected: impl AsRef<str>, actual: impl AsRef<str>) -> bool {
    if process_paths_match(expected.as_ref(), actual.as_ref()) {
        return true;
    }

    let Some(expected_root) = owned_engine_root(expected.as_ref()) else {
        return false;
    };
    let normalized_actual = normalize_process_path(actual.as_ref());
    normalized_actual.ends_with("\\sing-box.exe")
        && normalized_actual.starts_with(&format!("{expected_root}\\"))
}

fn owned_engine_root(path: &str) -> Option<String> {
    let normalized = normalize_process_path(path);
    let marker = "\\engine\\";
    let index = normalized.rfind(marker)?;
    Some(normalized[..index + marker.len() - 1].to_string())
}

fn normalize_process_path(path: &str) -> String {
    let normalized = path
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase();
    normalized
        .strip_prefix(r"\\?\")
        .unwrap_or(&normalized)
        .to_string()
}
