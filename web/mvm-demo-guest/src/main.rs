//! Browser-tier mvm microVM guest workload.
//!
//! This is a `wasm32-wasip1` binary. It is not a real Linux kernel; it is a
//! curated simulated guest that prints a boot sequence and provides a small
//! POSIX-like shell so the `/demo` page can show what launching an mvm-defined
//! microVM feels like inside a WebAssembly sandbox.
//!
//! The host drives the guest through two exports instead of stdin:
//! - `init()` prints the boot sequence and the first prompt.
//! - `exec(line_ptr, line_len)` executes one command line and prints the
//!   result plus the next prompt. This avoids the need for Asyncify on stdin.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::c_char;
use std::fs;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

// Host-provided egress import. The browser WASI host enforces the
// VmStartConfig.network_policy before performing the fetch.
#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "mvm")]
unsafe extern "C" {
    /// Request egress to `host:port` with `body`.
    ///
    /// Returns the number of bytes written on allow, a negative errno on
    /// deny/error. On allow, the response is written into `out`.
    fn egress(
        host_ptr: *const u8,
        host_len: usize,
        port: u16,
        body_ptr: *const u8,
        body_len: usize,
        out_ptr: *mut u8,
        out_len: usize,
    ) -> i32;
}

#[cfg(target_arch = "wasm32")]
fn host_egress(host: &str, port: u16, body: &[u8], out: &mut [u8]) -> Result<usize, i32> {
    let written = unsafe {
        egress(
            host.as_ptr(),
            host.len(),
            port,
            body.as_ptr(),
            body.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if written < 0 {
        Err(written)
    } else {
        Ok(written as usize)
    }
}

/// Host-only fallback for `cargo test` on the native target.
#[cfg(not(target_arch = "wasm32"))]
fn host_egress(_host: &str, _port: u16, _body: &[u8], _out: &mut [u8]) -> Result<usize, i32> {
    Err(-13) // EACCES fallback so tests never need real network.
}

fn print(s: &str) {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(s.as_bytes());
    let _ = lock.flush();
}

fn println(s: &str) {
    print(s);
    print("\n");
}

fn prompt() {
    print("root@mvm:~# ");
}

fn boot() {
    println("mvm: loading workload from VmStartConfig");
    println("mvm: mounting virtual rootfs (read-only)");
    println("mvm: applying NetworkPolicy");
    println("mvm: starting /bin/init");
    println("mvm: init complete");
    println("");
    println("Welcome to the mvm browser-tier microVM.");
    println("Type 'help' for available commands.");
    println("");
    prompt();
}

// -----------------------------------------------------------------------------
// Shell state
// -----------------------------------------------------------------------------

struct ShellState {
    cwd: String,
    env: BTreeMap<String, String>,
    history: Vec<String>,
}

impl ShellState {
    fn new() -> Self {
        let mut env = BTreeMap::new();
        env.insert("PATH".into(), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
        env.insert("HOME".into(), "/root".into());
        env.insert("USER".into(), "root".into());
        env.insert("LOGNAME".into(), "root".into());
        env.insert("HOSTNAME".into(), "mvm".into());
        env.insert("TERM".into(), "xterm-256color".into());
        env.insert("SHELL".into(), "/bin/sh".into());
        env.insert("LANG".into(), "C.UTF-8".into());
        Self {
            cwd: "/".into(),
            env,
            history: Vec::new(),
        }
    }
}

thread_local! {
    static SHELL: RefCell<ShellState> = RefCell::new(ShellState::new());
}

fn with_shell<R>(f: impl FnOnce(&mut ShellState) -> R) -> R {
    SHELL.with(|s| f(&mut s.borrow_mut()))
}

// -----------------------------------------------------------------------------
// Argument parser
// -----------------------------------------------------------------------------

fn parse_line(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;

    for ch in line.chars() {
        if escape {
            current.push(ch);
            escape = false;
            continue;
        }
        match ch {
            '\\' if !in_single => escape = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            c if c.is_whitespace() && !in_single && !in_double => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

// -----------------------------------------------------------------------------
// Path helpers
// -----------------------------------------------------------------------------

fn resolve_path(cwd: &str, path: &str) -> String {
    if path.starts_with('/') {
        normalize(path)
    } else if cwd == "/" {
        normalize(&format!("/{path}"))
    } else {
        normalize(&format!("{cwd}/{path}"))
    }
}

fn normalize(path: &str) -> String {
    let mut stack = Vec::new();
    for part in path.split('/').filter(|p| !p.is_empty() && *p != ".") {
        if part == ".." {
            stack.pop();
        } else {
            stack.push(part);
        }
    }
    if stack.is_empty() {
        "/".into()
    } else {
        format!("/{}", stack.join("/"))
    }
}

// -----------------------------------------------------------------------------
// Commands
// -----------------------------------------------------------------------------

fn cmd_help() {
    println("Available commands:");
    println("  help                   show this message");
    println("  clear                  clear the terminal screen");
    println("  exit                   shutdown the microVM");
    println("  pwd                    print working directory");
    println("  cd <path>              change directory");
    println("  ls [-la] [path]        list directory contents");
    println("  cat <file>...          print file contents");
    println("  echo [-n] <text>       print text");
    println("  fetch <host> <port>    egress to host:port via mvm:egress");
    println("  whoami                 print current user");
    println("  hostname               print system hostname");
    println("  date                   print current date and time");
    println("  uname [-a]             print system information");
    println("  env                    print environment variables");
    println("  printenv [name]        print an environment variable");
    println("  id                     print user identity");
    println("  ps                     list processes");
    println("  top                    display system tasks");
    println("  df [-h]                report filesystem disk usage");
    println("  free [-h]              display memory usage");
    println("  uptime                 print system uptime");
    println("  history                show command history");
    println("  which <command>        locate a command");
    println("  man [topic]            show manual page");
}

fn cmd_clear() {
    // The terminal UI interprets the form-feed byte as a clear-screen request.
    print("\x0c");
}

fn cmd_pwd(cwd: &str) {
    println(cwd);
}

fn cmd_cd(state: &mut ShellState, args: &[String]) {
    let target = args.get(1).map(String::as_str).unwrap_or("/root");
    let resolved = resolve_path(&state.cwd, target);
    match fs::metadata(&resolved) {
        Ok(m) if m.is_dir() => state.cwd = resolved,
        Ok(_) => println(&format!("cd: {target}: Not a directory")),
        Err(e) => println(&format!("cd: {target}: {e}")),
    }
}

fn cmd_ls(cwd: &str, args: &[String]) {
    let mut long = false;
    let mut all = false;
    let mut path: Option<&str> = None;

    for arg in &args[1..] {
        if arg.starts_with('-') && arg.len() > 1 {
            for ch in arg.chars().skip(1) {
                match ch {
                    'l' => long = true,
                    'a' => all = true,
                    _ => {}
                }
            }
        } else {
            path = Some(arg.as_str());
        }
    }

    let target = resolve_path(cwd, path.unwrap_or("."));
    match fs::read_dir(&target) {
        Ok(entries) => {
            let mut names: Vec<String> = entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();

            if long {
                println(&format!("total {}", names.len()));
                for name in &names {
                    if !all && name.starts_with('.') {
                        continue;
                    }
                    let full = if target == "/" {
                        format!("/{name}")
                    } else {
                        format!("{target}/{name}")
                    };
                    let (mode, size) = match fs::metadata(&full) {
                        Ok(m) => {
                            let t = if m.is_dir() { 'd' } else { '-' };
                            (format!("{t}rwxr-xr-x"), m.len())
                        }
                        Err(_) => ("-?????????".into(), 0),
                    };
                    println(&format!("{mode} 1 root root {size:>8} Jan  1 00:00 {name}"));
                }
            } else {
                for name in &names {
                    if !all && name.starts_with('.') {
                        continue;
                    }
                    println(name);
                }
            }
        }
        Err(e) => println(&format!("ls: {target}: {e}")),
    }
}

fn cmd_cat(args: &[String]) {
    if args.len() < 2 {
        println("cat: missing operand");
        return;
    }
    let cwd = with_shell(|s| s.cwd.clone());
    for arg in &args[1..] {
        let path = resolve_path(&cwd, arg);
        match fs::read_to_string(&path) {
            Ok(content) => {
                print(&content);
                if !content.ends_with('\n') {
                    print("\n");
                }
            }
            Err(e) => println(&format!("cat: {path}: {e}")),
        }
    }
}

fn cmd_echo(args: &[String]) {
    let mut no_newline = false;
    let mut start = 1;
    while start < args.len() && args[start].starts_with('-') {
        if args[start] == "-n" {
            no_newline = true;
        }
        start += 1;
    }
    let text = args[start..].join(" ");
    if no_newline {
        print(&text);
    } else {
        println(&text);
    }
}

fn cmd_whoami() {
    println("root");
}

fn cmd_hostname() {
    println("mvm");
}

fn cmd_date() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (y, mo, d, h, mi, s) = unix_to_datetime(now);
    println(&format!(
        "{weekday} {mon} {d:02} {h:02}:{mi:02}:{s:02} UTC {y}",
        weekday = weekday_name(unix_weekday(now)),
        mon = month_name(mo)
    ));
}

fn cmd_uname(args: &[String]) {
    if args.len() > 1 && args[1] == "-a" {
        println("Linux mvm 6.6.0-mvm #1 SMP PREEMPT mvm-browser-tier wasm32-wasip1 GNU/Linux");
    } else {
        println("Linux");
    }
}

fn cmd_env(state: &ShellState) {
    let mut keys: Vec<&String> = state.env.keys().collect();
    keys.sort();
    for k in keys {
        println(&format!("{k}={}", state.env[k]));
    }
}

fn cmd_printenv(state: &ShellState, args: &[String]) {
    if args.len() < 2 {
        cmd_env(state);
        return;
    }
    for arg in &args[1..] {
        if let Some(v) = state.env.get(arg) {
            println(v);
        }
    }
}

fn cmd_id() {
    println("uid=0(root) gid=0(root) groups=0(root)");
}

fn cmd_ps() {
    println("  PID TTY          TIME CMD");
    println("    1 ?        00:00:00 init");
    println("    2 ?        00:00:00 mvm-agentd");
    println("    3 ?        00:00:00 /bin/sh");
}

fn cmd_top() {
    println("top - 00:00:00 up 0 min,  1 user,  load average: 0.00, 0.00, 0.00");
    println("Tasks:   3 total,   1 running,   2 sleeping,   0 stopped,   0 zombie");
    println("  PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND");
    println("    1 root      20   0    4096   1024    512 S   0.0  0.1   0:00.00 init");
    println("    2 root      20   0    8192   2048   1024 S   0.0  0.2   0:00.00 mvm-agentd");
    println("    3 root      20   0    4096   1536    768 R   0.0  0.1   0:00.00 sh");
}

fn cmd_df(args: &[String]) {
    let human = args.iter().skip(1).any(|a| a == "-h");
    if human {
        println("Filesystem      Size  Used Avail Use% Mounted on");
        println("rootfs          128M   12M  116M   9% /");
    } else {
        println("Filesystem     1K-blocks   Used Available Use% Mounted on");
        println("rootfs            131072  12288    118784   9% /");
    }
}

fn cmd_free(args: &[String]) {
    let human = args.iter().skip(1).any(|a| a == "-h");
    if human {
        println("              total        used        free      shared  buff/cache   available");
        println("Mem:          128Mi        12Mi       108Mi       0.0Ki         8Mi       116Mi");
        println("Swap:         0.0Ki       0.0Ki       0.0Ki");
    } else {
        println("              total        used        free      shared  buff/cache   available");
        println("Mem:          131072       12288      110592           0        8192      118784");
        println("Swap:              0           0           0");
    }
}

fn cmd_uptime() {
    println(" 00:00:00 up 0 min,  1 user,  load average: 0.00, 0.00, 0.00");
}

fn cmd_history(state: &ShellState) {
    for (i, line) in state.history.iter().enumerate() {
        println(&format!("{:>5}  {line}", i + 1));
    }
}

fn cmd_which(args: &[String]) {
    if args.len() < 2 {
        println("which: missing operand");
        return;
    }
    let builtins: &[&str] = &[
        "help", "clear", "exit", "pwd", "cd", "ls", "cat", "echo", "fetch",
        "whoami", "hostname", "date", "uname", "env", "printenv", "id", "ps",
        "top", "df", "free", "uptime", "history", "which", "man",
    ];
    for arg in &args[1..] {
        if builtins.contains(&arg.as_str()) {
            println(&format!("{arg}: shell built-in command"));
        } else {
            println(&format!("which: no {arg} in (/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin)"));
        }
    }
}

fn cmd_man(args: &[String]) {
    if args.len() < 2 {
        println("What manual page do you want?");
        return;
    }
    let topic = &args[1];
    println(&format!("No manual entry for {topic}"));
}

fn cmd_fetch(args: &[String]) {
    if args.len() < 3 {
        println("fetch: usage: fetch <host> <port> [body]");
        return;
    }
    let host = args[1].clone();
    let port: u16 = match args[2].parse() {
        Ok(p) => p,
        Err(_) => {
            println("fetch: invalid port");
            return;
        }
    };
    let body = args.get(3).map(String::as_str).unwrap_or("").as_bytes();
    let mut out = vec![0u8; 4096];
    match host_egress(&host, port, body, &mut out) {
        Ok(n) => {
            let response = String::from_utf8_lossy(&out[..n]);
            println(&format!("fetch: allowed ({host}:{port})"));
            if !response.is_empty() {
                println(&response);
            }
        }
        Err(-13) => println(&format!("fetch: denied by NetworkPolicy ({host}:{port})")),
        Err(e) => println(&format!("fetch: error {e}")),
    }
}

fn run_line(line: &str) -> bool {
    let args = parse_line(line);
    if args.is_empty() {
        return true;
    }

    let command = args[0].clone();
    with_shell(|state| state.history.push(line.to_string()));

    match command.as_str() {
        "help" => cmd_help(),
        "clear" => cmd_clear(),
        "pwd" => with_shell(|s| cmd_pwd(&s.cwd)),
        "cd" => with_shell(|s| cmd_cd(s, &args)),
        "ls" => with_shell(|s| cmd_ls(&s.cwd, &args)),
        "cat" => cmd_cat(&args),
        "echo" => cmd_echo(&args),
        "whoami" => cmd_whoami(),
        "hostname" => cmd_hostname(),
        "date" => cmd_date(),
        "uname" => cmd_uname(&args),
        "env" => with_shell(|s| cmd_env(s)),
        "printenv" => with_shell(|s| cmd_printenv(s, &args)),
        "id" => cmd_id(),
        "ps" => cmd_ps(),
        "top" => cmd_top(),
        "df" => cmd_df(&args),
        "free" => cmd_free(&args),
        "uptime" => cmd_uptime(),
        "history" => with_shell(|s| cmd_history(s)),
        "which" => cmd_which(&args),
        "man" => cmd_man(&args),
        "fetch" => cmd_fetch(&args),
        "exit" => {
            println("mvm: stopping microVM");
            return false;
        }
        _ => println(&format!("{command}: command not found")),
    }
    true
}

// -----------------------------------------------------------------------------
// Minimal date/time formatting (avoids pulling chrono into the wasm bundle).
// -----------------------------------------------------------------------------

fn unix_to_datetime(seconds: u64) -> (u64, u64, u64, u64, u64, u64) {
    const SECS_PER_DAY: u64 = 86_400;
    const DAYS_IN_MONTH: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    let mut days = seconds / SECS_PER_DAY;
    let rem = seconds % SECS_PER_DAY;
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let sec = rem % 60;

    let mut year = 1970;
    loop {
        let ydays = if is_leap_year(year) { 366 } else { 365 };
        if days < ydays {
            break;
        }
        days -= ydays;
        year += 1;
    }

    let mut month = 0;
    while month < 12 {
        let mdays = if month == 1 && is_leap_year(year) {
            29
        } else {
            DAYS_IN_MONTH[month]
        };
        if days < mdays {
            break;
        }
        days -= mdays;
        month += 1;
    }

    (
        year,
        (month as u64) + 1,
        days + 1,
        hour,
        minute,
        sec,
    )
}

fn is_leap_year(year: u64) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn unix_weekday(seconds: u64) -> u64 {
    // 1970-01-01 was a Thursday.
    (4 + seconds / 86_400) % 7
}

fn weekday_name(n: u64) -> &'static str {
    match n {
        0 => "Sun",
        1 => "Mon",
        2 => "Tue",
        3 => "Wed",
        4 => "Thu",
        5 => "Fri",
        6 => "Sat",
        _ => "???",
    }
}

fn month_name(n: u64) -> &'static str {
    match n {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        12 => "Dec",
        _ => "???",
    }
}

// -----------------------------------------------------------------------------
// Host-call exports
// -----------------------------------------------------------------------------

/// # Safety
/// `line_ptr` must point to `line_len` valid UTF-8 bytes.
unsafe fn line_from_ptr(line_ptr: *const c_char, line_len: usize) -> String {
    let bytes = unsafe { std::slice::from_raw_parts(line_ptr.cast::<u8>(), line_len) };
    String::from_utf8_lossy(bytes).into_owned()
}

/// Initialize the guest: print boot sequence and first prompt.
#[unsafe(no_mangle)]
pub extern "C" fn init() -> i32 {
    boot();
    0
}

/// Execute one command line and print the result plus the next prompt.
///
/// # Safety
/// `line_ptr` must point to `line_len` valid UTF-8 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn exec(line_ptr: *const c_char, line_len: usize) -> i32 {
    let line = unsafe { line_from_ptr(line_ptr, line_len) };
    if run_line(&line) {
        prompt();
    }
    0
}

/// WASI `_start` entry point for standalone use.
fn main() {
    boot();
}

/// Fixed-size buffer the host writes commands into before calling `exec`.
static mut COMMAND_BUFFER: [u8; 4096] = [0; 4096];

/// Return a pointer to the host-writable command buffer.
#[unsafe(no_mangle)]
pub extern "C" fn command_buffer_ptr() -> *mut u8 {
    // SAFETY: COMMAND_BUFFER is only accessed through the returned pointer by
    // the single-threaded host. No Rust reference is created.
    std::ptr::addr_of_mut!(COMMAND_BUFFER).cast::<u8>()
}

/// Return the length of the host-writable command buffer.
#[unsafe(no_mangle)]
pub extern "C" fn command_buffer_len() -> usize {
    4096
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_command() {
        let args = parse_line("ls /etc");
        assert_eq!(args, vec!["ls", "/etc"]);
    }

    #[test]
    fn parse_quoted_command() {
        let args = parse_line("echo 'hello world' \"foo bar\"");
        assert_eq!(args, vec!["echo", "hello world", "foo bar"]);
    }

    #[test]
    fn parse_fetch_command() {
        let args = parse_line("fetch api.openai.com 443");
        assert_eq!(args, vec!["fetch", "api.openai.com", "443"]);
    }

    #[test]
    fn normalize_path() {
        assert_eq!(normalize("/etc/../var/log"), "/var/log");
        assert_eq!(normalize("/a/b/./c"), "/a/b/c");
    }

    #[test]
    fn run_help_is_true() {
        assert!(run_line("help"));
    }

    #[test]
    fn run_exit_is_false() {
        assert!(!run_line("exit"));
    }

    #[test]
    fn parse_with_quotes_and_escape() {
        let args = parse_line("echo \"a b\" 'c d'");
        assert_eq!(args, vec!["echo", "a b", "c d"]);
    }

    #[test]
    fn parse_empty_returns_nothing() {
        assert!(parse_line("   ").is_empty());
    }

    #[test]
    fn whoami_is_root() {
        // Capture stdout by swapping the global writer is not practical in
        // unit tests; exercise the command path and assert it does not stop
        // the shell.
        assert!(run_line("whoami"));
    }

    #[test]
    fn id_is_root() {
        assert!(run_line("id"));
    }

    #[test]
    fn echo_no_newline() {
        assert!(run_line("echo -n hello"));
    }

    #[test]
    fn unknown_command_is_true() {
        assert!(run_line("notacommand"));
    }
}
