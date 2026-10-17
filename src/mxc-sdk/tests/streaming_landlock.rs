// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Landlock backend tests: confinement, network postures, resource limits,
//! lifecycle, and the fallback from Bubblewrap.
//!
//! Tests skip when the kernel's Landlock is missing or older than ABI 3. Set
//! `MXC_LANDLOCK_TESTS_REQUIRE_EXECUTION=1` to fail instead.
//!
//! The fallback tests adapt to the host: where Bubblewrap can create its
//! namespaces they check that `process` stays on Bubblewrap, and where it
//! cannot they check that `process` moves to Landlock and that a request
//! naming Bubblewrap fails as a sandbox error. To exercise the second case on
//! a host that allows user namespaces, run the tests inside a user namespace
//! that cannot create another one (see the backend guide).

#![cfg(target_os = "linux")]

use std::io::Read;
use std::path::Path;

use mxc_sdk::v1::{ErrorCode, WaitResult};

fn landlock_available() -> bool {
    match mxc_sdk::landlock_common::abi::probe() {
        Ok(_) => true,
        Err(err) => {
            if std::env::var("MXC_LANDLOCK_TESTS_REQUIRE_EXECUTION").is_ok_and(|value| value != "0")
            {
                panic!("strict mode: {err}");
            }
            println!("SKIPPED: {err}");
            false
        }
    }
}

fn abi() -> mxc_sdk::landlock_common::abi::LandlockAbi {
    mxc_sdk::landlock_common::abi::probe().expect("Landlock available")
}

fn python3() -> bool {
    let found = std::process::Command::new("python3")
        .arg("-c")
        .arg("pass")
        .status()
        .is_ok_and(|status| status.success());
    if !found {
        println!("SKIPPED: python3 not found");
    }
    found
}

/// A raw `1.1.0-alpha` request with `fields` merged over the defaults.
fn request_json(containment: &str, command: &str, fields: serde_json::Value) -> String {
    let mut request = serde_json::json!({
        "version": "1.1.0-alpha",
        "containment": containment,
        "process": { "commandLine": command, "timeout": 60_000 },
    });
    if let (Some(request), Some(fields)) = (request.as_object_mut(), fields.as_object()) {
        for (key, value) in fields {
            request.insert(key.clone(), value.clone());
        }
    }
    request.to_string()
}

fn landlock_json(command: &str, fields: serde_json::Value) -> String {
    request_json("landlock", command, fields)
}

struct Outcome {
    outcome: WaitResult,
    stdout: String,
    stderr: String,
    warnings: Vec<String>,
    usage: Option<mxc_sdk::v1::ResourceUsage>,
}

fn run_json(json: &str) -> Outcome {
    let mut process = mxc_sdk::__ffi::spawn_container_json(json, false).expect("spawn");
    let mut stdout = process.take_stdout().expect("stdout");
    let mut stderr = process.take_stderr().expect("stderr");
    let reader = std::thread::spawn(move || {
        let mut err = String::new();
        let _ = stderr.read_to_string(&mut err);
        err
    });
    let mut out = String::new();
    stdout.read_to_string(&mut out).expect("read stdout");
    let outcome = process.wait().expect("wait");
    Outcome {
        outcome,
        stdout: out,
        stderr: reader.join().expect("stderr reader"),
        warnings: process.warnings(),
        usage: process
            .output_metadata()
            .and_then(|metadata| metadata.resource_usage),
    }
}

fn run(command: &str, fields: serde_json::Value) -> Outcome {
    run_json(&landlock_json(command, fields))
}

fn spawn_error(json: &str) -> mxc_sdk::v1::Error {
    mxc_sdk::__ffi::spawn_container_json(json, false)
        .err()
        .expect("the request must be refused")
}

fn path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Whether `pid` is gone. A killed process whose parent already exited is
/// reaped by init a moment later, so this waits a little for it.
fn gone(pid: &str) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let status = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        // Gone, or a zombie waiting for init: either way it no longer runs.
        if status.is_empty()
            || status
                .split(") ")
                .nth(1)
                .is_some_and(|rest| rest.starts_with('Z'))
        {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

#[test]
fn landlock_streams_stdio_and_keeps_the_exit_code() {
    if !landlock_available() {
        return;
    }
    use std::io::Write;

    let mut process = mxc_sdk::__ffi::spawn_container_json(
        &landlock_json("cat; exit 7", serde_json::json!({})),
        false,
    )
    .expect("spawn");
    let mut stdin = process.take_stdin().expect("stdin");
    let mut stdout = process.take_stdout().expect("stdout");
    stdin.write_all(b"ping-pong\n").expect("write");
    drop(stdin);
    let mut out = String::new();
    stdout.read_to_string(&mut out).expect("read");
    assert_eq!(out, "ping-pong\n");
    assert_eq!(process.wait().expect("wait"), WaitResult::Exited(7));
}

#[test]
fn landlock_grants_exactly_the_policy_paths() {
    if !landlock_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let ro = root.path().join("ro");
    let rw = root.path().join("rw");
    let hidden = root.path().join("hidden");
    for dir in [&ro, &rw, &hidden] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(ro.join("input"), "readable\n").unwrap();
    std::fs::write(hidden.join("secret"), "secret\n").unwrap();

    let script = format!(
        "cat {ro}/input; \
         echo written > {rw}/out && cat {rw}/out; \
         (echo nope > {ro}/out) 2>/dev/null || echo ro-write-denied; \
         (: > {ro}/input) 2>/dev/null || echo ro-truncate-denied; \
         cat {hidden}/secret 2>/dev/null || echo hidden-denied; \
         ls {root} >/dev/null 2>&1 || echo parent-list-denied",
        ro = path(&ro),
        rw = path(&rw),
        hidden = path(&hidden),
        root = path(root.path()),
    );
    let result = run(
        &script,
        serde_json::json!({
            "filesystem": {
                "readonlyPaths": [path(&ro)],
                "readwritePaths": [path(&rw)],
            }
        }),
    );
    assert_eq!(result.outcome, WaitResult::Exited(0), "{}", result.stderr);
    assert_eq!(
        result.stdout,
        "readable\nwritten\nro-write-denied\nro-truncate-denied\nhidden-denied\nparent-list-denied\n"
    );
    assert_eq!(
        std::fs::read_to_string(ro.join("input")).unwrap(),
        "readable\n"
    );
}

/// Landlock does not govern metadata, so the filter refuses changes by
/// path: a workload cannot make a file it may not read readable to others.
#[test]
fn landlock_refuses_metadata_changes_by_path() {
    if !landlock_available() {
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let rw = root.path().join("rw");
    let outside = root.path().join("outside");
    for dir in [&rw, &outside] {
        std::fs::create_dir_all(dir).unwrap();
    }
    let key = outside.join("key");
    std::fs::write(&key, "secret\n").unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mtime = std::fs::metadata(&key).unwrap().modified().unwrap();
    std::fs::write(rw.join("own"), "mine\n").unwrap();

    let script = format!(
        "chmod 644 {key} 2>/dev/null || echo chmod-denied; \
         chown $(id -u) {key} 2>/dev/null || echo chown-denied; \
         touch -d 2001-01-01 {key} 2>/dev/null || echo touch-denied; \
         chmod +x {rw}/own 2>/dev/null || echo own-chmod-denied; \
         touch -d 2001-01-01 {rw}/own && echo own-touch-ok; \
         touch {rw}/new && echo new-touch-ok",
        key = path(&key),
        rw = path(&rw),
    );
    let result = run(
        &script,
        serde_json::json!({ "filesystem": { "readwritePaths": [path(&rw)] } }),
    );
    assert_eq!(result.outcome, WaitResult::Exited(0), "{}", result.stderr);
    assert_eq!(
        result.stdout,
        "chmod-denied\nchown-denied\ntouch-denied\nown-chmod-denied\nown-touch-ok\nnew-touch-ok\n"
    );
    let metadata = std::fs::metadata(&key).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.modified().unwrap(), mtime);

    if !python3() {
        return;
    }
    // Through a descriptor it opened, a workload still sets its own files'
    // mode and times; an O_PATH descriptor of a file it may not open does
    // not count.
    let script = format!(
        "import os\n\
         fd = os.open('{rw}/own', os.O_WRONLY)\n\
         os.fchmod(fd, 0o755); os.utime(fd, (0, 0))\n\
         print('fd-ok', oct(os.stat('{rw}/own').st_mode & 0o777))\n\
         ref = os.open('{key}', os.O_PATH)\n\
         for change in (lambda: os.fchmod(ref, 0o644), lambda: os.utime(ref, (0, 0))):\n\
         \x20   try:\n\
         \x20       change(); print('O_PATH-CHANGED')\n\
         \x20   except OSError:\n\
         \x20       print('o-path-denied')\n",
        rw = path(&rw),
        key = path(&key),
    );
    // The script goes in the environment, so the shell leaves it alone.
    let command = "python3 -c \"$SCRIPT\"";
    let result = run(
        command,
        serde_json::json!({
            "filesystem": { "readwritePaths": [path(&rw)] },
            "process": {
                "commandLine": command,
                "timeout": 60_000,
                "env": [format!("SCRIPT={script}")],
            },
        }),
    );
    assert_eq!(result.outcome, WaitResult::Exited(0), "{}", result.stderr);
    assert_eq!(result.stdout, "fd-ok 0o755\no-path-denied\no-path-denied\n");
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn landlock_hides_the_callers_home_and_tmp() {
    if !landlock_available() {
        return;
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let result = run(
        &format!(
            "ls {home} >/dev/null 2>&1 || echo home-denied; \
             ls /tmp >/dev/null 2>&1 || echo tmp-denied; \
             echo scratch > \"$TMPDIR/f\" && cat \"$TMPDIR/f\"; echo \"$TMPDIR\""
        ),
        serde_json::json!({}),
    );
    assert_eq!(result.outcome, WaitResult::Exited(0), "{}", result.stderr);
    let mut lines = result.stdout.lines();
    assert_eq!(lines.next(), Some("home-denied"));
    assert_eq!(lines.next(), Some("tmp-denied"));
    assert_eq!(lines.next(), Some("scratch"));
    let tmpdir = lines.next().expect("TMPDIR printed");
    assert!(tmpdir.contains("mxc-landlock-"), "{tmpdir}");
    assert!(
        !Path::new(tmpdir).exists(),
        "the private temporary directory outlived the run"
    );
}

#[test]
fn landlock_refuses_what_it_cannot_carve_out() {
    if !landlock_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let secret = root.path().join(".env");
    std::fs::write(&secret, "TOKEN=1").unwrap();
    let error = spawn_error(&landlock_json(
        "cat .env",
        serde_json::json!({
            "filesystem": {
                "readwritePaths": [path(root.path())],
                "deniedPaths": [path(&secret)],
            }
        }),
    ));
    assert_eq!(error.code, ErrorCode::PolicyValidation, "{error:?}");
    assert!(error.message.contains("deniedPaths"), "{error:?}");
}

#[test]
fn landlock_keeps_a_denied_path_out_of_the_baseline() {
    if !landlock_available() {
        return;
    }
    // /etc is in the baseline; /etc/hostname sits inside it.
    if !Path::new("/etc/hostname").exists() || !Path::new("/etc/os-release").exists() {
        println!("SKIPPED: /etc/hostname or /etc/os-release missing");
        return;
    }
    let result = run(
        "cat /etc/hostname >/dev/null 2>&1 || echo hostname-denied; \
         cat /etc/os-release >/dev/null && echo os-release-readable",
        serde_json::json!({ "filesystem": { "deniedPaths": ["/etc/hostname"] } }),
    );
    assert_eq!(result.outcome, WaitResult::Exited(0), "{}", result.stderr);
    assert_eq!(result.stdout, "hostname-denied\nos-release-readable\n");
}

#[test]
fn landlock_isolates_the_network_by_default() {
    if !landlock_available() || !python3() {
        return;
    }
    let script = "python3 -c '\nimport socket\nfor family, kind in ((socket.AF_INET, socket.SOCK_STREAM), (socket.AF_INET, socket.SOCK_DGRAM), (socket.AF_INET6, socket.SOCK_STREAM)):\n    try:\n        socket.socket(family, kind)\n        print(\"open\")\n    except PermissionError:\n        print(\"denied\")\n'";
    let result = run(script, serde_json::json!({}));
    assert_eq!(result.outcome, WaitResult::Exited(0), "{}", result.stderr);
    assert_eq!(result.stdout, "denied\ndenied\ndenied\n");
}

#[test]
fn landlock_keeps_host_unix_sockets_out_of_reach() {
    if !landlock_available() || !python3() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("host.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let script = format!(
        "python3 -c '\nimport socket\ntry:\n    s = socket.socket(socket.AF_UNIX)\n    s.connect(\"{}\")\n    print(\"connected\")\nexcept PermissionError:\n    print(\"denied\")\na, b = socket.socketpair()\na.send(b\"x\")\nprint(b.recv(1).decode())\n'",
        path(&socket)
    );
    let result = run(&script, serde_json::json!({}));
    assert_eq!(result.outcome, WaitResult::Exited(0), "{}", result.stderr);
    assert_eq!(result.stdout, "denied\nx\n");

    // A socket inside a granted read-write path is reachable only where
    // Landlock confines Unix sockets to granted paths.
    let granted = run(
        &script,
        serde_json::json!({ "filesystem": { "readwritePaths": [path(root.path())] } }),
    );
    let expected = if abi().restricts_unix_sockets() {
        "connected\nx\n"
    } else {
        "denied\nx\n"
    };
    assert_eq!(granted.stdout, expected, "{}", granted.stderr);
}

#[test]
fn landlock_allows_the_host_network_only_when_everything_is_allowed() {
    if !landlock_available() || !python3() {
        return;
    }
    let error = spawn_error(&landlock_json(
        "true",
        serde_json::json!({ "network": { "egress": { "default": "allow" } } }),
    ));
    assert_eq!(error.code, ErrorCode::PolicyValidation, "{error:?}");
    assert!(error.message.contains("loopback"), "{error:?}");

    let result = run(
        "python3 -c 'import socket; socket.socket(); print(\"open\")'",
        serde_json::json!({
            "network": {
                "egress": { "default": "allow" },
                "ingress": { "default": "allow", "hostLoopback": "allow" },
            }
        }),
    );
    assert_eq!(result.outcome, WaitResult::Exited(0), "{}", result.stderr);
    assert_eq!(result.stdout, "open\n");
}

#[test]
fn landlock_refuses_address_rules_and_proxies() {
    if !landlock_available() {
        return;
    }
    let error = spawn_error(&landlock_json(
        "true",
        serde_json::json!({
            "network": { "egress": { "default": "deny", "allow": [{ "to": [{ "cidr": "1.1.1.1/32" }] }] } }
        }),
    ));
    assert_eq!(error.code, ErrorCode::PolicyValidation, "{error:?}");
}

#[test]
fn landlock_scopes_signals_where_the_abi_can() {
    if !landlock_available() {
        return;
    }
    let result = run(
        &format!(
            "kill -0 {} 2>/dev/null && echo reached || echo blocked",
            std::process::id()
        ),
        serde_json::json!({}),
    );
    let expected = if abi().scopes_signals_and_abstract_sockets() {
        "blocked\n"
    } else {
        assert!(
            result.warnings.iter().any(|w| w.contains("signalling")),
            "{:?}",
            result.warnings
        );
        "reached\n"
    };
    assert_eq!(result.stdout, expected);
}

#[test]
fn landlock_enforces_cpu_time_and_reports_usage() {
    if !landlock_available() {
        return;
    }
    let start = std::time::Instant::now();
    let result = run(
        "while :; do :; done",
        serde_json::json!({ "resources": { "cpuTimeMs": 1000, "priority": "low" } }),
    );
    assert_ne!(result.outcome, WaitResult::Exited(0));
    assert!(start.elapsed() < std::time::Duration::from_secs(30));
    let usage = result.usage.expect("resource usage reported");
    assert_eq!(
        usage.limit_exceeded,
        Some(mxc_sdk::v1::ResourceLimit::CpuTime)
    );

    let limits = run(
        "ulimit -t; ulimit -d; cut -d ' ' -f 19 /proc/self/stat",
        serde_json::json!({ "resources": { "cpuTimeMs": 1500, "memoryMb": 256, "priority": "idle" } }),
    );
    assert_eq!(limits.outcome, WaitResult::Exited(0), "{}", limits.stderr);
    // SAFETY: getpriority only queries the calling process.
    let parent = unsafe { libc::getpriority(libc::PRIO_PROCESS as _, 0) };
    assert_eq!(limits.stdout, format!("2\n262144\n{}\n", parent.max(19)));

    let error = spawn_error(&landlock_json(
        "true",
        serde_json::json!({ "resources": { "maxProcesses": 8 } }),
    ));
    assert_eq!(error.code, ErrorCode::PolicyValidation, "{error:?}");
}

#[test]
fn landlock_times_out_and_takes_background_processes_with_the_workload() {
    if !landlock_available() {
        return;
    }
    let mut process = mxc_sdk::__ffi::spawn_container_json(
        &request_json(
            "landlock",
            "sleep 30 & echo $!; wait",
            serde_json::json!({ "process": { "commandLine": "sleep 30 & echo $!; wait", "timeout": 500 } }),
        ),
        false,
    )
    .expect("spawn");
    let mut stdout = process.take_stdout().expect("stdout");
    let mut first = [0_u8; 32];
    let read = stdout.read(&mut first).expect("read");
    let background = String::from_utf8_lossy(&first[..read]).trim().to_string();
    assert!(background.parse::<u32>().is_ok(), "{background:?}");
    assert_eq!(process.wait().expect("wait"), WaitResult::TimedOut);
    assert!(
        gone(&background),
        "the background process outlived the timeout"
    );

    let result = run("sleep 30 >/dev/null 2>&1 & echo $!", serde_json::json!({}));
    assert_eq!(result.outcome, WaitResult::Exited(0));
    assert!(
        gone(result.stdout.trim()),
        "a background process outlived its workload"
    );
}

#[test]
fn landlock_runs_in_a_pty() {
    if !landlock_available() {
        return;
    }
    let process = mxc_sdk::__ffi::spawn_with_pty_json(
        &landlock_json("test -t 0 && echo tty", serde_json::json!({})),
        false,
        mxc_sdk::v1::MxcPtySize {
            rows: 24,
            cols: 80,
            ..Default::default()
        },
    )
    .expect("spawn");
    let mut reader = process.try_clone_reader().expect("reader");
    let reader = std::thread::spawn(move || {
        let mut out = String::new();
        let _ = reader.read_to_string(&mut out);
        out
    });
    assert_eq!(process.wait().expect("wait"), WaitResult::Exited(0));
    let out = reader.join().expect("reader thread");
    assert!(out.contains("tty"), "{out:?}");
}

/// `process` runs on Bubblewrap where it can create its namespaces, and on
/// Landlock, with a warning saying so, where it cannot.
#[test]
fn process_falls_back_to_landlock_only_when_bubblewrap_cannot_run() {
    let bubblewrap = mxc_sdk::bwrap_common::bwrap_version::probe_bwrap();
    let landlock = mxc_sdk::landlock_common::abi::probe();
    if bubblewrap.is_err() && landlock.is_err() {
        println!("SKIPPED: neither Bubblewrap nor Landlock can run here");
        return;
    }
    let result = run_json(&request_json("process", "echo ran", serde_json::json!({})));
    assert_eq!(result.outcome, WaitResult::Exited(0), "{}", result.stderr);
    assert_eq!(result.stdout, "ran\n");
    let fell_back = result
        .warnings
        .iter()
        .any(|w| w.contains("runs on Landlock"));
    assert_eq!(fell_back, bubblewrap.is_err(), "{:?}", result.warnings);
}
