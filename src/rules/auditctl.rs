//! Module defining functions that execute the auditctl commands that auditrs
//! wraps. For features like watches, it is not enough to look for commands
//! affecting given paths, we need to tell Linux Audit Subsystem to send us
//! events related to actions taken on those paths.
//!
//! This module is the single place where we construct and invoke `auditctl`
//! commands, so higher-level config code can stay focused on concepts
//! like watches & filters.

use anyhow::Result;
use audit::packet::rules::{
    RuleAction,
    RuleField,
    RuleFieldFlags,
    RuleFlags,
    RuleMessage,
    RuleSyscalls,
};
use std::process::Command;
use std::{
    fs::OpenOptions,
    io::{BufRead, BufReader, Seek, SeekFrom, Write},
};

use crate::rules::{AUDIT_RULES_FILE, AuditWatch, WatchAction};

use std::collections::HashSet;

fn syscalls_for_action(action: &WatchAction) -> &'static [&'static str] {
    match action {
        WatchAction::Execute => &["execve"],
        WatchAction::Write => {
            &[
                "rename",
                "mkdir",
                "rmdir",
                "creat",
                "link",
                "unlink",
                "symlink",
                "mknod",
                "mkdirat",
                "mknodat",
                "unlinkat",
                "renameat",
                "linkat",
                "symlinkat",
                "renameat2",
                "acct",
                "swapon",
                "quotactl",
                "quotactl_fd",
                "truncate",
                "ftruncate",
                "bind",
                "fallocate",
                "open",
                "openat",
                "openat2",
            ]
        }
        WatchAction::Read => {
            &[
                "readlink",
                "quotactl",
                "listxattr",
                "llistxattr",
                "flistxattr",
                "getxattr",
                "lgetxattr",
                "fgetxattr",
                "readlinkat",
                "open",
                "openat",
                "openat2",
            ]
        }
        WatchAction::Attributes => {
            &[
                "chmod",
                "fchmod",
                "chown",
                "lchown",
                "fchown",
                "setxattr",
                "lsetxattr",
                "fsetxattr",
                "removexattr",
                "lremovexattr",
                "fremovexattr",
                "fchownat",
                "fchmodat",
                "fchmodat2",
                "link",
                "linkat",
            ]
        }
    }
}

fn syscall_number(name: &str) -> Option<u32> {
    match name {
        "read" => Some(0),
        "write" => Some(1),
        "open" => Some(2),
        "execve" => Some(59),
        "truncate" => Some(76),
        "ftruncate" => Some(77),
        "getxattr" => Some(191),
        "lgetxattr" => Some(192),
        "fgetxattr" => Some(193),
        "listxattr" => Some(194),
        "llistxattr" => Some(195),
        "flistxattr" => Some(196),
        "removexattr" => Some(197),
        "lremovexattr" => Some(198),
        "fremovexattr" => Some(199),
        "chmod" => Some(90),
        "fchmod" => Some(91),
        "chown" => Some(92),
        "lchown" => Some(94),
        "fchown" => Some(93),
        "setxattr" => Some(188),
        "lsetxattr" => Some(189),
        "fsetxattr" => Some(190),
        "readlink" => Some(89),
        "symlink" => Some(88),
        "link" => Some(86),
        "unlink" => Some(87),
        "rename" => Some(82),
        "mkdir" => Some(83),
        "rmdir" => Some(84),
        "creat" => Some(85),
        "mknod" => Some(133),
        "acct" => Some(163),
        "swapon" => Some(167),
        "quotactl" => Some(179),
        "bind" => Some(49),
        "mkdirat" => Some(258),
        "mknodat" => Some(259),
        "fchownat" => Some(260),
        "fchmodat" => Some(268),
        "fchmodat2" => Some(452),
        "openat" => Some(257),
        "linkat" => Some(265),
        "symlinkat" => Some(266),
        "readlinkat" => Some(267),
        "unlinkat" => Some(263),
        "renameat" => Some(264),
        "fallocate" => Some(285),
        "renameat2" => Some(316),
        "quotactl_fd" => Some(443),
        "openat2" => Some(437),
        _ => None,
    }
}

fn generate_syscall_bitmask(actions: &[WatchAction]) -> RuleSyscalls {
    let mut syscall_mask = RuleSyscalls::new_zeroed();

    // Collect unique syscall numbers across all actions
    let mut syscall_nums: HashSet<u32> = HashSet::new();
    for action in actions {
        for name in syscalls_for_action(action) {
            if let Some(nr) = syscall_number(name) {
                syscall_nums.insert(nr);
            }
        }
    }

    // Set the bit for each syscall number
    for nr in syscall_nums {
        syscall_mask.set(nr);
    }

    syscall_mask
}


fn generate_perm_bitmask(actions: &[WatchAction]) -> u32 {
    let mut bitmask = 0;
    for action in actions {
        match action {
            WatchAction::Read => bitmask |= 1 << 0,
            WatchAction::Write => bitmask |= 1 << 1,
            WatchAction::Execute => bitmask |= 1 << 2,
            WatchAction::Attributes => bitmask |= 1 << 3,
        }
    }
    bitmask
}

fn watch_to_rule(watch: &AuditWatch) -> Result<()> {
    // agony
    // https://man7.org/linux/man-pages/man7/audit.rules.7.html
    // https://man7.org/linux/man-pages/man8/auditctl.8.html
    // https://docs.rs/netlink-packet-audit/0.5.1/netlink_packet_audit/rules/struct.RuleMessage.html
    let flag = RuleFlags::FilterExit;
    let action = RuleAction::Always;
    let path_field = (
        {
            match watch.recursive {
                true => RuleField::Dir(String::from(watch.path.to_string_lossy())),
                // i literallyy have no idea what rulefield::watch is supposed to represent
                false => RuleField::Watch(String::from(watch.path.to_string_lossy())),
            }
        },
        RuleFieldFlags::None,
    );
    let perm_field = (
        { RuleField::Perm(generate_perm_bitmask(&watch.actions)) },
        RuleFieldFlags::BitMask,
    );
    let key_field = (
        { RuleField::Filterkey(watch.key.clone()) },
        RuleFieldFlags::None,
    );
    let mut rule_message = RuleMessage::new();
    rule_message.flags = flag;
    rule_message.action = action;
    rule_message.fields = vec![path_field, perm_field, key_field];
    rule_message.syscalls = generate_syscall_bitmask(&watch.actions);

    Ok(())
}

// TODO: to persist the auditctl rules between reboots, we need to add them to
// /etc/audit/audit.rules, this should be done at the same time as the watches
// are added to /etc/auditrs/rules.toml and auditctl.

/// Execute a raw `auditctl` command string.
///
/// The provided `command` should NOT include the leading `auditctl` binary
/// name, only its arguments (e.g. `"-a always,exit -F path=/tmp/foo -F
/// perm=rw"`).
fn execute_auditctl_command(command: &str) -> Result<()> {
    Command::new("sh")
        .arg("-c")
        .arg(format!("auditctl {}", command))
        .output()?;

    persist_audit_rule(command)?;
    Ok(())
}

/// Check the default audit rules file for the presence of the auditrs signature
/// at the top: `# auditrs` If it is not present, we clear the file and add the
/// signature.
///
/// TODO: This is a workaround avoiding that we should ultimately be loading the
/// audit rules from `/etc/auditrs/rules.toml` on system startup. Eventually,
/// when the custom auditctl implementation is underway, we should seek to
/// replace rewrite this function.
fn prepare_audit_rules_file() -> Result<()> {
    // Open the rules file for both reading and writing so we can inspect and,
    // if necessary, rewrite its contents.
    let mut rules_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(AUDIT_RULES_FILE)?;

    let mut reader = BufReader::new(&rules_file);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line != "# auditrs\n" {
        rules_file.seek(SeekFrom::Start(0))?;
        rules_file.set_len(0)?;
        rules_file.write_all(b"# auditrs\n")?;
        rules_file.flush()?;
    }
    Ok(())
}

/// Persist a single audit rule to the audit rules file at
/// `/etc/audit/audit.rules`.
///
/// **Parameters:**
///
/// * `rule`: The audit rule to persist.
fn persist_audit_rule(rule: &str) -> Result<()> {
    // This is a lot of unnecessary IO
    prepare_audit_rules_file()?;

    let mut rules_file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(AUDIT_RULES_FILE)?;

    rules_file.write_all(format!("{}\n", rule).as_bytes())?;
    rules_file.flush()?;
    Ok(())
}

/// Given an `AuditWatch`` and whether we are deleting or adding, return the
/// appropriate `auditctl` command.
///
/// **Parameters:**
///
/// * `watch`: The `AuditWatch` to convert to an `auditctl` command.
/// * `delete`: Whether we are deleting or adding the watch.
fn watch_to_auditctl_format(watch: &AuditWatch, delete: bool) -> String {
    let mut perms = String::new();
    for action in &watch.actions {
        match action {
            WatchAction::Read => perms.push('r'),
            WatchAction::Write => perms.push('w'),
            WatchAction::Execute => perms.push('x'),
            WatchAction::Attributes => perms.push('a'),
        }
    }

    // Using the auditctl cli tool, the dir argument automatically enables recursive
    // watching, the path argument does not allow recursive watching.
    let recursive_str;
    let mut path_str = String::from(watch.path.to_string_lossy());
    if watch.recursive {
        recursive_str = "dir=".to_string();
        if !path_str.ends_with('/') {
            path_str.push('/');
        }
    } else {
        recursive_str = "path=".to_string();
        if path_str.ends_with('/') {
            path_str.pop();
        }
    }
    let add_or_delete_str = if delete { "-d" } else { "-a" };
    format!(
        "{} always,exit -F {}{} -F perm={} -k {}",
        add_or_delete_str, recursive_str, path_str, perms, watch.key
    )
}

/// Build and execute the appropriate `auditctl` command for a single
/// `AuditWatch`.
///
/// **Parameters:**
///
/// * `watch`: The `AuditWatch` to execute the `auditctl` command for.
/// * `delete`: Whether we are deleting or adding the watch.
pub fn execute_watch_auditctl_command(watch: &AuditWatch, delete: bool) -> Result<()> {
    if !delete {
        let command = watch_to_auditctl_format(watch, false);
        return execute_auditctl_command(&command);
    }

    let delete_cmd = watch_to_auditctl_format(watch, true);
    println!("Deleting watch: {}", delete_cmd);
    execute_auditctl_command(&delete_cmd)
}
