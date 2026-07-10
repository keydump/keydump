//! Recover DB/master key by scanning `securityd` process memory (macOS).
//!
//! **SIP / privileges**
//! - Requires root (`sudo`).
//! - Requires the ability to `task_for_pid` + read `securityd` memory.
//! - Default SIP **Debugging Restrictions** usually block this even as root.
//! - Keychain must already be unlocked so keys are resident in the heap.

use std::process::Command;

use zeroize::Zeroizing;

use super::{DbKeyValidator, Unlocked};
use crate::crypto::{decrypt_db_key, MASTER_KEY_LEN};
use crate::error::{KdError, Result};
use crate::keychain::KeychainFile;

const DB_KEY_LEN: usize = 24;

extern "C" {
    fn geteuid() -> u32;
    fn task_for_pid(target_tport: u32, pid: i32, t: *mut u32) -> i32;
    fn mach_task_self() -> u32;
    fn mach_vm_read(
        target_task: u32,
        address: u64,
        size: u64,
        data: *mut usize,
        data_cnt: *mut u32,
    ) -> i32;
    fn vm_deallocate(target: u32, address: usize, size: usize) -> i32;
}

fn require_root() -> Result<()> {
    let euid = unsafe { geteuid() };
    if euid != 0 {
        return Err(KdError::Securityd(
            "must run as root (sudo). Also needs SIP Debugging Restrictions disabled \
             (default SIP blocks reading securityd memory even as root)"
                .into(),
        ));
    }
    Ok(())
}

fn securityd_pid() -> Result<i32> {
    let out = Command::new("pgrep")
        .args(["-x", "securityd"])
        .output()
        .map_err(|e| KdError::Securityd(format!("pgrep securityd: {e}")))?;
    if !out.status.success() {
        return Err(KdError::Securityd("securityd process not found".into()));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let pid: i32 = s
        .lines()
        .next()
        .and_then(|l| l.trim().parse().ok())
        .ok_or_else(|| KdError::Securityd("failed to parse securityd pid".into()))?;
    Ok(pid)
}

fn entropy_ok(key: &[u8]) -> bool {
    let mut seen = [false; 256];
    let mut u = 0usize;
    for &b in key {
        if !seen[b as usize] {
            seen[b as usize] = true;
            u += 1;
        }
    }
    u >= 10
}

/// Parse `vmmap -interleaved` for MALLOC_* rw regions (where key material lives).
fn malloc_regions(pid: i32) -> Result<Vec<(u64, u64)>> {
    let out = Command::new("vmmap")
        .args(["-interleaved", &pid.to_string()])
        .output()
        .map_err(|e| KdError::Securityd(format!("vmmap: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut regions = Vec::new();
    for line in text.lines() {
        if !line.contains("MALLOC") {
            continue;
        }
        if !line.contains("rw-") && !line.contains("rwx") {
            continue;
        }
        // e.g. MALLOC_TINY  10344c000-10384c000  [ 4096K ...]
        let mut found = None;
        for token in line.split_whitespace() {
            if let Some((a, b)) = token.split_once('-') {
                if a.len() >= 6 && b.len() >= 6 && a.chars().all(|c| c.is_ascii_hexdigit()) {
                    if let (Ok(start), Ok(end)) =
                        (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16))
                    {
                        if end > start && end - start <= 64 * 1024 * 1024 {
                            found = Some((start, end));
                            break;
                        }
                    }
                }
            }
        }
        if let Some(r) = found {
            regions.push(r);
        }
    }
    regions.sort_unstable();
    regions.dedup();
    if regions.is_empty() {
        return Err(KdError::Securityd(
            "vmmap found no MALLOC regions for securityd".into(),
        ));
    }
    Ok(regions)
}

/// Scan securityd MALLOC heaps for DB wrapping key (preferred) or master key.
pub fn unlock_from_securityd(kc: &KeychainFile) -> Result<Unlocked> {
    require_root()?;
    let pid = securityd_pid()?;

    let ct = kc
        .db_blob
        .ciphertext(&kc.data)
        .ok_or_else(|| KdError::InvalidKeychain("DBBlob ciphertext oob".into()))?;
    let iv = kc.db_blob.iv;
    let validator = DbKeyValidator::from_keychain(kc)?;

    let mut task: u32 = 0;
    let kr = unsafe { task_for_pid(mach_task_self(), pid, &mut task) };
    if kr != 0 {
        return Err(KdError::Securityd(format!(
            "task_for_pid(securityd) failed (kr={kr}). On default SIP this is expected: \
             Debugging Restrictions block process memory access. Options: provide --master-key, \
             use --password on legacy keychains (blobVersion 0x100), or run on a host where \
             debugging restrictions allow task_for_pid."
        )));
    }

    let regions = malloc_regions(pid)?;
    let region_count = regions.len();
    let mut scanned: u64 = 0;

    for (start, end) in &regions {
        let size = end - start;
        if let Some(hit) = scan_region(task, *start, size, &iv, ct, &validator) {
            return Ok(hit);
        }
        scanned = scanned.saturating_add(size);
    }

    Err(KdError::Securityd(format!(
        "no valid DB/master key found in securityd MALLOC heaps (scanned ~{} MB, {region_count} regions). \
         Ensure the keychain is unlocked (e.g. security unlock-keychain), then retry. \
         If SIP Debugging Restrictions are enabled, memory scan cannot work — use --master-key \
         obtained by other authorized means, or --password on legacy (non-SEP) keychains.",
        scanned / (1024 * 1024)
    )))
}

fn scan_region(
    task: u32,
    address: u64,
    size: u64,
    db_iv: &[u8; 8],
    db_ct: &[u8],
    validator: &DbKeyValidator,
) -> Option<Unlocked> {
    let mut data_ptr: usize = 0;
    let mut data_cnt: u32 = 0;
    let kr = unsafe { mach_vm_read(task, address, size, &mut data_ptr, &mut data_cnt) };
    if kr != 0 || data_cnt < DB_KEY_LEN as u32 {
        return None;
    }
    let mem = unsafe { std::slice::from_raw_parts(data_ptr as *const u8, data_cnt as usize) };

    // Pass 1: DB key directly
    let mut off = 0usize;
    while off + DB_KEY_LEN <= mem.len() {
        let cand = &mem[off..off + DB_KEY_LEN];
        if entropy_ok(cand) && validator.validates(cand) {
            let db_key = Zeroizing::new(cand.to_vec());
            unsafe {
                let _ = vm_deallocate(mach_task_self(), data_ptr, data_cnt as usize);
            }
            return Some(Unlocked {
                db_key,
                master_key: None,
                method: "securityd-dbkey",
            });
        }
        off += 4;
    }

    // Pass 2: master key → DB key
    off = 0;
    while off + MASTER_KEY_LEN <= mem.len() {
        let master = &mem[off..off + MASTER_KEY_LEN];
        if entropy_ok(master) {
            if let Ok(db_key) = decrypt_db_key(master, db_iv, db_ct) {
                if validator.validates(&db_key) {
                    let master_z = Zeroizing::new(master.to_vec());
                    unsafe {
                        let _ = vm_deallocate(mach_task_self(), data_ptr, data_cnt as usize);
                    }
                    return Some(Unlocked {
                        db_key,
                        master_key: Some(master_z),
                        method: "securityd-master",
                    });
                }
            }
        }
        off += 4;
    }

    unsafe {
        let _ = vm_deallocate(mach_task_self(), data_ptr, data_cnt as usize);
    }
    None
}
