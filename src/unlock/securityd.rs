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
const SCAN_CHUNK_SIZE: u64 = 4 * 1024 * 1024;
const CANDIDATE_ALIGNMENT: u64 = 4;

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
    fn mach_port_deallocate(task: u32, name: u32) -> i32;
}

struct MachTask(u32);

impl MachTask {
    fn for_pid(pid: i32) -> Result<Self> {
        let mut task = 0;
        let kr = unsafe { task_for_pid(mach_task_self(), pid, &mut task) };
        if kr != 0 {
            return Err(KdError::Securityd(format!(
                "task_for_pid(securityd) failed (kr={kr}). On default SIP this is expected: \
                 Debugging Restrictions block process memory access. Options: provide --master-key, \
                 use --password on legacy keychains (blobVersion 0x100), or run on a host where \
                 debugging restrictions allow task_for_pid."
            )));
        }
        Ok(Self(task))
    }
}

impl Drop for MachTask {
    fn drop(&mut self) {
        unsafe {
            let _ = mach_port_deallocate(mach_task_self(), self.0);
        }
    }
}

struct MachReadBuffer {
    ptr: usize,
    len: usize,
}

impl MachReadBuffer {
    fn read(task: u32, address: u64, size: u64) -> Option<Self> {
        let mut ptr = 0usize;
        let mut count = 0u32;
        let kr = unsafe { mach_vm_read(task, address, size, &mut ptr, &mut count) };
        if kr != 0 || ptr == 0 || count == 0 {
            if ptr != 0 && count != 0 {
                unsafe {
                    let _ = vm_deallocate(mach_task_self(), ptr, count as usize);
                }
            }
            return None;
        }
        Some(Self {
            ptr,
            len: count as usize,
        })
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}

impl Drop for MachReadBuffer {
    fn drop(&mut self) {
        unsafe {
            let _ = vm_deallocate(mach_task_self(), self.ptr, self.len);
        }
    }
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
    let out = Command::new("/usr/bin/pgrep")
        .args(["-x", "-o", "securityd"])
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
    let out = Command::new("/usr/bin/vmmap")
        .args(["-interleaved", &pid.to_string()])
        .output()
        .map_err(|e| KdError::Securityd(format!("vmmap: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(KdError::Securityd(format!(
            "vmmap failed: {}",
            stderr.trim()
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let regions = parse_malloc_regions(&text);
    if regions.is_empty() {
        return Err(KdError::Securityd(
            "vmmap found no MALLOC regions for securityd".into(),
        ));
    }
    Ok(regions)
}

fn parse_malloc_regions(text: &str) -> Vec<(u64, u64)> {
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
                        if end > start {
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
    regions
}

/// Scan securityd MALLOC heaps for DB wrapping key (preferred) or master key.
pub fn unlock_from_securityd(kc: &KeychainFile) -> Result<Unlocked> {
    require_root()?;
    let pid = securityd_pid()?;

    let ct = kc.database_ciphertext()?;
    let iv = *kc.database_iv();
    let validator = DbKeyValidator::from_keychain(kc)?;

    let task = MachTask::for_pid(pid)?;

    let regions = malloc_regions(pid)?;
    let region_count = regions.len();
    let scanned: u64 = regions.iter().map(|(start, end)| end - start).sum();

    // Heap allocations are normally aligned. Scan aligned candidates across
    // the whole heap first, then the remaining byte alignments as fallbacks.
    for alignment in 0..CANDIDATE_ALIGNMENT {
        for (start, end) in &regions {
            let size = end - start;
            if let Some(hit) = scan_region(task.0, *start, size, alignment, &iv, ct, &validator) {
                return Ok(hit);
            }
        }
    }

    Err(KdError::Securityd(format!(
        "no valid DB/master key found in securityd MALLOC heaps (scanned ~{} MB, {region_count} regions, 4 alignment passes). \
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
    alignment: u64,
    db_iv: &[u8; 8],
    db_ct: &[u8],
    validator: &DbKeyValidator,
) -> Option<Unlocked> {
    let end = address.checked_add(size)?;
    let overlap = (MASTER_KEY_LEN - 1) as u64;
    let mut cursor = address;
    while cursor < end {
        let main_size = (end - cursor).min(SCAN_CHUNK_SIZE);
        let read_size = (end - cursor).min(main_size.saturating_add(overlap));
        if let Some(buffer) = MachReadBuffer::read(task, cursor, read_size) {
            if let Some(hit) = scan_bytes(
                buffer.as_slice(),
                cursor,
                main_size as usize,
                alignment,
                db_iv,
                db_ct,
                validator,
            ) {
                return Some(hit);
            }
        }
        cursor = cursor.checked_add(main_size)?;
    }
    None
}

fn candidate_offsets(
    base_address: u64,
    buffer_len: usize,
    start_limit: usize,
    alignment: u64,
) -> impl Iterator<Item = usize> {
    let first = ((alignment + CANDIDATE_ALIGNMENT - (base_address % CANDIDATE_ALIGNMENT))
        % CANDIDATE_ALIGNMENT) as usize;
    let max_start = start_limit.min(buffer_len.saturating_sub(MASTER_KEY_LEN - 1));
    (first..max_start).step_by(CANDIDATE_ALIGNMENT as usize)
}

fn scan_bytes(
    mem: &[u8],
    base_address: u64,
    start_limit: usize,
    alignment: u64,
    db_iv: &[u8; 8],
    db_ct: &[u8],
    validator: &DbKeyValidator,
) -> Option<Unlocked> {
    if mem.len() < MASTER_KEY_LEN {
        return None;
    }

    // Pass 1: DB key directly
    for off in candidate_offsets(base_address, mem.len(), start_limit, alignment) {
        let cand = &mem[off..off + DB_KEY_LEN];
        if entropy_ok(cand) && validator.validates(cand) {
            let db_key = Zeroizing::new(cand.to_vec());
            return Some(Unlocked {
                db_key,
                master_key: None,
                method: "securityd-dbkey",
            });
        }
    }

    // Pass 2: master key → DB key
    for off in candidate_offsets(base_address, mem.len(), start_limit, alignment) {
        let master = &mem[off..off + MASTER_KEY_LEN];
        if entropy_ok(master) {
            if let Ok(db_key) = decrypt_db_key(master, db_iv, db_ct) {
                if validator.validates(&db_key) {
                    let master_z = Zeroizing::new(master.to_vec());
                    return Some(Unlocked {
                        db_key,
                        master_key: Some(master_z),
                        method: "securityd-master",
                    });
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{candidate_offsets, parse_malloc_regions};

    #[test]
    fn vmmap_parser_keeps_large_readable_malloc_regions() {
        let text = "\
MALLOC_TINY  100000000-100001000  [   4K] rw-/rwx SM=PRV
MALLOC_LARGE 200000000-208000000  [ 128M] rw-/rwx SM=PRV
__TEXT       300000000-300001000  [   4K] r-x/r-x SM=COW\n";

        assert_eq!(
            parse_malloc_regions(text),
            vec![(0x100000000, 0x100001000), (0x200000000, 0x208000000)]
        );
    }

    #[test]
    fn alignment_passes_cover_every_candidate_offset_once() {
        let base = 0x1001;
        let buffer_len = 64;
        let expected: Vec<_> = (0..=buffer_len - 24).collect();
        let mut actual = Vec::new();
        for alignment in 0..4 {
            actual.extend(candidate_offsets(base, buffer_len, buffer_len, alignment));
        }
        actual.sort_unstable();

        assert_eq!(actual, expected);
    }
}
