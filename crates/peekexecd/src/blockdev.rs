//! What a disk a request names really is: the classic hardware mistake is
//! the right command on the wrong disk (`dd of=/dev/sda` meant for the
//! USB stick at `/dev/sdb`). `/dev/sdX` names say nothing, so each block
//! device a request names is described in one line: what it reports
//! itself as, its size, how it is attached, and what on it is in use
//! (mounted, swap, held by LVM or RAID). A device in use becomes a note,
//! so it takes a click; one that is not is a fact under the command.
//!
//! Read in the inspection helper, as the user (R1): sysfs and
//! `/proc/self/mountinfo` are readable by everyone. The model string is
//! the device's own claim (a USB device can call itself anything), so it
//! is quoted as such and reduced to plain characters; size, attachment
//! and use come from the kernel.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// One line of plain text, escaped where the view is built.
    pub text: String,
    /// Something on it is mounted, used as swap or held by another device.
    pub in_use: bool,
}

/// Devices described in one request; more get one line that says so.
pub const MAX_DESCRIBED: usize = 4;
/// Uses listed for one device.
const MAX_USES: usize = 6;
/// Devices followed through partitions and holders.
const MAX_NODES: usize = 64;

/// The kernel's state, as the files it is read from.
pub struct System<'a> {
    /// A sysfs root (`/sys`).
    pub sys: &'a Path,
    /// `/proc/self/mountinfo`.
    pub mountinfo: &'a str,
    /// `major:minor` of each device used as swap.
    pub swaps: &'a [String],
}

/// A name a request uses for a disk, and the device it led to when shown
/// (`major:minor`). Names under `/dev/disk/by-label` and the like follow
/// disk content, and a link of the user's can be re-pointed: root checks
/// each name again just before running ([`same_disks`]).
pub type Bound = (String, String);

/// Every block device among `paths` (relative ones from `cwd`), each once.
#[cfg(target_os = "linux")]
pub fn describe(paths: impl Iterator<Item = String>, cwd: &str) -> Vec<Device> {
    describe_and_bind(paths, cwd).0
}

/// [`describe`], and every name that led to a block device, bound to it.
#[cfg(target_os = "linux")]
pub fn describe_and_bind(
    paths: impl Iterator<Item = String>,
    cwd: &str,
) -> (Vec<Device>, Vec<Bound>) {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let block = |p: &Path| {
        std::fs::metadata(p)
            .ok()
            .filter(|m| m.file_type().is_block_device())
            .map(|m| majmin(m.rdev()))
    };
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let swaps: Vec<String> = std::fs::read_to_string("/proc/swaps")
        .unwrap_or_default()
        .lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next())
        .filter_map(|p| block(Path::new(&unescape(p))))
        .collect();
    let system = System {
        sys: Path::new("/sys"),
        mountinfo: &mountinfo,
        swaps: &swaps,
    };
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut bound = Vec::new();
    let mut more = 0;
    // Every word, not only those with a `/`: `--cwd /dev` makes `sda` a
    // disk. And the value of `key=value` (`dd of=sda`).
    let words = paths.flat_map(|p| {
        let value = p.split_once('=').map(|(_, v)| v.to_string());
        std::iter::once(p).chain(value)
    });
    // Distinct words only, so repeats cost nothing; past the bound the
    // answer is "not looked at", said, never a silent pass.
    let mut checked = std::collections::HashSet::new();
    let mut unchecked = false;
    for p in words.filter(|p| !p.is_empty()) {
        if checked.contains(&p) {
            continue;
        }
        if checked.len() == MAX_WORDS_CHECKED {
            unchecked = true;
            break;
        }
        checked.insert(p.clone());
        let at = Path::new(cwd).join(&p);
        let Some(mm) = block(&at) else {
            continue;
        };
        bound.push((at.to_string_lossy().into_owned(), mm.clone()));
        if !seen.insert(mm.clone()) {
            continue;
        }
        if out.len() == MAX_DESCRIBED {
            more += 1;
            continue;
        }
        out.extend(describe_at(&system, &p, &mm));
    }
    if more > 0 {
        out.push(Device {
            text: format!("This request names {more} more disks, not described here."),
            in_use: true,
        });
    }
    if unchecked {
        out.push(Device {
            text: format!(
                "This request has more than {MAX_WORDS_CHECKED} different words: disks it names \
                 after those were not looked for."
            ),
            in_use: true,
        });
    }
    (out, bound)
}

/// Just before running, as root (after approval, so rule 1 allows it):
/// each name still leads to the device the human was shown, or nothing
/// runs. A disk attached with another's label, then detached, would
/// otherwise move `/dev/disk/by-label/X` from the decoy shown to the disk
/// written.
#[cfg(target_os = "linux")]
pub fn same_disks(bound: &[Bound]) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    for (name, was) in bound {
        let now = std::fs::metadata(name)
            .ok()
            .filter(|m| m.file_type().is_block_device())
            .map(|m| majmin(m.rdev()));
        if now.as_deref() != Some(was.as_str()) {
            // What root sees now stays in the journal: the requester learns
            // only that the name moved.
            eprintln!(
                "peekexecd: disk name {name:?} moved since it was shown: was {was}, now {}",
                now.as_deref().unwrap_or("none")
            );
            return Err(format!(
                "not run: {} no longer leads to the disk that was shown",
                clean_path(name)
            ));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn same_disks(_: &[Bound]) -> Result<(), String> {
    Ok(())
}

/// Distinct words checked for a disk (one `stat` each, inside the
/// helper's time limit), as for the path note.
pub const MAX_WORDS_CHECKED: usize = 1000;

#[cfg(not(target_os = "linux"))]
pub fn describe(_: impl Iterator<Item = String>, _: &str) -> Vec<Device> {
    Vec::new()
}

#[cfg(not(target_os = "linux"))]
pub fn describe_and_bind(_: impl Iterator<Item = String>, _: &str) -> (Vec<Device>, Vec<Bound>) {
    (Vec::new(), Vec::new())
}

/// `major:minor` of a Linux `dev_t` (glibc's encoding).
#[cfg(target_os = "linux")]
fn majmin(dev: u64) -> String {
    let major = ((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0x0000_0fff);
    let minor = ((dev >> 12) & 0xffff_ff00) | (dev & 0x0000_00ff);
    format!("{major}:{minor}")
}

/// The device `major:minor` is, named `shown` in the request.
pub fn describe_at(system: &System, shown: &str, majmin: &str) -> Option<Device> {
    let node = system
        .sys
        .join("dev/block")
        .join(majmin)
        .canonicalize()
        .ok()?;
    let name = file_name(&node);
    let partition = read(&node.join("partition"));
    let disk = if partition.is_some() {
        node.parent()?.to_path_buf()
    } else {
        node.clone()
    };
    let what = identity(&disk);
    let size = read(&node.join("size"))
        .and_then(|s| s.parse::<u64>().ok())
        .map(|sectors| human(sectors.saturating_mul(512)));
    let size = size.unwrap_or_else(|| "size unknown".into());
    let dev = format!("/dev/{name}");
    // The kernel's name and facts lead; the name the request used comes
    // last, plain and short, so requester text can neither pass for a
    // fact nor push one past a cut.
    let named = dev.clone();
    let mut text = match &partition {
        Some(n) => {
            let disk_size = read(&disk.join("size"))
                .and_then(|s| s.parse::<u64>().ok())
                .map(|s| human(s.saturating_mul(512)))
                .unwrap_or_else(|| "size unknown".into());
            format!(
                "{named}: partition {n}, {size}, of /dev/{} ({what}, {disk_size})",
                file_name(&disk)
            )
        }
        None => format!("{named}: {what}, {size}"),
    };
    let uses = uses(system, &node, partition.is_none());
    if uses.is_empty() {
        text.push_str("; nothing on it is mounted or swap.");
    } else {
        text.push_str(&format!("; in use: {}.", uses.join(", ")));
    }
    if shown != dev {
        let short: String = shown.chars().take(60).collect();
        let cut = if short.len() < shown.len() { "…" } else { "" };
        text.push_str(&format!(" Named as {}{cut}.", clean_path(&short)));
    }
    Some(Device {
        text,
        in_use: !uses.is_empty(),
    })
}

/// What the device says it is, and how it is attached.
fn identity(disk: &Path) -> String {
    if let Some(name) = read(&disk.join("dm/name")) {
        return format!("device-mapper volume {}", clean(&name));
    }
    if let Some(file) = read(&disk.join("loop/backing_file")) {
        return format!("loop device of {}", clean(&file));
    }
    let vendor = read(&disk.join("device/vendor")).unwrap_or_default();
    let model = read(&disk.join("device/model")).unwrap_or_default();
    // "ATA" is the transport, not a maker.
    let label = [vendor.as_str(), model.as_str()]
        .iter()
        .filter(|s| !s.is_empty() && **s != "ATA")
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    let path = disk.to_string_lossy();
    let attached = if path.contains("/devices/virtual/") {
        "virtual disk"
    } else if path.contains("/usb") {
        "USB disk"
    } else if path.contains("/mmc") {
        "SD/MMC card"
    } else if read(&disk.join("removable")).as_deref() == Some("1") {
        "removable disk"
    } else {
        "internal disk"
    };
    if label.is_empty() {
        format!("{attached}, no model name")
    } else {
        // In quotes: the device's own claim, not the kernel's.
        format!("{attached} \"{}\"", clean(&label))
    }
}

/// Mounts, swap and holders of `node`, its partitions if it is a whole
/// disk, and whatever is built on them (LVM, RAID, encryption).
fn uses(system: &System, node: &Path, whole: bool) -> Vec<String> {
    let mut nodes = vec![node.to_path_buf()];
    if whole {
        if let Ok(entries) = std::fs::read_dir(node) {
            let mut parts: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.join("partition").exists())
                .collect();
            parts.sort();
            nodes.extend(parts);
        }
    }
    // Devices built on these (LVM, RAID, encryption) follow them.
    let built_on_from = nodes.len();
    let mut i = 0;
    while i < nodes.len() && nodes.len() < MAX_NODES {
        if let Ok(entries) = std::fs::read_dir(nodes[i].join("holders")) {
            for e in entries.flatten() {
                let held = system.sys.join("class/block").join(e.file_name());
                let held = held.canonicalize().unwrap_or(held);
                if !nodes.contains(&held) {
                    nodes.push(held);
                }
            }
        }
        i += 1;
    }
    let mut out = Vec::new();
    for (i, n) in nodes.iter().enumerate() {
        let label = read(&n.join("dm/name")).unwrap_or_else(|| file_name(n));
        let on = if n == node {
            String::new()
        } else {
            format!(" (on {})", clean(&label))
        };
        let mm = read(&n.join("dev")).unwrap_or_default();
        let sources = [
            format!("/dev/{}", file_name(n)),
            format!("/dev/mapper/{label}"),
        ];
        let before = out.len();
        for (dev, source, mount) in mounts(system.mountinfo) {
            if (!mm.is_empty() && dev == mm) || sources.contains(&source) {
                out.push(format!("{}{on}", clean(&mount)));
            }
        }
        if !mm.is_empty() && system.swaps.contains(&mm) {
            out.push(format!("swap{on}"));
        }
        // Built on this device, and itself neither mounted, swap, nor the
        // base of something else (an unmounted LVM volume, a RAID array):
        // writing under it still destroys it.
        let holds_more = std::fs::read_dir(n.join("holders")).is_ok_and(|mut d| d.next().is_some());
        if i >= built_on_from && out.len() == before && !holds_more {
            out.push(format!("held by {}", clean(&label)));
        }
    }
    out.dedup();
    // The root filesystem first: it is the one that matters most.
    out.sort_by_key(|u| !(u == "/" || u.starts_with("/ ")));
    if out.len() > MAX_USES {
        let more = out.len() - MAX_USES;
        out.truncate(MAX_USES);
        out.push(format!("{more} more"));
    }
    out
}

/// `(major:minor, source, mount point)` of each line of mountinfo.
fn mounts(mountinfo: &str) -> impl Iterator<Item = (String, String, String)> + '_ {
    mountinfo.lines().filter_map(|l| {
        let (before, after) = l.split_once(" - ")?;
        let f: Vec<&str> = before.split(' ').collect();
        let source = after.split(' ').nth(1)?;
        Some((f.get(2)?.to_string(), unescape(source), unescape(f.get(4)?)))
    })
}

/// The kernel writes space, tab, newline and backslash in mountinfo and
/// /proc/swaps as `\ooo`.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let oct = b
            .get(i + 1..i + 4)
            .filter(|o| o.iter().all(|c| (b'0'..=b'7').contains(c)));
        match (b[i], oct) {
            (b'\\', Some(o)) => {
                out.push((o[0] - b'0') * 64 + (o[1] - b'0') * 8 + (o[2] - b'0'));
                i += 4;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Text a device or a mounter chose, made plain: what is not a letter,
/// digit or ` ._-/:+` becomes `?`, so it cannot fake punctuation of the
/// line it sits in, and it is cut.
fn clean(s: &str) -> String {
    let plain: String = s
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || " ._-/:+".contains(c) {
                c
            } else {
                '?'
            }
        })
        .collect();
    if plain.chars().count() > 48 {
        format!("{}…", plain.chars().take(47).collect::<String>())
    } else {
        plain
    }
}

/// A path the request gave, made plain like [`clean`] but uncut here.
pub fn clean_path(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-/:+@".contains(c) {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// Bytes in decimal units, as disks are sold.
fn human(bytes: u64) -> String {
    for (unit, name) in [(1e12, "TB"), (1e9, "GB"), (1e6, "MB"), (1e3, "kB")] {
        if bytes as f64 >= unit {
            return format!("{:.1} {name}", bytes as f64 / unit);
        }
    }
    format!("{bytes} bytes")
}

fn read(p: &Path) -> Option<String> {
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A sysfs tree like this machine's: an internal SATA disk whose
    /// partition 3 holds LVM with the root filesystem, a USB stick, and
    /// an unused internal disk.
    fn fake_sys(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("pe-blk-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let put = |p: &str, s: &str| {
            let p = root.join(p);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, s).unwrap();
        };
        let sda = "devices/pci0000:00/ata1/host0/target0:0:0/0:0:0:0/block/sda";
        put(&format!("{sda}/size"), "1953525168\n");
        put(&format!("{sda}/removable"), "0\n");
        put(&format!("{sda}/dev"), "8:0\n");
        put(&format!("{sda}/device/vendor"), "ATA     \n");
        put(&format!("{sda}/device/model"), "WDC WDS100T2B0A\n");
        put(&format!("{sda}/sda1/partition"), "1\n");
        put(&format!("{sda}/sda1/size"), "1048576\n");
        put(&format!("{sda}/sda1/dev"), "8:1\n");
        put(&format!("{sda}/sda3/partition"), "3\n");
        put(&format!("{sda}/sda3/size"), "1900000000\n");
        put(&format!("{sda}/sda3/dev"), "8:3\n");
        put(&format!("{sda}/sda3/holders/dm-0"), "");
        let dm = "devices/virtual/block/dm-0";
        put(&format!("{dm}/dev"), "253:0\n");
        put(&format!("{dm}/size"), "1890000000\n");
        put(&format!("{dm}/dm/name"), "vgubuntu-root\n");
        let sdb = "devices/pci0000:00/usb1/1-1/1-1:1.0/host6/target6:0:0/6:0:0:0/block/sdb";
        put(&format!("{sdb}/size"), "62521344\n");
        put(&format!("{sdb}/removable"), "1\n");
        put(&format!("{sdb}/dev"), "8:16\n");
        put(&format!("{sdb}/device/model"), "Ultra\n");
        let sdc = "devices/pci0000:00/ata2/host1/target1:0:0/1:0:0:0/block/sdc";
        put(&format!("{sdc}/size"), "3907029168\n");
        put(&format!("{sdc}/removable"), "0\n");
        put(&format!("{sdc}/dev"), "8:32\n");
        put(&format!("{sdc}/device/model"), "Evil\" 1 TB, USB\nhidden\n");
        let link = |at: &str, to: &str| {
            let at = root.join(at);
            fs::create_dir_all(at.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(root.join(to), at).unwrap();
        };
        link("dev/block/8:0", sda);
        link("dev/block/8:1", &format!("{sda}/sda1"));
        link("dev/block/8:3", &format!("{sda}/sda3"));
        link("dev/block/253:0", dm);
        link("class/block/dm-0", dm);
        link("dev/block/8:16", sdb);
        link("dev/block/8:32", sdc);
        root
    }

    const MOUNTINFO: &str = "\
26 1 253:0 / / rw,relatime shared:1 - ext4 /dev/mapper/vgubuntu-root rw
30 26 8:1 / /boot/efi rw,relatime shared:3 - vfat /dev/sda1 rw
";

    fn system<'a>(root: &'a Path, mountinfo: &'a str, swaps: &'a [String]) -> System<'a> {
        System {
            sys: root,
            mountinfo,
            swaps,
        }
    }

    #[test]
    fn the_system_disk_says_it_holds_root() {
        let root = fake_sys("sda");
        let d = describe_at(&system(&root, MOUNTINFO, &[]), "/dev/sda", "8:0").unwrap();
        assert!(d.in_use, "{d:?}");
        for part in [
            "/dev/sda: internal disk",
            "\"WDC WDS100T2B0A\"",
            "1.0 TB",
            "/ (on vgubuntu-root)",
            "/boot/efi (on sda1)",
        ] {
            assert!(d.text.contains(part), "{part}: {}", d.text);
        }
        assert!(
            d.text.contains("; in use: / (on vgubuntu-root), /boot/efi"),
            "{}",
            d.text
        );
        // Named the careful way, it says which /dev name that is.
        let d = describe_at(
            &system(&root, MOUNTINFO, &[]),
            "/dev/disk/by-id/ata-WDC",
            "8:0",
        );
        assert!(d.unwrap().text.starts_with("/dev/sda: internal"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_partition_names_its_disk_and_its_own_use() {
        let root = fake_sys("part");
        let s = system(&root, MOUNTINFO, &[]);
        let d = describe_at(&s, "/dev/sda1", "8:1").unwrap();
        assert!(d.in_use);
        assert!(
            d.text.contains("partition 1, 536.9 MB, of /dev/sda"),
            "{}",
            d.text
        );
        assert!(d.text.contains("/boot/efi"), "{}", d.text);
        assert!(!d.text.contains("vgubuntu"), "only its own use: {}", d.text);
        // Held by LVM, not mounted itself: still in use.
        let d = describe_at(&s, "/dev/sda3", "8:3").unwrap();
        assert!(d.in_use);
        assert!(d.text.contains("/ (on vgubuntu-root)"), "{}", d.text);
        // Swap counts.
        let swaps = ["8:16".to_string()];
        let d = describe_at(&system(&root, "", &swaps), "/dev/sdb", "8:16").unwrap();
        assert!(d.in_use && d.text.contains("swap"), "{}", d.text);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_unused_usb_stick_is_a_fact_not_a_warning() {
        let root = fake_sys("usb");
        let d = describe_at(&system(&root, MOUNTINFO, &[]), "/dev/sdb", "8:16").unwrap();
        assert!(!d.in_use, "{d:?}");
        assert_eq!(
            d.text,
            "/dev/sdb: USB disk \"Ultra\", 32.0 GB; nothing on it is mounted or swap."
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn mounted_by_source_when_the_number_is_anonymous() {
        // btrfs reports an anonymous device number in mountinfo.
        let root = fake_sys("btrfs");
        let mi = "40 1 0:45 / /media/u/MY\\040STICK rw - btrfs /dev/sdb rw\n";
        let d = describe_at(&system(&root, mi, &[]), "/dev/sdb", "8:16").unwrap();
        assert!(d.in_use);
        assert!(d.text.contains("/media/u/MY STICK"), "{}", d.text);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn what_the_device_calls_itself_cannot_fake_the_line() {
        let root = fake_sys("evil");
        let d = describe_at(&system(&root, "", &[]), "/dev/sdc", "8:32").unwrap();
        assert!(!d.text.contains('\n'), "{}", d.text);
        assert!(
            d.text.contains("\"Evil? 1 TB? USB hidden\""),
            "quotes, commas and line breaks are plain: {}",
            d.text
        );
        assert!(d.text.contains("internal disk \"Evil"), "{}", d.text);
        fs::remove_dir_all(&root).unwrap();
    }

    // A name the requester made (a link of its own) cannot pass for the
    // kernel's facts, nor push them past a cut.
    #[test]
    fn the_name_used_comes_last_and_plain() {
        let root = fake_sys("named");
        let s = system(&root, MOUNTINFO, &[]);
        let fake = "/home/u/x: USB disk \"SanDisk\", 32 GB; nothing on it is mounted";
        let d = describe_at(&s, fake, "8:0").unwrap();
        assert!(d.text.starts_with("/dev/sda: internal disk"), "{}", d.text);
        assert!(
            d.text.contains("; in use: / (on vgubuntu-root)"),
            "{}",
            d.text
        );
        let tail = d.text.split(" Named as ").nth(1).unwrap();
        assert!(!tail.contains(['"', ';', ' ', ',']), "{tail}");
        let long = format!("/dev/disk/by-id/{}", "a".repeat(200));
        let d = describe_at(&s, &long, "8:0").unwrap();
        assert!(
            d.text.ends_with("aaa….") && d.text.len() < 300,
            "{}",
            d.text
        );
        fs::remove_dir_all(&root).unwrap();
    }

    /// `--cwd /dev` with a bare `sda`, and `of=sda`, name a disk too.
    #[cfg(target_os = "linux")]
    #[test]
    fn bare_names_in_a_device_directory_are_disks() {
        let Some(disk) = std::fs::read_dir("/sys/block").ok().and_then(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .find(|n| Path::new("/dev").join(n).exists())
        }) else {
            eprintln!("skipped: no block device");
            return;
        };
        for word in [disk.clone(), format!("of={disk}")] {
            let out = describe(std::iter::once(word.clone()), "/dev");
            assert_eq!(out.len(), 1, "{word}: {out:?}");
            assert!(out[0].text.starts_with(&format!("/dev/{disk}")), "{out:?}");
        }
        // Elsewhere a bare word is a file name, and no disk.
        assert!(describe(std::iter::once(disk), "/").is_empty());
    }

    // A long script cannot hide a disk past the bound: it says so instead.
    #[cfg(target_os = "linux")]
    #[test]
    fn past_the_bound_it_says_so() {
        let Some(disk) = std::fs::read_dir("/sys/block").ok().and_then(|d| {
            d.flatten()
                .map(|e| format!("/dev/{}", e.file_name().to_string_lossy()))
                .find(|n| Path::new(n).exists())
        }) else {
            eprintln!("skipped: no block device");
            return;
        };
        // Repeats cost nothing.
        let repeated = std::iter::repeat("x".to_string()).take(5000);
        let out = describe(repeated.chain(std::iter::once(disk.clone())), "/");
        assert_eq!(out.len(), 1, "{out:?}");
        let many = (0..=MAX_WORDS_CHECKED).map(|i| format!("w{i}"));
        let out = describe(many.chain(std::iter::once(disk)), "/");
        assert!(
            out.iter()
                .any(|d| d.in_use && d.text.contains("were not looked for")),
            "{out:?}"
        );
    }

    // A name re-pointed after it was shown (a udev name that follows disk
    // content, or a link of the user's): nothing runs.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_name_that_moved_to_another_disk_stops_the_run() {
        let disks: Vec<String> = std::fs::read_dir("/sys/block")
            .map(|d| {
                d.flatten()
                    .map(|e| format!("/dev/{}", e.file_name().to_string_lossy()))
                    .filter(|n| Path::new(n).exists())
                    .collect()
            })
            .unwrap_or_default();
        let Some(first) = disks.first() else {
            eprintln!("skipped: no block device");
            return;
        };
        let dir = std::env::temp_dir().join(format!("pe-bound-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let link = dir.join("disk");
        std::os::unix::fs::symlink(first, &link).unwrap();
        let (_, bound) = describe_and_bind(std::iter::once(link.display().to_string()), "/");
        assert_eq!(bound.len(), 1, "{bound:?}");
        assert!(same_disks(&bound).is_ok());
        // Re-pointed at another disk, or at something that is no disk.
        fs::remove_file(&link).unwrap();
        let other = disks.get(1).map(String::as_str).unwrap_or("/dev/null");
        std::os::unix::fs::symlink(other, &link).unwrap();
        let e = same_disks(&bound).unwrap_err();
        assert!(
            e.contains("no longer leads to the disk that was shown"),
            "{e}"
        );
        fs::remove_file(&link).unwrap();
        assert!(same_disks(&bound).is_err(), "gone is not the same either");
        fs::remove_dir_all(&dir).unwrap();
        // Every name is bound, not only the first one per disk.
        let twice = [first.clone(), format!("/dev/./{}", &first[5..])];
        let (_, bound) = describe_and_bind(twice.into_iter(), "/");
        assert_eq!(bound.len(), 2, "{bound:?}");
    }

    #[test]
    fn unknown_numbers_and_sizes() {
        let root = fake_sys("none");
        assert!(describe_at(&system(&root, "", &[]), "/dev/x", "9:9").is_none());
        assert_eq!(human(999), "999 bytes");
        assert_eq!(human(32_010_928_128), "32.0 GB");
        assert_eq!(unescape("a\\040b\\134c\\9"), "a b\\c\\9");
        fs::remove_dir_all(&root).unwrap();
    }

    /// On the machine running the tests: whatever disks it has are
    /// described from the real /sys, without a panic, each once.
    #[cfg(target_os = "linux")]
    #[test]
    fn real_disks_are_described() {
        let names: Vec<String> = std::fs::read_dir("/sys/block")
            .map(|d| {
                d.flatten()
                    .map(|e| format!("/dev/{}", e.file_name().to_string_lossy()))
                    .collect()
            })
            .unwrap_or_default();
        let twice = names.iter().chain(names.iter()).cloned();
        let out = describe(twice, "/");
        assert!(out.len() <= MAX_DESCRIBED + 1);
        for d in &out {
            assert!(
                d.text.starts_with("/dev/") || d.text.starts_with("This request"),
                "{d:?}"
            );
            eprintln!("{}", d.text);
        }
    }

    // An LVM volume that is active but not mounted still makes its
    // partition in use.
    #[test]
    fn an_unmounted_volume_still_holds_its_partition() {
        let root = fake_sys("lvm");
        let d = describe_at(&system(&root, "", &[]), "/dev/sda3", "8:3").unwrap();
        assert!(d.in_use, "{d:?}");
        assert!(d.text.contains("held by vgubuntu-root"), "{}", d.text);
        fs::remove_dir_all(&root).unwrap();
    }
}
