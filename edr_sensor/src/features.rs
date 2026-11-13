//! The 99 behavioral features, ported 1:1 from `build_behavioral_dataset.py`.
//!
//! Any change here must be mirrored in the Python builder (and vice versa),
//! otherwise the models score vectors they were never trained on.
//! `parity_check.py` compares this code against `dataset/behavioral_dataset.npz`.

use regex::{NoExpand, Regex};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

/// Events per process the training window used (first N by SystemTime).
pub const WINDOW: usize = 50;
pub const FEATURE_DIM: usize = 99;

/// One Sysmon event, reduced to the fields the feature schema reads.
/// Missing fields are empty strings, like `fillna("")` in the builder.
#[derive(Clone, Debug, Default)]
pub struct Event {
    pub eid: u32,
    /// SystemTime in nanoseconds since the Unix epoch.
    pub t_ns: Option<i64>,
    pub image: String,
    pub parent_image: String,
    pub command_line: String,
    pub integrity_level: String,
    pub destination_ip: String,
    pub destination_port: String,
    pub image_loaded: String,
    pub signed: String,
    pub signature_status: String,
    pub target_filename: String,
    pub target_object: String,
    pub query_name: String,
    pub granted_access: String,
}

impl Event {
    /// Set a field by its Sysmon / CSV column name. Unknown names are ignored.
    pub fn set_field(&mut self, name: &str, value: &str) {
        let slot = match name {
            "Image" => &mut self.image,
            "ParentImage" => &mut self.parent_image,
            "CommandLine" => &mut self.command_line,
            "IntegrityLevel" => &mut self.integrity_level,
            "DestinationIp" => &mut self.destination_ip,
            "DestinationPort" => &mut self.destination_port,
            "ImageLoaded" => &mut self.image_loaded,
            "Signed" => &mut self.signed,
            "SignatureStatus" => &mut self.signature_status,
            "TargetFilename" => &mut self.target_filename,
            "TargetObject" => &mut self.target_object,
            "QueryName" => &mut self.query_name,
            "GrantedAccess" => &mut self.granted_access,
            _ => return,
        };
        *slot = value.to_string();
    }

    /// Sort key: by time, events without a timestamp last (pandas na_position="last").
    pub fn sort_key(&self) -> i64 {
        self.t_ns.unwrap_or(i64::MAX)
    }
}

// ───────────────────────── schema ─────────────────────────

const CATS: [&str; 9] = [
    "none", "office", "shell", "script_host", "browser", "system", "lolbin", "admin_tool", "other",
];

pub fn feature_names() -> &'static [String] {
    static NAMES: OnceLock<Vec<String>> = OnceLock::new();
    NAMES.get_or_init(|| {
        let mut n: Vec<String> = (1..=23).map(|i| format!("cnt_eid_{i}")).collect();
        let fixed: &[&[&str]] = &[
            &["win_len_frac"],
            &["has_creation_row", "cmd_len_log", "cmd_len_gt_200", "has_base64",
              "has_powershell_bypass", "has_http_download", "has_ps_obfuscation",
              "has_persistence_cmd", "has_destructive_cmd", "cmd_has_temp_path"],
            &["is_executing_from_temp", "is_from_user_writable", "is_from_downloads",
              "is_from_appdata", "is_system_binary_wrong_path", "has_double_extension",
              "ext_tmp", "ext_scr_com", "name_entropy", "name_digit_ratio"],
        ];
        for group in fixed {
            n.extend(group.iter().map(|s| s.to_string()));
        }
        n.extend(CATS.iter().map(|c| format!("child_{c}")));
        n.extend(CATS.iter().map(|c| format!("parent_{c}")));
        let rest: &[&str] = &[
            "office_spawns_exec", "browser_spawns_exec", "shell_spawns_shell",
            "system_spawns_exec", "parent_missing", "parent_in_user_writable",
            "integ_system", "integ_high", "integ_medium", "integ_low", "integ_unknown",
            "net_cnt_log", "net_frac_external", "net_unique_dst_log", "net_has_susp_port",
            "net_only_web_ports", "net_frac_high_port",
            "file_cnt_log", "file_frac_temp", "file_exec_drops_log", "reg_cnt_log",
            "reg_runkey_log", "dns_cnt_log", "dns_max_len_log", "dns_has_long_name",
            "dns_unique_log",
            "img_cnt_log", "img_frac_unsigned", "img_frac_invalid_sig", "img_userwritable_log",
            "pa_cnt_log", "pa_high_access_log",
            "dur_log", "med_delta_log", "min_delta_log", "mean_delta_log", "frac_burst_50ms",
        ];
        n.extend(rest.iter().map(|s| s.to_string()));
        assert_eq!(n.len(), FEATURE_DIM);
        n
    })
}

fn feature_index() -> &'static HashMap<&'static str, usize> {
    static IDX: OnceLock<HashMap<&'static str, usize>> = OnceLock::new();
    IDX.get_or_init(|| {
        feature_names().iter().enumerate().map(|(i, s)| (s.as_str(), i)).collect()
    })
}

// ───────────────────────── patterns & lookup sets ─────────────────────────

struct Patterns {
    user: Regex,
    docs: Regex,
    b64: Regex,
    bypass: Regex,
    dl: Regex,
    iex: Regex,
    persist: Regex,
    destruct: Regex,
    temp: Regex,
    userw: Regex,
    doubleext: Regex,
    runkey: Regex,
    drop: Regex,
    downloads: Regex,
    appdata: Regex,
}

fn pat() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| {
        let r = |s: &str| Regex::new(s).expect("bad feature regex");
        Patterns {
            user: r(r"(?i)\\users\\[^\\]+"),
            docs: r(r"(?i)\\documents and settings\\[^\\]+"),
            b64: r(r"(-enc\b|-encodedcommand|frombase64string|[a-z0-9+/]{80,}={0,2})"),
            bypass: r(r"(executionpolicy\s+bypass|-ep\s+bypass|-exec\s+bypass|-nop\b|-noprofile|-w\s+hidden|-windowstyle\s+hidden|-noni\b)"),
            dl: r(r"(https?://|downloadstring|downloadfile|invoke-webrequest|\biwr\b|\bcurl\b|\bwget\b|bitsadmin|urlcache|start-bitstransfer)"),
            iex: r(r"(\biex\b|invoke-expression|\[char\]|-join|\[convert\]|\bfromcharcode)"),
            persist: r(r"(schtasks.*/create|currentversion\\run|reg\s+add.*run|sc\s+create|new-service|startup\\)"),
            destruct: r(r"(delete\s+shadows|shadowcopy.*delete|recoveryenabled\s+no|wbadmin\s+delete|cipher\s+/w|wevtutil\s+cl|clear-eventlog|vssadmin.*resize)"),
            temp: r(r"(\\temp\\|\\tmp\\|\\appdata\\local\\temp)"),
            userw: r(r"(\\users\\|\\programdata\\|\\windows\\temp\\|\\perflogs\\|\\public\\)"),
            doubleext: r(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|zip)\.(exe|scr|com|bat)$"),
            runkey: r(r"(\\currentversion\\run|\\currentversion\\policies\\explorer\\run|image file execution options|\\winlogon\\(shell|userinit)|\\services\\[^\\]+\\imagepath|\\currentversion\\windows\\load)"),
            drop: r(r"\.(exe|dll|bat|ps1|vbs|js|scr|cmd|hta|jar|lnk)$"),
            downloads: r(r"\\downloads\\"),
            appdata: r(r"\\appdata\\"),
        }
    })
}

const OFFICE: &[&str] = &["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
    "onenote.exe", "mspub.exe", "visio.exe"];
const SHELL: &[&str] = &["cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe"];
const SCRIPT: &[&str] = &["wscript.exe", "cscript.exe", "mshta.exe"];
const BROWSER: &[&str] = &["chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe",
    "brave.exe", "vivaldi.exe"];
const SYSTEM: &[&str] = &["svchost.exe", "services.exe", "wininit.exe", "winlogon.exe", "explorer.exe",
    "taskhostw.exe", "smss.exe", "csrss.exe", "lsass.exe", "userinit.exe", "dllhost.exe",
    "sihost.exe", "runtimebroker.exe", "wmiprvse.exe", "conhost.exe"];
const LOLBIN: &[&str] = &["rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "wmic.exe", "msiexec.exe", "cmstp.exe", "mavinject.exe",
    "forfiles.exe", "esentutl.exe"];
const ADMIN: &[&str] = &["net.exe", "net1.exe", "whoami.exe", "schtasks.exe", "sc.exe", "reg.exe", "netsh.exe",
    "vssadmin.exe", "tasklist.exe", "taskkill.exe", "nltest.exe", "ipconfig.exe",
    "systeminfo.exe", "at.exe", "bcdedit.exe", "wbadmin.exe"];
const SYS_BINS: &[&str] = &["svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe", "wininit.exe",
    "smss.exe", "explorer.exe", "taskhostw.exe", "cmd.exe", "powershell.exe", "rundll32.exe",
    "regsvr32.exe", "conhost.exe", "dllhost.exe", "wmiprvse.exe", "spoolsv.exe", "sihost.exe",
    "runtimebroker.exe", "mshta.exe", "wscript.exe", "cscript.exe", "certutil.exe"];
const SUSP_PORTS: &[f64] = &[4444.0, 5555.0, 6666.0, 1337.0, 31337.0, 8888.0, 9001.0, 4443.0, 1234.0,
    12345.0, 6667.0, 2222.0, 3333.0];
const WEB_PORTS: &[f64] = &[80.0, 443.0, 8080.0, 8443.0];
const HIGH_ACCESS: &[&str] = &["0x1fffff", "0x1410", "0x1010", "0x1438", "0x143a", "0x1f3fff", "0x1f0fff"];

fn category(name: &str) -> &'static str {
    if name.is_empty() {
        return "none";
    }
    for (cat, set) in [("office", OFFICE), ("shell", SHELL), ("script_host", SCRIPT),
                       ("browser", BROWSER), ("system", SYSTEM), ("lolbin", LOLBIN),
                       ("admin_tool", ADMIN)] {
        if set.contains(&name) {
            return cat;
        }
    }
    "other"
}

fn system_root() -> &'static str {
    static SR: OnceLock<String> = OnceLock::new();
    SR.get_or_init(|| {
        std::env::var("SystemRoot")
            .unwrap_or_else(|_| r"C:\Windows".to_string())
            .to_lowercase()
            .trim_end_matches('\\')
            .to_string()
    })
}

// ───────────────────────── string helpers (Python semantics) ─────────────────────────

/// `sanitize()` / `san_series()`: strip, lower, "-"/"0"/"nan" -> "", mask profile names.
pub fn sanitize(s: &str) -> String {
    let s = s.trim().to_lowercase();
    if s == "-" || s == "0" || s == "nan" {
        return String::new();
    }
    let p = pat();
    let s = p.user.replace_all(&s, NoExpand(r"\users\<user>"));
    p.docs.replace_all(&s, NoExpand(r"\documents and settings\<user>")).into_owned()
}

/// `base_of()`: last component after `\` or `/`.
fn base_of(p: &str) -> &str {
    p.rsplit(|c| c == '\\' || c == '/').next().unwrap_or("")
}

/// `ntpath.dirname()` for an already-lowercased path.
fn nt_dirname(p: &str) -> &str {
    let is_sep = |c: char| c == '\\' || c == '/';
    let (drive, rest) = if p.len() >= 2 && p.as_bytes()[1] == b':' { p.split_at(2) } else { ("", p) };
    let head = match rest.rfind(is_sep) {
        Some(i) => &rest[..=i],
        None => "",
    };
    let stripped = head.trim_end_matches(is_sep);
    let head = if stripped.is_empty() { head } else { stripped };
    &p[..drive.len() + head.len()]
}

/// `os.path.splitext(name)[0]`: a leading run of dots is not an extension.
fn stem(name: &str) -> &str {
    if let Some(dot) = name.rfind('.') {
        if name[..dot].chars().any(|c| c != '.') {
            return &name[..dot];
        }
    }
    name
}

fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    let mut n = 0usize;
    for ch in s.chars() {
        *counts.entry(ch).or_insert(0) += 1;
        n += 1;
    }
    let n = n as f64;
    -counts.values().map(|&v| { let p = v as f64 / n; p * p.log2() }).sum::<f64>()
}

fn wrong_path_system_binary(path: &str) -> bool {
    let n = base_of(path);
    if path.is_empty() || !SYS_BINS.contains(&n) {
        return false;
    }
    let sr = system_root();
    let protected = [format!("{sr}\\system32\\"), format!("{sr}\\syswow64\\"), format!("{sr}\\winsxs\\")];
    let ok = protected.iter().any(|p| path.starts_with(p.as_str()))
        || (n == "explorer.exe" && nt_dirname(path) == sr);
    !ok
}

/// `ipaddress.ip_address(ip.strip("[]")).is_global` as 1 / 0, or -1 if unparseable.
fn is_external(ip: &str) -> i8 {
    match crate::ip::is_global(ip.trim_matches(|c| c == '[' || c == ']')) {
        Some(true) => 1,
        Some(false) => 0,
        None => -1,
    }
}

/// `pd.to_numeric(port, errors="coerce").fillna(-1)`
fn port_num(s: &str) -> f64 {
    s.trim().parse::<f64>().ok().filter(|v| !v.is_nan()).unwrap_or(-1.0)
}

fn mean(v: &[f64]) -> f64 {
    if v.is_empty() { 0.0 } else { v.iter().sum::<f64>() / v.len() as f64 }
}

fn median(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = s.len();
    if n % 2 == 1 { s[n / 2] } else { (s[n / 2 - 1] + s[n / 2]) / 2.0 }
}

fn b(x: bool) -> f64 {
    if x { 1.0 } else { 0.0 }
}

fn ln1p(x: f64) -> f64 {
    x.ln_1p()
}

// ───────────────────────── assembly ─────────────────────────

struct Out([f64; FEATURE_DIM]);

impl Out {
    fn set(&mut self, name: &str, v: f64) {
        let i = *feature_index().get(name).unwrap_or_else(|| panic!("unknown feature {name}"));
        self.0[i] = v;
    }
}

/// Stable-sort events by time and split them like the builder does:
/// the first `WINDOW` events, plus the earliest EventID-1 row.
pub fn split_events(mut events: Vec<Event>) -> (Vec<Event>, Option<Event>) {
    events.sort_by_key(Event::sort_key);
    let creation = events.iter().find(|e| e.eid == 1).cloned();
    events.truncate(WINDOW);
    (events, creation)
}

/// Compute the 99-feature vector for one process.
/// `window` must already be time-ordered and at most `WINDOW` long.
pub fn compute(window: &[Event], creation: Option<&Event>) -> [f32; FEATURE_DIM] {
    let p = pat();
    let mut f = Out([0.0; FEATURE_DIM]);

    // ── EventID counts ──
    let mut cnt = [0usize; 24];
    for e in window {
        if (1..=23).contains(&e.eid) {
            cnt[e.eid as usize] += 1;
        }
    }
    for i in 1..=23 {
        f.set(&format!("cnt_eid_{i}"), ln1p(cnt[i] as f64));
    }
    f.set("win_len_frac", window.len() as f64 / WINDOW as f64);

    // ── network (EventID 3) ──
    let net: Vec<&Event> = window.iter().filter(|e| e.eid == 3).collect();
    if !net.is_empty() {
        let ext: Vec<i8> = net.iter().map(|e| is_external(&e.destination_ip)).collect();
        let known: Vec<f64> = ext.iter().filter(|&&v| v >= 0).map(|&v| b(v == 1)).collect();
        let ports: Vec<f64> = net.iter().map(|e| port_num(&e.destination_port)).collect();
        let dsts: HashSet<&str> = net.iter().map(|e| e.destination_ip.as_str()).collect();
        f.set("net_cnt_log", ln1p(net.len() as f64));
        f.set("net_frac_external", mean(&known));
        f.set("net_unique_dst_log", ln1p(dsts.len() as f64));
        f.set("net_has_susp_port", b(ports.iter().any(|x| SUSP_PORTS.contains(x))));
        f.set("net_only_web_ports", b(ports.iter().all(|x| WEB_PORTS.contains(x))));
        f.set("net_frac_high_port", mean(&ports.iter().map(|&x| b(x >= 49152.0)).collect::<Vec<_>>()));
    }

    // ── file create (EventID 11) ──
    let files: Vec<String> = window.iter().filter(|e| e.eid == 11)
        .map(|e| sanitize(&e.target_filename)).collect();
    if !files.is_empty() {
        let temp: Vec<f64> = files.iter().map(|s| b(p.temp.is_match(s))).collect();
        let drops = files.iter().filter(|s| p.drop.is_match(s)).count();
        f.set("file_cnt_log", ln1p(files.len() as f64));
        f.set("file_frac_temp", mean(&temp));
        f.set("file_exec_drops_log", ln1p(drops as f64));
    }

    // ── registry (EventID 12/13/14) ──
    let regs: Vec<String> = window.iter().filter(|e| matches!(e.eid, 12 | 13 | 14))
        .map(|e| sanitize(&e.target_object)).collect();
    if !regs.is_empty() {
        let run = regs.iter().filter(|s| p.runkey.is_match(s)).count();
        f.set("reg_cnt_log", ln1p(regs.len() as f64));
        f.set("reg_runkey_log", ln1p(run as f64));
    }

    // ── DNS (EventID 22) ──
    let dns: Vec<String> = window.iter().filter(|e| e.eid == 22)
        .map(|e| e.query_name.to_lowercase().trim().to_string()).collect();
    if !dns.is_empty() {
        let max_len = dns.iter().map(|q| q.chars().count()).max().unwrap_or(0) as f64;
        let uniq: HashSet<&str> = dns.iter().map(|s| s.as_str()).collect();
        f.set("dns_cnt_log", ln1p(dns.len() as f64));
        f.set("dns_max_len_log", ln1p(max_len));
        f.set("dns_has_long_name", b(max_len > 40.0));
        f.set("dns_unique_log", ln1p(uniq.len() as f64));
    }

    // ── image loads (EventID 7) ──
    let loads: Vec<&Event> = window.iter().filter(|e| e.eid == 7).collect();
    if !loads.is_empty() {
        let unsigned: Vec<f64> = loads.iter().map(|e| b(e.signed.to_lowercase() != "true")).collect();
        let invalid: Vec<f64> = loads.iter().map(|e| {
            let ss = e.signature_status.to_lowercase();
            b(ss != "valid" && !ss.is_empty())
        }).collect();
        let uw = loads.iter().filter(|e| p.userw.is_match(&sanitize(&e.image_loaded))).count();
        f.set("img_cnt_log", ln1p(loads.len() as f64));
        f.set("img_frac_unsigned", mean(&unsigned));
        f.set("img_frac_invalid_sig", mean(&invalid));
        f.set("img_userwritable_log", ln1p(uw as f64));
    }

    // ── process access (EventID 10) ──
    let pa: Vec<&Event> = window.iter().filter(|e| e.eid == 10).collect();
    if !pa.is_empty() {
        let high = pa.iter().filter(|e| HIGH_ACCESS.contains(&e.granted_access.to_lowercase().as_str())).count();
        f.set("pa_cnt_log", ln1p(pa.len() as f64));
        f.set("pa_high_access_log", ln1p(high as f64));
    }

    // ── timing ──
    let times: Vec<i64> = window.iter().filter_map(|e| e.t_ns).collect();
    if let (Some(lo), Some(hi)) = (times.iter().min(), times.iter().max()) {
        f.set("dur_log", ln1p(((hi - lo) as f64 / 1e9).max(0.0)));
    }
    let deltas: Vec<f64> = window.windows(2).filter_map(|w| match (w[0].t_ns, w[1].t_ns) {
        (Some(a), Some(b)) => Some((b - a) as f64 / 1e6),
        _ => None,
    }).collect();
    if !deltas.is_empty() {
        f.set("med_delta_log", ln1p(median(&deltas).max(0.0)));
        f.set("min_delta_log", ln1p(deltas.iter().cloned().fold(f64::INFINITY, f64::min).max(0.0)));
        f.set("mean_delta_log", ln1p(mean(&deltas).max(0.0)));
        f.set("frac_burst_50ms", mean(&deltas.iter().map(|&d| b(d < 50.0)).collect::<Vec<_>>()));
    }

    // ── process-creation row ──
    let empty = Event::default();
    let c = creation.unwrap_or(&empty);
    let cmd = sanitize(&c.command_line);
    let img = sanitize(&c.image);
    let par = sanitize(&c.parent_image);
    let integ = c.integrity_level.to_lowercase();
    let cmd_len = cmd.chars().count() as f64;

    f.set("has_creation_row", b(creation.is_some()));
    f.set("cmd_len_log", ln1p(cmd_len) / 8.0);
    f.set("cmd_len_gt_200", b(cmd_len > 200.0));
    f.set("has_base64", b(p.b64.is_match(&cmd)));
    f.set("has_powershell_bypass", b(p.bypass.is_match(&cmd)));
    f.set("has_http_download", b(p.dl.is_match(&cmd)));
    f.set("has_ps_obfuscation", b(p.iex.is_match(&cmd)));
    f.set("has_persistence_cmd", b(p.persist.is_match(&cmd)));
    f.set("has_destructive_cmd", b(p.destruct.is_match(&cmd)));
    f.set("cmd_has_temp_path", b(p.temp.is_match(&cmd)));
    f.set("is_executing_from_temp", b(p.temp.is_match(&img)));
    f.set("is_from_user_writable", b(p.userw.is_match(&img)));
    f.set("is_from_downloads", b(p.downloads.is_match(&img)));
    f.set("is_from_appdata", b(p.appdata.is_match(&img)));
    f.set("is_system_binary_wrong_path", b(wrong_path_system_binary(&img)));
    f.set("has_double_extension", b(p.doubleext.is_match(&img)));
    f.set("ext_tmp", b(img.ends_with(".tmp")));
    f.set("ext_scr_com", b(img.ends_with(".scr") || img.ends_with(".com")));
    let st = stem(base_of(&img));
    let st_len = st.chars().count();
    f.set("name_entropy", entropy(st) / 4.5);
    f.set("name_digit_ratio", st.chars().filter(|ch| ch.is_ascii_digit()).count() as f64 / st_len.max(1) as f64);

    let cc = if img.is_empty() { "none" } else { category(base_of(&img)) };
    let pc = if par.is_empty() { "none" } else { category(base_of(&par)) };
    for cat in CATS {
        f.set(&format!("child_{cat}"), b(cc == cat));
        f.set(&format!("parent_{cat}"), b(pc == cat));
    }
    let exec_kid = matches!(cc, "shell" | "script_host" | "lolbin" | "admin_tool");
    f.set("office_spawns_exec", b(pc == "office" && exec_kid));
    f.set("browser_spawns_exec", b(pc == "browser" && exec_kid));
    f.set("shell_spawns_shell", b(pc == "shell" && cc == "shell"));
    f.set("system_spawns_exec", b(pc == "system" && exec_kid));
    f.set("parent_missing", b(par.is_empty()));
    f.set("parent_in_user_writable", b(p.userw.is_match(&par)));
    f.set("integ_system", b(integ == "system"));
    f.set("integ_high", b(integ == "high"));
    f.set("integ_medium", b(integ == "medium"));
    f.set("integ_low", b(integ == "low"));
    f.set("integ_unknown", b(!matches!(integ.as_str(), "system" | "high" | "medium" | "low")));

    let mut out = [0f32; FEATURE_DIM];
    for (o, v) in out.iter_mut().zip(f.0.iter()) {
        *o = *v as f32;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(eid: u32, t_ms: i64) -> Event {
        Event { eid, t_ns: Some(t_ms * 1_000_000), ..Default::default() }
    }

    #[test]
    fn schema_has_99_unique_names() {
        let names = feature_names();
        assert_eq!(names.len(), FEATURE_DIM);
        assert_eq!(names.iter().collect::<HashSet<_>>().len(), FEATURE_DIM);
        assert_eq!(names[0], "cnt_eid_1");
        assert_eq!(names[98], "frac_burst_50ms");
    }

    #[test]
    fn sanitize_masks_usernames() {
        let a = sanitize(r"C:\Users\Alice.Smith\AppData\Local\Temp\x.exe");
        let b = sanitize(r"C:\USERS\chrsm\AppData\Local\Temp\x.exe");
        assert_eq!(a, r"c:\users\<user>\appdata\local\temp\x.exe");
        assert_eq!(a, b);
        assert_eq!(sanitize(" - "), "");
    }

    #[test]
    fn path_helpers_match_python() {
        assert_eq!(stem("evil.pdf.exe"), "evil.pdf");
        assert_eq!(stem(".hidden"), ".hidden");
        assert_eq!(stem("noext"), "noext");
        assert_eq!(nt_dirname(r"c:\windows\explorer.exe"), r"c:\windows");
        assert_eq!(nt_dirname(r"c:\explorer.exe"), r"c:\");
        assert!(wrong_path_system_binary(r"c:\users\<user>\svchost.exe"));
        assert!(!wrong_path_system_binary(&format!(r"{}\system32\svchost.exe", system_root())));
        assert!(!wrong_path_system_binary(r"c:\tools\notepad.exe"));
    }

    #[test]
    fn creation_row_features() {
        let mut c = ev(1, 0);
        c.image = r"C:\Users\Bob\Downloads\invoice.pdf.exe".into();
        c.parent_image = r"C:\Program Files\Microsoft Office\WINWORD.EXE".into();
        c.command_line = "powershell -nop -w hidden -enc AAAA".into();
        c.integrity_level = "Medium".into();
        let (w, cr) = split_events(vec![ev(11, 30), c, ev(3, 10)]);
        let v = compute(&w, cr.as_ref());
        let get = |n: &str| v[*feature_index().get(n).unwrap()];
        assert_eq!(get("has_creation_row"), 1.0);
        assert_eq!(get("has_double_extension"), 1.0);
        assert_eq!(get("is_from_downloads"), 1.0);
        assert_eq!(get("parent_office"), 1.0);
        assert_eq!(get("child_other"), 1.0);
        assert_eq!(get("has_powershell_bypass"), 1.0);
        assert_eq!(get("has_base64"), 1.0);
        assert_eq!(get("integ_medium"), 1.0);
        assert!((get("win_len_frac") - 3.0 / 50.0).abs() < 1e-6);
        // deltas 10ms and 20ms -> all bursts
        assert_eq!(get("frac_burst_50ms"), 1.0);
    }

    #[test]
    fn missing_creation_row_defaults() {
        let v = compute(&[ev(3, 0), ev(3, 5)], None);
        let get = |n: &str| v[*feature_index().get(n).unwrap()];
        assert_eq!(get("has_creation_row"), 0.0);
        assert_eq!(get("child_none"), 1.0);
        assert_eq!(get("parent_none"), 1.0);
        assert_eq!(get("parent_missing"), 1.0);
        assert_eq!(get("integ_unknown"), 1.0);
    }
}
