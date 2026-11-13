//! Parsing Sysmon events (rendered XML, or CSV-style field maps) into `Event`s.

use crate::features::Event;
use std::collections::HashMap;

/// Parse "YYYY-MM-DD[ T]HH:MM:SS[.fffffffff][Z]" into ns since the Unix epoch.
/// Covers both Sysmon's `TimeCreated/@SystemTime` and the dataset's `SystemTime`.
pub fn parse_time_ns(s: &str) -> Option<i64> {
    let s = s.trim().trim_end_matches('Z');
    let (date, time) = s.split_once(|c| c == 'T' || c == ' ')?;
    let mut d = date.splitn(3, '-').map(|x| x.parse::<i64>());
    let (y, m, day) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    let (hms, frac) = match time.split_once('.') {
        Some((a, b)) => (a, b),
        None => (time, ""),
    };
    let mut t = hms.splitn(3, ':').map(|x| x.parse::<i64>());
    let (hh, mm, ss) = (t.next()?.ok()?, t.next()?.ok()?, t.next()?.ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let frac_digits: String = frac.chars().take_while(|c| c.is_ascii_digit()).take(9).collect();
    let frac_ns = if frac_digits.is_empty() {
        0
    } else {
        frac_digits.parse::<i64>().ok()? * 10i64.pow(9 - frac_digits.len() as u32)
    };
    // days_from_civil (Howard Hinnant)
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(((days * 86400 + hh * 3600 + mm * 60 + ss) * 1_000_000_000) + frac_ns)
}

/// `pd.to_numeric(EventID)` restricted to 1..=23, the range the models were trained on.
pub fn parse_eid(s: &str) -> Option<u32> {
    let v = s.trim().parse::<f64>().ok()?;
    if v.fract() == 0.0 && (1.0..=23.0).contains(&v) { Some(v as u32) } else { None }
}

/// A parsed event plus the identity of the process it belongs to.
pub struct Owned {
    pub guid: String,
    pub pid: u32,
    pub event: Event,
}

/// Normalise a ProcessGuid; "", "0" and missing mean "no owner" (dropped in training too).
fn owner_guid(g: Option<&str>) -> Option<String> {
    let g = g?.trim();
    if g.is_empty() || g == "0" { None } else { Some(g.to_ascii_lowercase()) }
}

/// Build an event from a field map keyed by Sysmon / CSV column names.
pub fn from_fields(fields: &HashMap<String, String>) -> Option<(Option<String>, Option<u32>, Event)> {
    let eid = parse_eid(fields.get("EventID")?)?;
    let mut ev = Event { eid, t_ns: fields.get("SystemTime").and_then(|s| parse_time_ns(s)), ..Default::default() };
    for (k, v) in fields {
        ev.set_field(k, v);
    }
    let guid = owner_guid(fields.get("ProcessGuid").map(|s| s.as_str()));
    let pid = fields.get("ProcessId").and_then(|s| s.trim().parse::<f64>().ok()).map(|v| v as u32);
    Some((guid, pid, ev))
}

/// Parse one event rendered with `EvtRenderEventXml`.
/// Returns `Ok(None)` for events the schema ignores (other EventIDs, no ProcessGuid).
pub fn from_xml(xml: &str) -> Result<Option<Owned>, String> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| e.to_string())?;
    let mut fields: HashMap<String, String> = HashMap::new();
    for node in doc.descendants().filter(|n| n.is_element()) {
        match node.tag_name().name() {
            "EventID" => {
                fields.insert("EventID".into(), node.text().unwrap_or("").to_string());
            }
            "TimeCreated" => {
                if let Some(t) = node.attribute("SystemTime") {
                    fields.insert("SystemTime".into(), t.to_string());
                }
            }
            "Data" => {
                if let Some(name) = node.attribute("Name") {
                    fields.insert(name.to_string(), node.text().unwrap_or("").to_string());
                }
            }
            _ => {}
        }
    }
    let Some((guid, pid, event)) = from_fields(&fields) else { return Ok(None) };
    match (guid, pid) {
        (Some(guid), Some(pid)) => Ok(Some(Owned { guid, pid, event })),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_formats() {
        let a = parse_time_ns("2021-09-07 10:40:12.482262").unwrap();
        let b = parse_time_ns("2021-09-07T10:40:12.4822620Z").unwrap();
        assert_eq!(a, b);
        assert_eq!(parse_time_ns("1970-01-01 00:00:01"), Some(1_000_000_000));
        assert_eq!(parse_time_ns("2000-03-01T00:00:00Z"), Some(951_868_800_000_000_000));
        assert_eq!(parse_time_ns("garbage"), None);
    }

    #[test]
    fn eid_range() {
        assert_eq!(parse_eid("3.0"), Some(3));
        assert_eq!(parse_eid("23"), Some(23));
        assert_eq!(parse_eid("255"), None);
        assert_eq!(parse_eid("x"), None);
    }

    #[test]
    fn sysmon_xml() {
        let xml = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID>
          <TimeCreated SystemTime='2026-10-18T10:00:00.1234567Z'/></System>
          <EventData><Data Name='ProcessGuid'>{ABC-1}</Data><Data Name='ProcessId'>4242</Data>
          <Data Name='Image'>C:\Temp\x.exe</Data><Data Name='CommandLine'>x.exe -a</Data></EventData></Event>"#;
        let o = from_xml(xml).unwrap().unwrap();
        assert_eq!(o.pid, 4242);
        assert_eq!(o.guid, "{abc-1}");
        assert_eq!(o.event.eid, 1);
        assert_eq!(o.event.image, r"C:\Temp\x.exe");
        assert!(o.event.t_ns.is_some());
    }

    #[test]
    fn xml_without_process_guid_is_ignored() {
        let xml = r#"<Event><System><EventID>10</EventID></System>
          <EventData><Data Name='SourceProcessGUID'>{A}</Data></EventData></Event>"#;
        assert!(from_xml(xml).unwrap().is_none());
    }
}
