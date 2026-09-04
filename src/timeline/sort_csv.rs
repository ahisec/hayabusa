use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process;

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone};
use csv::{QuoteStyle, ReaderBuilder, WriterBuilder};
use hashbrown::HashSet;

use crate::detections::configs::SortCsvOption;
use crate::detections::message::AlertMessage;

const TIMESTAMP_COLUMN: &str = "Timestamp";
const EVTX_FILE_COLUMN: &str = "EvtxFile";

/// Timestamp formats Hayabusa can write for the `Timestamp` column (see `format_time` in
/// `utils.rs`). `%.f` matches whatever fractional-second precision was used (`.3f`/`.6f`/none),
/// so the default and the `--rfc-3339` outputs share a pattern. Offset-bearing formats are parsed
/// as `DateTime`; the offset-less ones fall through to the naive parsers below.
const OFFSET_FORMATS: &[&str] = &[
    "%Y-%m-%d %H:%M:%S%.f %:z",    // default
    "%Y-%m-%d %H:%M:%S%.f%:z",     // --rfc-3339
    "%m-%d-%Y %H:%M:%S%.f %:z",    // --us-military-time
    "%d-%m-%Y %H:%M:%S%.f %:z",    // --european-time
    "%m-%d-%Y %I:%M:%S%.f %p %:z", // --us-time
    "%a, %e %b %Y %H:%M:%S %:z",   // --rfc-2822
];

const NAIVE_FORMATS: &[&str] = &[
    "%Y-%m-%dT%H:%M:%S%.fZ", // --iso-8601 (the trailing Z is literal in Hayabusa's output)
    "%Y-%m-%d %H:%M:%S%.f",
];

const DATE_ONLY_FORMATS: &[&str] = &["%Y-%m-%d", "%m-%d-%Y", "%d-%m-%Y", "%a, %e %b %Y"];

/// Turn a UTC-anchored timestamp into a comparable nanosecond key. Unlike `timestamp_nanos_opt`,
/// which is `None` for dates outside roughly 1677-2262, this covers the full range chrono can
/// represent, so an old event timestamp does not flip the whole file to a lexical fallback.
fn sort_key<Tz: TimeZone>(dt: DateTime<Tz>) -> i128 {
    dt.timestamp() as i128 * 1_000_000_000 + i128::from(dt.timestamp_subsec_nanos())
}

/// Parse a Hayabusa timestamp cell into a comparable nanosecond value. Offset-aware timestamps are
/// normalized to UTC; offset-less and date-only ones are taken at face value. Returns `None` when
/// none of the known formats match, which flips the whole sort to a lexical fallback.
fn parse_timestamp(value: &str) -> Option<i128> {
    let value = value.trim();
    for fmt in OFFSET_FORMATS {
        if let Ok(parsed) = DateTime::parse_from_str(value, fmt) {
            return Some(sort_key(parsed));
        }
    }
    for fmt in NAIVE_FORMATS {
        if let Ok(parsed) = NaiveDateTime::parse_from_str(value, fmt) {
            return Some(sort_key(parsed.and_utc()));
        }
    }
    for fmt in DATE_ONLY_FORMATS {
        if let Ok(date) = NaiveDate::parse_from_str(value, fmt) {
            return Some(sort_key(date.and_hms_opt(0, 0, 0)?.and_utc()));
        }
    }
    None
}

/// Gather the CSV files to process: the single `-f` file, or every `*.csv` in the `-d` directory
/// (sorted by path so a directory scan is deterministic).
fn collect_input_files(opt: &SortCsvOption) -> Vec<PathBuf> {
    if let Some(file) = &opt.filepath {
        return vec![file.clone()];
    }
    let Some(dir) = &opt.directory else {
        return vec![];
    };
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            AlertMessage::alert(&format!(
                "Failed to read directory {}. {err}",
                dir.display()
            ))
            .ok();
            process::exit(1);
        }
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("csv"))
        })
        .collect();
    files.sort();
    files
}

/// Read one CSV, returning its header row and its data rows. The header is checked against the
/// first file's header by the caller so that rows from different files line up column-for-column.
fn read_csv(path: &Path) -> Option<(Vec<String>, Vec<Vec<String>>)> {
    let mut reader = match ReaderBuilder::new().flexible(true).from_path(path) {
        Ok(reader) => reader,
        Err(err) => {
            AlertMessage::alert(&format!("Failed to open {}. {err}", path.display())).ok();
            return None;
        }
    };
    let header = match reader.headers() {
        Ok(header) => header.iter().map(str::to_string).collect::<Vec<_>>(),
        Err(err) => {
            AlertMessage::alert(&format!(
                "Failed to read header of {}. {err}",
                path.display()
            ))
            .ok();
            return None;
        }
    };
    let mut rows = vec![];
    for record in reader.records() {
        match record {
            Ok(record) => rows.push(record.iter().map(str::to_string).collect::<Vec<_>>()),
            Err(err) => {
                AlertMessage::alert(&format!(
                    "Failed to read a row in {}. {err}",
                    path.display()
                ))
                .ok();
                return None;
            }
        }
    }
    Some((header, rows))
}

/// The dedup key for a row: every cell except the `EvtxFile` column, so the same detection
/// collected from overlapping/backup `.evtx` files collapses to one entry (same logic as
/// `-X, --remove-duplicate-detections`).
fn dedup_key(row: &[String], evtx_idx: Option<usize>) -> Vec<String> {
    match evtx_idx {
        Some(idx) => row
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != idx)
            .map(|(_, cell)| cell.clone())
            .collect(),
        None => row.to_vec(),
    }
}

pub fn sort_csv(opt: &SortCsvOption) {
    let files = collect_input_files(opt);
    if files.is_empty() {
        AlertMessage::alert("No CSV files were found to sort.").ok();
        process::exit(1);
    }

    let mut header: Option<Vec<String>> = None;
    let mut rows: Vec<Vec<String>> = vec![];
    for file in &files {
        let Some((file_header, file_rows)) = read_csv(file) else {
            process::exit(1);
        };
        match &header {
            None => header = Some(file_header),
            Some(expected) if expected != &file_header => {
                AlertMessage::warn(&format!(
                    "Skipping {}: its header does not match the other files.",
                    file.display()
                ))
                .ok();
                continue;
            }
            Some(_) => {}
        }
        rows.extend(file_rows);
    }

    let header = header.unwrap();
    let Some(timestamp_idx) = header.iter().position(|col| col == TIMESTAMP_COLUMN) else {
        AlertMessage::alert(&format!(
            "The input CSV has no {TIMESTAMP_COLUMN} column, so it cannot be sorted by time."
        ))
        .ok();
        process::exit(1);
    };
    let evtx_idx = header.iter().position(|col| col == EVTX_FILE_COLUMN);

    // Sort by timestamp, then by the full row so the ordering is a stable total order (identical
    // timestamps come out the same on every run). If any row's timestamp is in a format we don't
    // recognize, fall back to a lexical sort on the raw timestamp string.
    let parsed: Vec<Option<i128>> = rows
        .iter()
        .map(|row| row.get(timestamp_idx).and_then(|ts| parse_timestamp(ts)))
        .collect();
    let all_parsed = parsed.iter().all(Option::is_some);

    let mut order: Vec<usize> = (0..rows.len()).collect();
    order.sort_by(|&a, &b| {
        let primary = if all_parsed {
            parsed[a].cmp(&parsed[b])
        } else {
            rows[a].get(timestamp_idx).cmp(&rows[b].get(timestamp_idx))
        };
        primary.then_with(|| rows[a].cmp(&rows[b]))
    });

    let mut seen: HashSet<Vec<String>> = HashSet::new();
    let mut output_rows: Vec<&Vec<String>> = vec![];
    for &idx in &order {
        if seen.insert(dedup_key(&rows[idx], evtx_idx)) {
            output_rows.push(&rows[idx]);
        }
    }

    if let Err(err) = write_output(opt, &header, &output_rows) {
        AlertMessage::alert(&format!("Failed to write output. {err}")).ok();
        process::exit(1);
    }
}

fn write_output(opt: &SortCsvOption, header: &[String], rows: &[&Vec<String>]) -> io::Result<()> {
    let sink: Box<dyn Write> = if let Some(path) = &opt.output {
        if path.exists() && !opt.clobber {
            AlertMessage::alert(&format!(
                "{} already exists. Use -C, --clobber to overwrite it.",
                path.display()
            ))
            .ok();
            process::exit(1);
        }
        Box::new(BufWriter::new(fs::File::create(path)?))
    } else {
        Box::new(BufWriter::new(io::stdout()))
    };

    let mut writer = WriterBuilder::new()
        .quote_style(QuoteStyle::NonNumeric)
        .from_writer(sink);
    writer.write_record(header)?;
    for row in rows {
        writer.write_record(row.iter())?;
    }
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(name: &str, contents: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("hayabusa_sortcsv_test_{name}"));
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn sorts_by_timestamp_and_drops_evtxfile_duplicates() {
        // Two records share every field except EvtxFile (collected from a backup evtx), so one is
        // a duplicate. The input is also out of time order to exercise the sort.
        let input = "\"Timestamp\",\"RuleTitle\",\"Computer\",\"EvtxFile\"\n\
\"2021-12-13 09:05:00.000 +09:00\",\"Later\",\"host1\",\"a.evtx\"\n\
\"2021-12-13 09:00:00.000 +09:00\",\"Earlier\",\"host1\",\"a.evtx\"\n\
\"2021-12-13 09:00:00.000 +09:00\",\"Earlier\",\"host1\",\"backup.evtx\"\n";
        let in_path = write_temp("in.csv", input);
        let out_path = std::env::temp_dir().join("hayabusa_sortcsv_test_out.csv");
        let _ = fs::remove_file(&out_path);

        let opt = SortCsvOption {
            filepath: Some(in_path.clone()),
            directory: None,
            output: Some(out_path.clone()),
            clobber: true,
            common_options: Default::default(),
        };
        sort_csv(&opt);

        let result = fs::read_to_string(&out_path).unwrap();
        let lines: Vec<&str> = result.lines().collect();

        // Header preserved.
        assert_eq!(
            lines[0],
            "\"Timestamp\",\"RuleTitle\",\"Computer\",\"EvtxFile\""
        );
        // The duplicate (same fields, different EvtxFile) is gone: header + 2 rows.
        assert_eq!(lines.len(), 3);
        // Earlier timestamp sorts first.
        assert!(lines[1].contains("Earlier"));
        assert!(lines[2].contains("Later"));

        let _ = fs::remove_file(&in_path);
        let _ = fs::remove_file(&out_path);
    }

    #[test]
    fn parses_all_supported_timestamp_formats() {
        assert!(parse_timestamp("2021-12-13 09:00:00.000 +09:00").is_some());
        assert!(parse_timestamp("2021-12-13T09:00:00.000000Z").is_some());
        assert!(parse_timestamp("12-13-2021 09:00:00.000 +09:00").is_some());
        assert!(parse_timestamp("2021-12-13").is_some());
        assert!(parse_timestamp("not a timestamp").is_none());
    }

    #[test]
    fn earlier_timestamp_orders_first() {
        let earlier = parse_timestamp("2021-12-13 09:00:00.000 +09:00").unwrap();
        let later = parse_timestamp("2021-12-13 09:05:00.000 +09:00").unwrap();
        assert!(earlier < later);
    }

    #[test]
    fn timestamps_before_the_nanosecond_epoch_still_sort() {
        // Dates before ~1677 overflow chrono's `timestamp_nanos_opt`; the sort key must still
        // cover them so a single old row does not flip the whole file to a lexical fallback.
        let ancient = parse_timestamp("1601-01-01").unwrap();
        let modern = parse_timestamp("2021-12-13").unwrap();
        assert!(ancient < modern);
    }
}
