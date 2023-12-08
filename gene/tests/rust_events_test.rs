use std::{borrow::Cow, collections::HashMap, fs::File, io::Read, time::Duration};

use event_derive::{Event, FieldGetter};
use gene::{Engine, Event, FieldGetter, FieldValue, Rule};
use libflate::gzip;
use serde::{Deserialize, Deserializer};

#[derive(Debug, FieldGetter, Deserialize)]
#[getter(use_serde_rename)]
struct System {
    #[serde(rename = "Channel")]
    channel: String,
    #[serde(rename = "EventID", deserialize_with = "deserialize_string_to_int")]
    event_id: i64,
}

fn deserialize_string_to_int<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    s.parse().map_err(serde::de::Error::custom)
}

#[derive(FieldGetter, Debug, Deserialize)]
#[getter(use_serde_rename)]
struct Inner {
    #[serde(rename = "EventData")]
    event_data: HashMap<String, String>,
    #[serde(rename = "System")]
    system: System,
}

#[derive(Event, FieldGetter, Debug, Deserialize)]
#[getter(use_serde_rename)]
#[event(id = self.event.system.event_id, source = Cow::from(&self.event.system.channel))]
struct WinEvent {
    #[serde(rename = "Event")]
    event: Inner,
}

fn time_it<F: FnMut()>(mut f: F) -> Duration {
    let start_time = std::time::Instant::now();
    f();
    let end_time = std::time::Instant::now();
    end_time - start_time
}

#[test]
#[ignore = "long test that must be ran in release mode"]
fn test_fast() {
    let rules = Rule::deserialize_reader(File::open("./tests/data/compiled.gen").unwrap());
    let it = rules.into_iter().map(|r| r.unwrap()).collect::<Vec<Rule>>();

    // decoding gzip file
    let mut dec = gzip::Decoder::new(File::open("./tests/data/events.json.gz").unwrap()).unwrap();
    let mut all = vec![];
    dec.read_to_end(&mut all).unwrap();

    let events = serde_json::Deserializer::from_slice(all.as_slice())
        .into_iter::<WinEvent>()
        .map(|e| e.unwrap())
        .collect::<Vec<WinEvent>>();

    let run_count = 5;

    let mut engine = Engine::new();
    for i in 0..8 {
        for r in it.iter() {
            let mut r = r.clone();
            r.name = format!("{}.{}", r.name, i);
            engine.insert_rule(r).unwrap();
        }

        let mut positives = 0;
        let scan_dur = time_it(|| {
            for _ in 0..run_count {
                for e in events.iter() {
                    if let Some(sr) = engine.scan(e).ok().and_then(|v| v) {
                        if sr.is_detection() {
                            positives += 1
                        }
                    }
                }
            }
        });

        let events_count = events.len() * run_count;
        let mb = (all.len() * run_count) as f64 / 1_000_000_f64;
        let mbs = mb / (scan_dur.as_secs_f64());
        let eps = (events_count as f64) / scan_dur.as_secs_f64();

        println!("Number of scanned events: {events_count} -> {mb:.2} MB");
        println!("Number of loaded rules: {}", engine.rules_count());
        println!("Scan duration: {scan_dur:?} -> {mbs:.2} MB/s -> {eps:.2} events/s",);
        println!("Number of detections: {positives}");
        assert!(positives > 0);
        println!();
    }
}
