use std::{
    borrow::Cow,
    collections::HashMap,
    io::{self, Read},
};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use gene::{Compiler, Engine, Event, FieldGetter, FieldValue, Rule};
use gene_derive::{Event, FieldGetter};
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

const RULES: &[u8] = include_bytes!("./data/compiled.gen");
const EVENTS: &[u8] = include_bytes!("./data/events.json.gz");

fn bench_rust_events(c: &mut Criterion) {
    let rules = Rule::deserialize_reader(io::Cursor::new(RULES));

    let it = rules.into_iter().map(|r| r.unwrap()).collect::<Vec<Rule>>();

    // decoding gzip file
    let mut dec = gzip::Decoder::new(io::Cursor::new(EVENTS)).unwrap();
    let mut all = vec![];
    dec.read_to_end(&mut all).unwrap();

    let events = serde_json::Deserializer::from_slice(all.as_slice())
        .into_iter::<WinEvent>()
        .map(|e| e.unwrap())
        .collect::<Vec<WinEvent>>();

    let mut compiler = Compiler::new();

    let mut group = c.benchmark_group("scan-throughput");
    group.sample_size(20);
    group.throughput(Throughput::Bytes(all.len() as u64));

    for i in 0..1 {
        for r in it.iter() {
            let mut r = r.clone();
            r.name = format!("{}.{}", r.name, i);
            compiler.load(r).unwrap();
        }

        let mut engine = Engine::try_from(compiler.clone()).unwrap();

        group.bench_function(format!("scan-with-{}-rules", engine.rules_count()), |b| {
            b.iter(|| {
                for e in events.iter() {
                    let _ = engine.scan(e);
                }
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_rust_events);
criterion_main!(benches);
