use std::{
    borrow::Cow,
    collections::HashMap,
    io::{self, Read},
};

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use gene::{Compiler, Engine, Event, FieldGetter, FieldValue, Rule, FieldNameIterator};
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

// Builds a ladder of dependency diamonds: l{k} depends on a{k} and b{k},
// which both depend on l{k-1}. Engine construction resolves the dependencies
// of every rule, so this measures the cost of dependency resolution.
fn diamond_ladder(depth: usize) -> String {
    let mut s =
        String::from("name: l0\ntype: dependency\nmatches:\n  $a: .a == 'x'\ncondition: $a\n");
    for k in 1..=depth {
        for side in ["a", "b"] {
            s.push_str(&format!(
                "---\nname: {side}{k}\ntype: dependency\nmatches:\n  $r: rule(l{})\ncondition: $r\n",
                k - 1
            ));
        }
        s.push_str(&format!(
            "---\nname: l{k}\ntype: dependency\nmatches:\n  $x: rule(a{k})\n  $y: rule(b{k})\ncondition: $x and $y\n"
        ));
    }
    s
}

fn bench_engine_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("engine-build");
    group.sample_size(10);

    for depth in [8, 12, 16] {
        let mut compiler = Compiler::new();
        compiler.load_rules_from_str(diamond_ladder(depth)).unwrap();
        compiler.compile().unwrap();

        group.bench_function(format!("diamond-deps-depth-{depth}"), |b| {
            // Engine::try_from consumes the compiler, so a fresh clone is made
            // in the untimed setup to measure engine construction only
            b.iter_batched(
                || compiler.clone(),
                |compiler| Engine::try_from(compiler).unwrap(),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion_group!(benches, bench_rust_events, bench_engine_build);
criterion_main!(benches);
