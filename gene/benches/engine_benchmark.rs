use std::{
    borrow::Cow,
    collections::HashMap,
    hint::black_box,
    io::{self, Read},
};

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use gene::{Compiler, Engine, Event, FieldGetter, FieldNameIterator, FieldValue, Rule};
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
                    let _ = black_box(engine.scan(e));
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

#[derive(Event, FieldGetter)]
#[event(id = 1, source = Cow::from("bench"))]
struct DepEvent {
    a: String,
    cmd: String,
}

// Detection rules guarded by a cheap `.cmd` check and sharing the top of a
// diamond ladder, so `cmd` decides whether the dependencies are reached.
fn bench_scan_deps(c: &mut Criterion) {
    let depth = 16;
    let mut rules = diamond_ladder(depth);
    for i in 0..10 {
        rules.push_str(&format!(
            "---\nname: top{i}\nmatches:\n  $c: .cmd == 'chmod'\n  $d: rule(l{depth})\ncondition: $c and $d\n"
        ));
    }

    let mut compiler = Compiler::new();
    compiler.load_rules_from_str(rules).unwrap();
    let mut engine = Engine::try_from(compiler).unwrap();

    let mut group = c.benchmark_group("scan-deps");
    for cmd in ["ls", "chmod"] {
        let event = DepEvent {
            a: "x".into(),
            cmd: cmd.into(),
        };
        group.bench_function(format!("diamond-depth-{depth}-cmd-{cmd}"), |b| {
            b.iter(|| engine.scan(&event).unwrap().includes_detection("top0"))
        });
    }
    group.finish();
}

// Process events shaped like Kunai's, with struct fields rather than maps.
#[derive(Debug, FieldGetter)]
struct ProcData {
    exe: String,
    command_line: String,
    ancestors: String,
}

#[derive(Debug, Event, FieldGetter)]
#[event(id = self.id, source = "kunai".into())]
struct ProcEvent {
    id: i64,
    data: ProcData,
}

// Detection rules sharing dependencies and using group operators, the
// patterns seen in Kunai rule sets.
const DEPENDENCY_RULES: &str = r#"
name: dep.tmp.exe
type: dependency
matches:
    $exe: .data.exe ~= '^/(tmp|dev/shm|run)/'
    $anc: .data.ancestors ~= '\|/(tmp|dev/shm|run)/'
condition: any of them
---
name: dep.web.parent
type: dependency
matches:
    $anc: .data.ancestors ~= '\|/usr/sbin/(apache2|nginx)\|'
condition: $anc
---
name: tmp.exe
match-on:
    events:
        kunai: [1]
matches:
    $d: rule(dep.tmp.exe)
condition: $d
---
name: tmp.exe.download
match-on:
    events:
        kunai: [1]
matches:
    $dl: .data.command_line ~= '(curl|wget) '
    $d: rule(dep.tmp.exe)
condition: $dl and $d
---
name: webshell
match-on:
    events:
        kunai: [1]
matches:
    $sh: .data.exe ~= '/(ba|da|z)?sh$'
    $d: rule(dep.web.parent)
condition: all of them
---
name: shell.from.web.tmp
match-on:
    events:
        kunai: [1]
matches:
    $d1: rule(dep.web.parent)
    $d2: rule(dep.tmp.exe)
condition: any of $d
---
name: susp.cli
match-on:
    events:
        kunai: [1]
matches:
    $c1: .data.command_line ~= 'base64 -d'
    $c2: .data.command_line ~= 'chmod \+x /tmp/'
    $c3: .data.command_line ~= 'nc -e'
condition: 1 of $c
"#;

fn proc_events(n: usize) -> Vec<ProcEvent> {
    let samples = [
        ("/usr/bin/ls", "ls -la /home", "|/sbin/init|/usr/bin/bash|"),
        (
            "/usr/bin/curl",
            "curl -s https://example.org",
            "|/sbin/init|/usr/bin/bash|",
        ),
        (
            "/tmp/payload",
            "/tmp/payload --run",
            "|/sbin/init|/usr/bin/bash|",
        ),
        (
            "/usr/bin/bash",
            "bash -c id",
            "|/sbin/init|/usr/sbin/nginx|",
        ),
        (
            "/usr/bin/python3",
            "python3 -m http.server",
            "|/sbin/init|/usr/sbin/sshd|",
        ),
        ("/usr/bin/sh", "sh -c base64 -d", "|/sbin/init|/tmp/loader|"),
    ];
    (0..n)
        .map(|i| {
            let (exe, cmd, anc) = samples[i % samples.len()];
            ProcEvent {
                id: 1,
                data: ProcData {
                    exe: exe.into(),
                    command_line: cmd.into(),
                    ancestors: anc.into(),
                },
            }
        })
        .collect()
}

fn bench_dependency_rules(c: &mut Criterion) {
    let mut compiler = Compiler::new();
    compiler.load_rules_from_str(DEPENDENCY_RULES).unwrap();
    let mut engine = Engine::try_from(compiler).unwrap();
    let events = proc_events(10_000);

    // guard against a rule set that silently stops matching
    let detections = events
        .iter()
        .filter(|e| matches!(engine.scan(*e), Ok(sr) if sr.detection.get_include().is_some()))
        .count();
    assert!(detections > 0);

    let mut group = c.benchmark_group("scan-dependencies");
    group.throughput(Throughput::Elements(events.len() as u64));
    group.bench_function("scan-kunai-like-events", |b| {
        b.iter(|| {
            for e in events.iter() {
                black_box(engine.scan(e).unwrap());
            }
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_rust_events,
    bench_engine_build,
    bench_scan_deps,
    bench_dependency_rules
);
criterion_main!(benches);
