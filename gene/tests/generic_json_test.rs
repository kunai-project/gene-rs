use gene::{Engine, Event, FieldGetter, FieldValue, Rule, XPath};
use lazy_static::lazy_static;
use libflate::gzip;
use std::{borrow::Cow, fs::File, io::Read, slice, str::FromStr, time::Duration};

use serde_json::Value;

struct JsonEvent {
    root: Value,
}

impl From<Value> for JsonEvent {
    fn from(value: Value) -> Self {
        Self::new(value)
    }
}

lazy_static! {
    static ref ID_PATH: XPath = XPath::from_str(".Event.System.EventID").unwrap();
    static ref SRC_PATH: XPath = XPath::from_str(".Event.System.Channel").unwrap();
}

impl JsonEvent {
    fn new(value: Value) -> Self {
        Self { root: value }
    }

    fn get_rec(v: &Value, mut next: slice::Iter<'_, std::string::String>) -> Option<Value> {
        match v {
            Value::Number(n) => Some(Value::Number(n.clone())),
            Value::Object(m) => Self::get_rec(m.get(next.next()?)?, next),
            Value::Array(a) => Some(Value::Array(a.clone())),
            Value::Bool(b) => Some(Value::Bool(*b)),
            Value::String(s) => Some(Value::String(s.clone())),
            Value::Null => Some(Value::Null),
        }
    }

    fn field_value(value: Value) -> FieldValue {
        match value {
            Value::String(s) => s.into(),
            Value::Bool(b) => b.into(),
            Value::Number(n) => match n {
                n if n.is_u64() => n.as_u64().unwrap().into(),
                n if n.is_f64() => n.as_f64().unwrap().into(),
                n if n.is_i64() => n.as_i64().unwrap().into(),
                _ => unreachable!(),
            },
            Value::Object(_) | Value::Array(_) | Value::Null => unreachable!(),
        }
    }
}

impl FieldGetter for JsonEvent {
    #[inline]
    fn get_from_iter(&self, i: core::slice::Iter<'_, std::string::String>) -> Option<FieldValue> {
        Some(Self::field_value(Self::get_rec(&self.root, i)?))
    }
}

impl Event for JsonEvent {
    #[inline]
    fn id(&self) -> i64 {
        if let FieldValue::Number(num) = self.get_from_path(&ID_PATH).unwrap() {
            return num.try_into().unwrap();
        }
        match self.get_from_path(&ID_PATH).unwrap() {
            FieldValue::Number(num) => num.try_into().unwrap(),
            FieldValue::String(s) => s.parse::<i64>().unwrap(),
            _ => panic!("cannot get event id"),
        }
    }

    #[inline]
    fn source(&self) -> Cow<'_, str> {
        if let FieldValue::String(src) = self.get_from_path(&SRC_PATH).unwrap() {
            return src.into();
        }
        panic!("cannot get event source")
    }
}

fn time_it<F: FnMut()>(mut f: F) -> Duration {
    let start_time = std::time::Instant::now();
    f();
    let end_time = std::time::Instant::now();
    end_time - start_time
}

#[test]
#[ignore = "long test that must be ran in release mode"]
fn test_engine() {
    let mut engine = Engine::new();
    let rules = Rule::deserialize_reader(File::open("./tests/data/compiled.gen").unwrap());
    let it = rules.into_iter().map(|r| r.unwrap()).collect::<Vec<Rule>>();

    for i in 0..4 {
        for r in it.iter() {
            let mut r = r.clone();
            r.name = format!("{}.{}", r.name, i);
            engine.insert_rule(r).unwrap();
        }
    }

    // decoding gzip file
    let mut dec = gzip::Decoder::new(File::open("./tests/data/events.json.gz").unwrap()).unwrap();
    let mut all = vec![];
    dec.read_to_end(&mut all).unwrap();

    let des = serde_json::Deserializer::from_slice(all.as_slice()).into_iter::<Value>();

    // loading all events
    let events: Vec<JsonEvent> = des.map(|v| JsonEvent::from(v.unwrap())).collect();

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
