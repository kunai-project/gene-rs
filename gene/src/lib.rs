#![deny(missing_docs)]
#![deny(unused_imports)]
#![allow(clippy::derivable_impls)]

//! # Gene - A high-performance event scanning and filtering engine
//!
//! Gene is a Rust library for scanning and filtering structured log events using
//! a powerful rule-based system. It provides efficient pattern matching, condition
//! evaluation, and decision-making capabilities for event processing pipelines.
//!
//! ## Core Concepts
//!
//! - **Events**: Structured data representing log entries or system events
//! - **Rules**: Pattern matching and condition evaluation definitions
//! - **Decisions**: Include/exclude logic for controlling scan results
//! - **Templates**: Dynamic rule configuration through variable substitution
//!
//! ## Key Features
//!
//! - **High Performance**: Optimized for low-latency event processing
//! - **Flexible Matching**: Support for complex pattern matching on event fields
//! - **Decision System**: Fine-grained control over event inclusion/exclusion
//! - **Rule Dependencies**: Support for rule inter-dependencies and chaining
//! - **Template System**: Dynamic rule configuration through variable substitution
//! - **Metadata Support**: Tags, attack IDs, severity levels, and actions
//!
//! ## Usage Example
//!
//! ```no_run
//! use gene::{Compiler, Engine, Event, FieldGetter, FieldValue};
//! use gene_derive::{Event, FieldGetter};
//!
//! // Define an event type
//! #[derive(Event, FieldGetter)]
//! #[event(id = 1, source = "syslog".into())]
//! struct LogEvent {
//!     message: String,
//!     severity: u8,
//! }
//!
//! // Load rules
//! let mut compiler = Compiler::new();
//! compiler.load_rules_from_str(
//!     r#"name: high.severity
//! matches:
//!     $sev: .severity > 5
//! condition: $sev"#
//! ).unwrap();
//!
//! // Create engine
//! let mut engine = Engine::try_from(compiler).unwrap();
//!
//! // Scan events
//! let event = LogEvent {
//!     message: "Critical error".to_string(),
//!     severity: 8,
//! };
//!
//! let scan_result = engine.scan(&event).unwrap();
//! if scan_result.includes_detection("high.severity") {
//!     println!("High severity event detected!");
//! }
//! ```

mod event;
pub use event::{Event, FieldGetter};

pub mod rules;
pub use rules::Rule;

mod engine;
pub use engine::*;

pub mod values;
pub use values::FieldValue;

mod paths;
pub use paths::XPath;

mod template;
pub use template::Templates;

mod compiler;
pub use compiler::Compiler;

mod map;
