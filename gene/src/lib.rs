#![deny(missing_docs)]
#![deny(unused_imports)]
#![allow(clippy::derivable_impls)]

//! # Gene - High-Performance Event Scanning and Filtering Engine
//!
//! [![Crates.io Version](https://img.shields.io/crates/v/gene?style=for-the-badge)](https://crates.io/crates/gene)
//! [![Documentation](https://img.shields.io/badge/docs-gene-blue.svg?style=for-the-badge&logo=docsdotrs)](https://docs.rs/gene)
//! [![Documentation](https://img.shields.io/badge/docs-gene_derive-purple.svg?style=for-the-badge&logo=docsdotrs)](https://docs.rs/gene_derive)
//! ![Crates.io MSRV](https://img.shields.io/crates/msrv/gene?style=for-the-badge)
//! ![Crates.io License](https://img.shields.io/crates/l/gene?style=for-the-badge&color=green)
//!
//! ## Project Overview
//!
//! **Gene** is a Rust implementation of the [original Gene project](https://github.com/0xrawsec/gene) designed
//! for high-performance event scanning and filtering. Built primarily to power the
//! [Kunai](https://github.com/kunai-project/kunai) security monitoring system, Gene provides a flexible
//! and efficient rule-based engine for processing structured log events.
//!
//! ### Purpose
//! - Embeddable security event scanning engine
//! - High-throughput log processing and filtering
//! - Rule-based detection system for security monitoring
//!
//! ### Key Technologies
//! - **Rule Format**: YAML-based rule definitions for easy authoring
//! - **Pattern Matching**: Advanced field matching with XPath-like syntax
//! - **Performance**: Optimized for low-latency, high-volume event processing
//!
//! ### Target Audience
//! - Security engineers building detection systems
//! - DevOps teams implementing log monitoring
//! - Rust developers needing event processing capabilities
//!
//! ## Installation
//!
//! Add Gene to your project:
//!
//! ```bash
//! cargo add gene
//! cargo add gene_derive
//! ```
//!
//! ## Quickstart
//!
//! ```
//! use gene::{Compiler, Engine, Event, FieldGetter, FieldValue};
//! use gene_derive::{Event, FieldGetter};
//!
//! // 1. Define your event structure
//! #[derive(Event, FieldGetter)]
//! #[event(id = 1, source = "syslog".into())]
//! struct LogEvent {
//!     message: String,
//!     severity: u8,
//! }
//!
//! // 2. Create compiler and load rules
//! let mut compiler = Compiler::new();
//! compiler.load_rules_from_str(
//!     r#"
//! name: high.severity
//! matches:
//!     $sev: .severity > '5'
//! condition: $sev"#
//! ).unwrap();
//!
//! // 3. Build the scanning engine
//! let mut engine = Engine::try_from(compiler).unwrap();
//!
//! // 4. Scan events
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
//!
//! ## Core Concepts
//!
//! | Concept | Description |
//! |---------|-------------|
//! | **Events** | Structured data representing log entries or system events |
//! | **Rules** | Pattern matching and condition evaluation definitions |
//! | **Matches** | Field extraction and pattern matching expressions |
//! | **Conditions** | Boolean logic combining match results |
//! | **Decisions** | Include/exclude logic for scan results |
//! | **Templates** | Dynamic rule configuration through variable substitution |
//!
//! ## Rule Format
//!
//! Gene uses YAML for rule definitions, providing a clean and structured format:
//!
//! ```yaml
//! name: mimic.kthread
//! meta:
//!     tags: [ 'os:linux' ]
//!     attack: [ T1036 ]
//!     authors: [ 0xrawsec ]
//!     comments:
//!         - tries to catch binaries masquerading kernel threads
//! match-on:
//!     events:
//!         kunai: [1,2]  # Match specific event types
//! matches:
//!     $task_is_kthread: .info.task.flags &= '0x200000'
//!     $kthread_names: .info.task.name ~= '^(kworker)'
//! condition: not $task_is_kthread and $kthread_names
//! severity: 10
//! ```
//!
//! ### Rule Components
//!
//! - **`name`**: Unique rule identifier
//! - **`meta`**: Metadata including tags, attack IDs, authors
//! - **`match-on`**: Event type filtering
//! - **`matches`**: Field extraction and pattern matching
//! - **`condition`**: Boolean logic for detection
//! - **`severity`**: Numerical severity level
//!
//! ## Features
//!
//! ### High Performance
//! - Optimized for low-latency event processing
//! - Efficient pattern matching algorithms
//! - Minimal memory overhead
//!
//! ### Flexible Matching
//! - XPath-like field access (`.field.subfield`)
//! - Regular expression support (`~=` operator)
//! - Bitwise operations (`&=`, `|=`, etc.)
//! - Comparison operators (`>`, `<`, `==`, etc.)
//!
//! ### Advanced Capabilities
//! - **Rule Dependencies**: Chain rules together for complex detection logic
//! - **Template System**: Dynamic rule configuration with variable substitution
//! - **Metadata Support**: Rich metadata including MITRE ATT&CK mappings
//! - **Decision System**: Fine-grained control over event inclusion/exclusion
//!
//! ## Performance Benchmarks
//!
//! Benchmarks conducted with real detection rules and security events:
//!
//! ### Hundred-ish Rules (127 rules)
//! ```text
//! Number of scanned events: 1,001,600 (1,327.72 MB)
//! Scan duration: 1.28s
//! Throughput: 1,037.66 MB/s | 782,784.83 events/s
//! Detections: 550
//! ```
//!
//! ### Thousand-ish Rules (1,016 rules)
//! ```text
//! Number of scanned events: 1,001,600 (1,327.72 MB)
//! Scan duration: 9.54s
//! Throughput: 139.24 MB/s | 105,042.31 events/s
//! Detections: 550
//! ```
//!
//! > **Note**: Performance scales with rule complexity. These benchmarks demonstrate
//! > that Gene remains efficient even with large rule sets, avoiding bottleneck issues
//! > in embedded applications.
//!
//! ### Contributing
//!
//! - Report issues on [GitHub](https://github.com/kunai-project/gene-rs/issues)
//! - Submit pull requests with clear descriptions
//! - Follow Rust API guidelines and documentation standards
//! - Maintain `cargo test` and `cargo clippy` cleanliness
//!
//! ## License
//!
//! Gene is licensed under the **GPL-3.0** - see the `LICENSE` file for details.

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
