<div align="center"><img src="assets/logo.svg" width="250"/></div>

[![Crates.io Version](https://img.shields.io/crates/v/gene?style=for-the-badge)](https://crates.io/crates/gene)
[![GitHub Workflow Status (with event)](https://img.shields.io/github/actions/workflow/status/0xrawsec/gene-rs/ci.yml?style=for-the-badge&logo=github)](https://github.com/kunai-project/gene-rs/actions)

# Description

This project is a Rust implementation of the [Gene project](https://github.com/0xrawsec/gene) initially 
written in Go. The main objective of this project is to embed a security event scanning engine to
[Kunai](https://github.com/kunai-project/kunai). Even though it has been built for a specific use case,
the code in this library is completely re-usable for other log scanning purposes.

This re-implementation was also the occasion to completely rework the rule format, to
make it simpler, better structured and easier to write. It is now using the [YAML](https://yaml.org/) document 
format to encode rule information.

```yaml
name: mimic.kthread
meta:
    tags: [ 'os:linux' ]
    attack: [ T1036 ]
    authors: [ 0xrawsec ]
    comments:
        - tries to catch binaries masquerading kernel threads
match-on:
    events:
        # we match kunai events execve and execve_script
        kunai: [1,2]
matches:
    # 0x200000 is the flag for KTHREAD
    $task_is_kthread: .info.task.flags &= '0x200000'
    # common kthread names 
    $kthread_names: .info.task.name ~= '^(kworker)'
# if task is NOT a KTHREAD but we have a name that looks like one
condition: not $task_is_kthread and $kthread_names
severity: 10
```

# Benchmarks

Even though the following benchmarks were made with **real** detection rules and **real security events**
performances are indicative. I would say that the throughput is not bad, at least to fulfill the main objective of
this project. The most important aspect being that this library does not become the bottleneck of the
program in which it is embedded.

To determine whether this library might be a bottleneck for your application, try to evaluate the number
of events you want to scan per second and see if it is above the processing throughput.

## Engine loaded with hundred-ish rules (1 thread)

```
Number of scanned events: 1001600 -> 1327.72 MB
Number of loaded rules: 127
Scan duration: 1.279534249s -> 1037.66 MB/s -> 782784.83 events/s
Number of detections: 550
```

## Engine loaded with thousand-ish rules (1 thread)

```
Number of scanned events: 1001600 -> 1327.72 MB
Number of loaded rules: 1016
Scan duration: 9.535205107s -> 139.24 MB/s -> 105042.31 events/s
Number of detections: 550
```







