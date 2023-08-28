# Netto

![Example output from Netto](images/online_boutique.svg)

_Netto is an eBPF-based network monitoring tool for Linux that measures the CPU cost of the Linux network stack._

## Features

 - Measurement of the on-CPU time of the main networking entry points in kernel
 - Breakdown of the `NET_RX_SOFTIRQ` entry point into the basic network functions by stack trace-based profiling of the kernel
 - Low overhead
 - Real time operation
 - Minimum Linux version supported: **5.11** (`BPF_MAP_TYPE_TASK_STORAGE`)

## Compilation

To compile the tool you'll need:
 - Latest Rust toolchain (stable or nightly)
 - [wasm_pack](https://rustwasm.github.io/wasm-pack/installer/) (for the web frontend)

Compile and run with:
    
    cargo xtask run [--release]

## Usage

Netto exposes the real time results as a Wasm-powered web page accessible on `http://localhost:8080`

## Repository structure

| Folder | Contents |
| - | - |
| `images` | Images used on this `README` |
| `main` | Main Rust binary crate |
| `main/src/bpf` | BPF-C programs |
| `metrics-common` | Bridge Rust library crate for `main` and `web-frontend` |
| `web-frontend` | Rust WebAssembly frontend |
| `www` | Static files for the web frontend |
| `xtask` | Utility binary crate for managing coordination between the other crates |
