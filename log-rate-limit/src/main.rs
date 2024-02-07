use aya::{programs::Lsm, Btf, BpfLoader};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, warn, debug};
use tokio::signal;
use std::env;
use clap::Parser;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: u32,
}


#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env::set_var("RUST_LOG", "debug");
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }


    info!("PID: {}", opt.pid);

    // This will include your eBPF object file as rlaw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = BpfLoader::new().set_global("PID", &opt.pid, true).load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/log-rate-limit"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = BpfLoader::new().set_global("PID", &opt.pid, true).load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/log-rate-limit"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut("file_permission").unwrap().try_into()?;
    program.load("file_permission", &btf)?;
    program.attach()?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
