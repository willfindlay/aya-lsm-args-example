use aya::{include_bytes_aligned, Bpf};
use aya::{maps::HashMap, programs::Lsm};
use std::{
    convert::TryInto,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    thread,
    time::Duration,
};

fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {:#}", e);
    }
}

fn try_main() -> Result<(), anyhow::Error> {
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/lsm-args"
    ))?;

    let program: &mut Lsm = bpf.program_mut("task_alloc")?.try_into()?;
    program.load("task_alloc")?;
    program.attach()?;

    let map: HashMap<_, i32, i32> = bpf.map("MAP")?.try_into()?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    println!("Waiting for Ctrl-C...");
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(500))
    }

    // Dump the contents of the PIDs map
    for (_, v) in unsafe { map.iter() }.filter_map(Result::ok) {
        println!("found PID {}", v);
    }

    println!("Exiting...");

    Ok(())
}
