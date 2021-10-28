#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use aya_bpf::{macros::lsm, macros::map, maps::HashMap, programs::LsmContext};
use vmlinux::task_struct;

#[map]
static mut MAP: HashMap<i32, i32> = HashMap::with_max_entries(1024, 0);

#[lsm(name = "task_alloc")]
pub fn task_alloc(ctx: LsmContext) -> i32 {
    match unsafe { try_task_alloc(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_task_alloc(ctx: LsmContext) -> Result<i32, i32> {
    let task: *const task_struct = ctx.argument(0);
    let pid = (*task).pid;

    let _ = MAP.insert(&pid, &pid, 0);
    //info!(&ctx, "new pid {}", pid);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
