#![no_std]
#![no_main]

use core::ffi::c_int;

use aya_bpf::helpers::bpf_get_current_uid_gid;
use aya_bpf::BpfContext;
use aya_bpf::{macros::lsm, programs::LsmContext};
use aya_log_ebpf::info;

#[no_mangle]
static PID: i32 = 0;

#[lsm(hook = "file_permission")]
pub fn file_permission(ctx: LsmContext) -> i32 {
    match unsafe {try_file_permission(ctx)} {
        1 => 1,
        _ => 0,
    }



}

unsafe fn try_file_permission(ctx: LsmContext) -> i32 {
    let pid = ctx.pid();

    let global_pid = core::ptr::read_volatile(&PID);

    if global_pid == pid as i32 {
        return 1;
    }
    0

}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
