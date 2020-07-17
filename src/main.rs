pub mod emulator;
pub mod mmu;
pub mod primitive;

use emulator::{Emulator, Register};
use mmu::{Perm, Section, VirtAddr, PERM_EXEC, PERM_READ, PERM_WRITE};
use std::sync::Arc;
use std::time::Duration;

const THREADS: usize = 8;

fn worker(mut emu: Emulator, original: Arc<Emulator>) {
    const BATCH_SIZE: usize = 100;

    loop {
        for _ in 0..BATCH_SIZE {
            emu.reset(&*original);

            match emu.run() {
                Err(reason) => println!("Stop reason: {:?}", reason),
                _ => println!("Emulation ended successfully"),
            }
        }
    }
}

fn main() {
    let mut emu = Emulator::new(1024 * 1024);
    emu.load(
        "./test_app",
        &[
            Section {
                file_off: 0x0000000000000000,
                virt_addr: VirtAddr(0x0000000000010000),
                file_size: 0x0000000000000190,
                mem_size: 0x0000000000000190,
                permissions: Perm(PERM_READ),
            },
            Section {
                file_off: 0x0000000000000190,
                virt_addr: VirtAddr(0x0000000000011190),
                file_size: 0x0000000000002598,
                mem_size: 0x0000000000002598,
                permissions: Perm(PERM_EXEC),
            },
            Section {
                file_off: 0x0000000000002728,
                virt_addr: VirtAddr(0x0000000000014728),
                file_size: 0x00000000000000f8,
                mem_size: 0x0000000000000750,
                permissions: Perm(PERM_READ | PERM_WRITE),
            },
        ],
    )
    .expect("Failed to load test application into addres space");

    emu.set_reg(Register::Pc, 0x11190);

    // Setup a stack
    let stack = emu
        .memory
        .allocate(32 * 1024)
        .expect("Failed to allocate stack");
    emu.set_reg(Register::Sp, stack.0 as u64 + 32 * 1024);

    // Setup arguments
    let progname = b"test_app\0";
    let argv0 = emu
        .memory
        .allocate(progname.len())
        .expect("Failed to allocate program name");
    emu.memory
        .write_from(argv0, progname)
        .expect("Failed to write program name");

    macro_rules! push {
        ($expr:expr) => {
            let sp = emu.reg(Register::Sp) - 8;
            emu.memory
                .write(VirtAddr(sp as usize), $expr)
                .expect("Push failed");
            emu.set_reg(Register::Sp, sp);
        };
    }

    push!(0u64); // Auxp
    push!(0u64); // Envp
    push!(0u64); // Argv null
    push!(argv0.0); // Argv 0
    push!(1u64); // Argc

    let emu = Arc::new(emu);

    for _ in 0..THREADS {
        let worker_emu = emu.fork();
        let original = emu.clone();

        std::thread::spawn(move || {
            worker(worker_emu, original);
        });
    }

    std::thread::sleep(Duration::from_millis(6 * 1000));
}
