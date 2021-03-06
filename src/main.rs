pub mod emulator;
pub mod file;
pub mod mmu;
pub mod primitive;

use emulator::{Emulator, Register};
use mmu::{Perm, Section, VirtAddr, PERM_EXEC, PERM_RAW, PERM_READ, PERM_WRITE};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEBUG: usize = 0; // Increase for more debug info
const THREADS: usize = 1;

fn rdtsc() -> u64 {
    unsafe { std::arch::x86_64::_rdtsc() }
}

#[derive(Default)]
/// Statistics during fuzzing
struct Statistics {
    /// Number of fuzz cases
    fuzz_cases: u64,

    /// Number of crashes
    crashes: u64,

    /// RISC-V instructions executed
    instrs_execed: u64,

    /// CPU cycles spent in workers
    worker_cycles: u64,

    /// CPU cycles spent resetting guests
    reset_cycles: u64,

    /// CPU cycles spent emulating
    emu_cycles: u64,
}

fn worker(mut emu: Emulator, original: Arc<Emulator>, stats: Arc<Mutex<Statistics>>) {
    const BATCH_SIZE: usize = if DEBUG > 0 { 2 } else { 100 };

    loop {
        // Start worker timer
        let batch_start = rdtsc();

        let mut local_stats = Statistics::default();

        for _ in 0..BATCH_SIZE {
            let it = rdtsc();
            emu.reset(&*original);
            local_stats.reset_cycles += rdtsc() - it;

            let it = rdtsc();
            let res = emu.run(&mut local_stats.instrs_execed);
            local_stats.emu_cycles += rdtsc() - it;

            if let Err(reason) = res {
                local_stats.crashes += 1;
                if DEBUG > 0 {
                    println!(
                        "Emu stopped at {:#x} with: {:#x?}",
                        emu.reg(Register::Pc),
                        reason
                    );
                }
            }

            local_stats.fuzz_cases += 1;
        }

        // Get access to statistics
        let mut stats = stats.lock().unwrap();

        stats.fuzz_cases += local_stats.fuzz_cases;
        stats.crashes += local_stats.crashes;
        stats.instrs_execed += local_stats.instrs_execed;

        // Track amount of cycles spent in worker for this batch
        stats.worker_cycles += rdtsc() - batch_start;
        stats.reset_cycles += local_stats.reset_cycles;
        stats.emu_cycles += local_stats.emu_cycles;

        if DEBUG > 0 {
            break;
        }
    }
}

fn main() {
    let program = "./objdump";
    let args: Vec<&str> = vec![program, "-x", "test_app"];

    let mut emu = Emulator::new(32 * 1024 * 1024);
    emu.load(
        program,
        &[
            Section {
                file_off: 0x0000000000000000,
                virt_addr: VirtAddr(0x0000000000010000),
                file_size: 0x00000000000e2e44,
                mem_size: 0x00000000000e2e44,
                permissions: Perm(PERM_READ | PERM_EXEC),
            },
            Section {
                file_off: 0x00000000000e3000,
                virt_addr: VirtAddr(0x00000000000f3000),
                file_size: 0x0000000000001e4a,
                mem_size: 0x00000000000046e0,
                permissions: Perm(PERM_READ | PERM_WRITE),
            },
        ],
    )
    .expect("Failed to load fuzz target into address space");

    emu.set_reg(Register::Pc, 0x104cc);

    // Setup a stack

    //   - First create a region with no perms to hopefully catch
    //     stack overflows
    emu.memory
        .allocate_perms(1024, Perm(PERM_RAW))
        .expect("Failed to allocate stack guard");

    let stack = emu
        .memory
        .allocate(32 * 1024)
        .expect("Failed to allocate stack");
    emu.set_reg(Register::Sp, stack.0 as u64 + 32 * 1024);

    // Setup arguments
    let mut argv: Vec<VirtAddr> = Vec::new();
    for arg in args {
        let arg_addr = emu
            .memory
            .allocate(arg.len() + 1)
            .expect("Failed to allocate space for argument");
        emu.memory
            .write_from(arg_addr, String::from(arg).as_bytes())
            .expect("Failed to write argument");
        emu.memory
            .write_from(VirtAddr(arg_addr.0 + arg.len()), &[0u8])
            .expect("Failed to write argument null terminator");

        argv.push(arg_addr);
    }

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

    // Argv, Argc
    push!(0u64); // Argv null
    for arg_ptr in (&argv).iter().rev() {
        push!(arg_ptr.0);
    }
    push!(argv.len() as u64);

    // Set the initial program break
    emu.sbrk(0);

    let emu = Arc::new(emu);

    // Create a new stats structure
    let stats = Arc::new(Mutex::new(Statistics::default()));

    for _ in 0..(if DEBUG > 0 { 1 } else { THREADS }) {
        let worker_emu = emu.fork();
        let original = emu.clone();
        let stats = stats.clone();

        std::thread::spawn(move || {
            worker(worker_emu, original, stats);
        });
    }

    // Start a timer
    let start = Instant::now();

    let mut last_cases = 0;
    let mut last_instrs = 0;
    loop {
        std::thread::sleep(Duration::from_millis(1000));

        let elapsed = start.elapsed().as_secs_f64();

        let stats = stats.lock().unwrap();

        let fuzz_cases = stats.fuzz_cases;
        let crashes = stats.crashes;
        let instrs = stats.instrs_execed;

        let reset_pct = (stats.reset_cycles as f64 / stats.worker_cycles as f64) * 100.0;
        let emu_pct = (stats.emu_cycles as f64 / stats.worker_cycles as f64) * 100.0;

        println!(
            "[{:8.0}] cases {:10} ({:8}/s) | crashes {:10} ({:3}%) | Minst/sec {:10}\n\
             reset {:3.1}% | emu {:3.1}%",
            elapsed,
            fuzz_cases,
            fuzz_cases - last_cases,
            crashes,
            (crashes as f64 / fuzz_cases as f64) * 100.0,
            (instrs - last_instrs) / 1_000_000,
            reset_pct,
            emu_pct
        );

        last_cases = fuzz_cases;
        last_instrs = instrs;

        if DEBUG > 0 {
            break;
        }
    }
}
