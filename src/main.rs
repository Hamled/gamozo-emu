pub mod emulator;
pub mod mmu;
pub mod primitive;

use emulator::{Emulator, Register};
use mmu::{Perm, Section, VirtAddr, PERM_EXEC, PERM_READ, PERM_WRITE};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    const BATCH_SIZE: usize = 100;

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

            if res.is_err() {
                local_stats.crashes += 1;
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

    // Create a new stats structure
    let stats = Arc::new(Mutex::new(Statistics::default()));

    for _ in 0..THREADS {
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
    }
}
