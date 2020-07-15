pub mod emulator;
pub mod mmu;
pub mod primitive;

use emulator::{Emulator, Register};
use mmu::{Perm, Section, VirtAddr, PERM_EXEC, PERM_READ, PERM_WRITE};

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

    }
}
