pub mod emulator;
pub mod mmu;
pub mod primitive;

use emulator::Emulator;
use mmu::{Perm, VirtAddr, PERM_EXEC, PERM_READ, PERM_WRITE};
use std::path::Path;

}

fn main() {
    let mut emu = Emulator::new(1024 * 1024);

    let tmp = emu.memory.allocate(4).unwrap();
    emu.memory.write_from(VirtAddr(tmp.0 + 0), b"asdf").unwrap();

    {
        let mut forked = emu.fork();
        for ii in 0..100_000_000 {
            forked.memory.reset(&emu.memory);
        }
    }
}
