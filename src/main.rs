pub mod mmu;
pub mod primitive;

use mmu::{Mmu, Perm, VirtAddr, PERM_EXEC, PERM_READ, PERM_WRITE};
use std::path::Path;

/// All the state of the emulated system
pub struct Emulator {
    /// Memory for the emulator
    pub memory: Mmu,
}

impl Emulator {
    /// Creates a new emulator with `size` bytes of memory
    pub fn new(size: usize) -> Self {
        Emulator {
            memory: Mmu::new(size),
        }
    }

    /// Fork an emulator into a new emulator which will diff from the original
    pub fn fork(&self) -> Self {
        Emulator {
            memory: self.memory.fork(),
        }
    }
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
