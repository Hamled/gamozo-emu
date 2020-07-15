pub mod primitive;
use primitive::Primitive;
const PERM_READ: u8 = 1 << 0;
const PERM_WRITE: u8 = 2 << 0;
const PERM_EXEC: u8 = 3 << 0;
const PERM_RAW: u8 = 4 << 0;

/// Block size used for resetting and tracking memory which has been modified
/// the Larger this is, the fewer but more expensive memcpys() need to occur,
/// the smaller, the greater but less expensive memcpys() need to occur.
/// it seems the sweet spot is
const DIRTY_BLOCK_SIZE: usize = 4096;

/// A permissions byte which corresponds to a memory byte and defines the
/// permissions it has
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Perm(u8);

/// A guest virtual address
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtAddr(usize);

/// An isolated memory space
pub struct Mmu {
    /// Block of memory for this address space
    /// Offset 0 corresponds to address 0 in the guest address space
    memory: Vec<u8>,

    /// Holds the permission bytes for the corresponding byte in memory
    permissions: Vec<Perm>,

    /// Tracks blocks in `memory` which are dirty
    dirty: Vec<usize>,

    /// Tracks which parts of `memory` have been dirtied
    dirty_bitmap: Vec<u64>,

    /// Current base address of the next allocation
    cur_alc: VirtAddr,
}

impl Mmu {
    /// Create a new memory space which can hold `size` bytes
    pub fn new(size: usize) -> Self {
        Mmu {
            memory: vec![0; size],
            permissions: vec![Perm(0); size],
            dirty: Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1),
            dirty_bitmap: vec![0u64; size / DIRTY_BLOCK_SIZE / 64 + 1],
            cur_alc: VirtAddr(0x10000),
        }
    }

    /// Fork from an existing MMU
    pub fn fork(&self) -> Self {
        let size = self.memory.len();

        Mmu {
            memory: self.memory.clone(),
            permissions: self.permissions.clone(),
            dirty: Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1),
            dirty_bitmap: vec![0u64; size / DIRTY_BLOCK_SIZE / 64 + 1],
            cur_alc: self.cur_alc.clone(),
        }
    }

    /// Restores memory back to the original state (eg. restores all dirty
    /// blocks from the state of `other`)
    pub fn reset(&mut self, other: &Mmu) {
        for block in &self.dirty {
            // Get the start and end addresses of the dirtied memory
            let start = block * DIRTY_BLOCK_SIZE;
            let end = (block + 1) * DIRTY_BLOCK_SIZE;

            // Zero the bitmap. this hits wide, but its fine, we have to do
            // a 64-bit write anyways, no reason to compute the bit index
            self.dirty_bitmap[block / 64] = 0;

            self.memory[start..end].copy_from_slice(&other.memory[start..end]);
        }

        // Clear the dirty list
        self.dirty.clear();
    }

    /// Allocate a region of memory as RW in the address space
    pub fn allocate(&mut self, size: usize) -> Option<VirtAddr> {
        // 16-byte align the allocation
        let align_size = (size + 0xf) & !0xf;

        // Get the current allocation base
        let base = self.cur_alc;

        // Cannote allocate
        if base.0 >= self.memory.len() {
            return None;
        }

        // Update the allocation size
        self.cur_alc = VirtAddr(self.cur_alc.0.checked_add(align_size)?);

        // Could not satisfy allocation without going OOM
        if self.cur_alc.0 > self.memory.len() {
            return None;
        }

        // Mark the memory as un-initialized and writeable
        self.set_permissions(base, size, Perm(PERM_RAW | PERM_WRITE));

        Some(base)
    }

    /// Apply permissions to a region of memory
    pub fn set_permissions(&mut self, addr: VirtAddr, size: usize, perm: Perm) -> Option<()> {
        self.permissions
            .get_mut(addr.0..addr.0.checked_add(size)?)?
            .iter_mut()
            .for_each(|x| *x = perm);

        Some(())
    }

    pub fn write_from(&mut self, addr: VirtAddr, buf: &[u8]) -> Option<()> {
        let perms = self
            .permissions
            .get_mut(addr.0..addr.0.checked_add(buf.len())?)?;

        let mut has_raw = false;
        if !perms.iter_mut().all(|x| {
            has_raw |= (x.0 & PERM_RAW) != 0;
            (x.0 & PERM_WRITE) != 0
        }) {
            return None;
        }

        self.memory
            .get_mut(addr.0..addr.0.checked_add(buf.len())?)?
            .copy_from_slice(buf);

        let block_start = addr.0 / DIRTY_BLOCK_SIZE;
        let block_end = (addr.0 + buf.len()) / DIRTY_BLOCK_SIZE;
        for block in block_start..=block_end {
            // Determine the bitmap position of the dirty block
            let idx = block_start / 64;
            let bit = block_start % 64;

            // Check if the block is not dirty
            if self.dirty_bitmap[idx] & (1 << bit) == 0 {
                // Block is not dirty, add it to the dirty list
                self.dirty.push(block);
                self.dirty_bitmap[idx] |= 1 << bit;
            }
        }

        if has_raw {
            perms.iter_mut().for_each(|x| {
                if (x.0 & PERM_RAW) != 0 {
                    // Mark memory as readable
                    *x = Perm(x.0 | PERM_READ);
                }
            });
        }

        Some(())
    }

    /// Read the memory at `addr` into `buf` assuming all `exp_perms` bits are set
    /// This functions checks to see if all bits in `exp_perms` are set in the permission bytes.
    /// If this is zero, we ignore permissions entirely.
    pub fn read_into_perms(&self, addr: VirtAddr, buf: &mut [u8], exp_perms: Perm) -> Option<()> {
        let perms = self
            .permissions
            .get(addr.0..addr.0.checked_add(buf.len())?)?;

        if exp_perms.0 != 0 && !perms.iter().all(|x| (x.0 & exp_perms.0) == exp_perms.0) {
            return None;
        }

        buf.copy_from_slice(self.memory.get(addr.0..addr.0.checked_add(buf.len())?)?);

        Some(())
    }

    pub fn read_into(&self, addr: VirtAddr, buf: &mut [u8]) -> Option<()> {
        self.read_into_perms(addr, buf, Perm(PERM_READ))
    }

    pub fn read_perms<T: Primitive>(&self, addr: VirtAddr, exp_perms: Perm) -> Option<T> {
        let mut tmp = [0u8; 16];
        self.read_into_perms(addr, &mut tmp[..core::mem::size_of::<T>()], exp_perms)?;
        Some(unsafe { core::ptr::read_unaligned(tmp.as_ptr() as *const T) })
    }

    pub fn read<T: Primitive>(&self, addr: VirtAddr) -> Option<T> {
        self.read_perms(addr, Perm(PERM_READ))
    }

    pub fn write<T: Primitive>(&mut self, addr: VirtAddr, val: T) -> Option<()> {
        let tmp = unsafe {
            core::slice::from_raw_parts(&val as *const T as *const u8, core::mem::size_of::<T>())
        };
        self.write_from(addr, tmp)
    }
}

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
