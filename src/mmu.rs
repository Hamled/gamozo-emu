use crate::emulator::EmuStop;
use crate::primitive::Primitive;

const TRACK_UNINIT: bool = false;

pub const PERM_READ: u8 = 1 << 0;
pub const PERM_WRITE: u8 = 2 << 0;
pub const PERM_EXEC: u8 = 3 << 0;
pub const PERM_RAW: u8 = 4 << 0;

/// Block size used for resetting and tracking memory which has been modified
/// the Larger this is, the fewer but more expensive memcpys() need to occur,
/// the smaller, the greater but less expensive memcpys() need to occur.
/// it seems the sweet spot is
const DIRTY_BLOCK_SIZE: usize = 4096;

/// A permissions byte which corresponds to a memory byte and defines the
/// permissions it has
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Perm(pub u8);

/// A guest virtual address
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtAddr(pub usize);

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

        self.cur_alc = other.cur_alc;

        // Clear the dirty list
        self.dirty.clear();
    }

    /// Allocate a region of memory as RW in the address space with given permissions
    pub fn allocate_perms(&mut self, size: usize, perm: Perm) -> Option<VirtAddr> {
        // If size is zero, just return current alloc base
        if size == 0 {
            return Some(self.cur_alc);
        }

        // 16-byte align the allocation
        let align_size = (size + 0xf) & !0xf;

        // Get the current allocation base
        let base = self.cur_alc;

        // Cannot allocate
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
        self.set_permissions(base, align_size, perm);

        Some(base)
    }

    /// Allocate a region of memory as RW in the address space
    pub fn allocate(&mut self, size: usize) -> Option<VirtAddr> {
        self.allocate_perms(
            size,
            if TRACK_UNINIT {
                Perm(PERM_RAW | PERM_WRITE)
            } else {
                Perm(PERM_READ | PERM_WRITE)
            },
        )
    }

    /// Apply permissions to a region of memory
    pub fn set_permissions(&mut self, addr: VirtAddr, size: usize, perm: Perm) -> Option<()> {
        self.permissions
            .get_mut(addr.0..addr.0.checked_add(size)?)?
            .iter_mut()
            .for_each(|x| *x = perm);

        Some(())
    }

    pub fn write_from(&mut self, addr: VirtAddr, buf: &[u8]) -> Result<(), EmuStop> {
        let start = addr.0;
        let end = start
            .checked_add(buf.len())
            .ok_or(EmuStop::AddressOverflow)?;

        let perms = self
            .permissions
            .get_mut(start..end)
            .ok_or(EmuStop::AddressMiss(VirtAddr(start), buf.len()))?;

        let mut has_raw = false;
        for (addr, perm) in perms.iter_mut().enumerate() {
            if (perm.0 & PERM_WRITE) == 0 {
                return Err(EmuStop::WriteFault(VirtAddr(start + addr)));
            }
            has_raw |= (perm.0 & PERM_RAW) != 0;
        }

        self.memory
            .get_mut(start..end)
            .ok_or(EmuStop::AddressMiss(VirtAddr(start), buf.len()))?
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

        Ok(())
    }

    /// Read the memory at `addr` into `buf` assuming all `exp_perms` bits are set
    /// This functions checks to see if all bits in `exp_perms` are set in the permission bytes.
    /// If this is zero, we ignore permissions entirely.
    pub fn read_into_perms(
        &self,
        addr: VirtAddr,
        buf: &mut [u8],
        exp_perms: Perm,
    ) -> Result<(), EmuStop> {
        let start = addr.0;
        let end = start
            .checked_add(buf.len())
            .ok_or(EmuStop::AddressOverflow)?;

        let perms = self
            .permissions
            .get(start..end)
            .ok_or(EmuStop::AddressMiss(VirtAddr(start), buf.len()))?;

        if exp_perms.0 != 0 {
            for (addr, perm) in perms.iter().enumerate() {
                if (perm.0 & exp_perms.0) != exp_perms.0 {
                    return Err(if perm.0 & PERM_RAW != 0 {
                        EmuStop::UninitFault(VirtAddr(start + addr))
                    } else {
                        EmuStop::ReadFault(VirtAddr(start + addr))
                    });
                }
            }
        }

        buf.copy_from_slice(
            self.memory
                .get(start..end)
                .ok_or(EmuStop::AddressMiss(VirtAddr(start), buf.len()))?,
        );

        Ok(())
    }

    pub fn read_into(&self, addr: VirtAddr, buf: &mut [u8]) -> Result<(), EmuStop> {
        self.read_into_perms(addr, buf, Perm(PERM_READ))
    }

    pub fn peek_perms(
        &self,
        addr: VirtAddr,
        size: usize,
        exp_perms: Perm,
    ) -> Result<&[u8], EmuStop> {
        let start = addr.0;
        let end = start.checked_add(size).ok_or(EmuStop::AddressOverflow)?;

        let perms = self
            .permissions
            .get(start..end)
            .ok_or(EmuStop::AddressMiss(VirtAddr(start), size))?;

        if exp_perms.0 != 0 {
            for (addr, &perm) in perms.iter().enumerate() {
                if (perm.0 & exp_perms.0) != exp_perms.0 {
                    return Err(EmuStop::ReadFault(VirtAddr(start + addr)));
                }
            }
        }

        Ok(&self.memory[start..end])
    }

    pub fn peek(&self, addr: VirtAddr, size: usize) -> Result<&[u8], EmuStop> {
        self.peek_perms(addr, size, Perm(PERM_READ))
    }

    pub fn read_perms<T: Primitive>(&self, addr: VirtAddr, exp_perms: Perm) -> Result<T, EmuStop> {
        let mut tmp = [0u8; 16];
        self.read_into_perms(addr, &mut tmp[..core::mem::size_of::<T>()], exp_perms)?;
        Ok(unsafe { core::ptr::read_unaligned(tmp.as_ptr() as *const T) })
    }

    pub fn read<T: Primitive>(&self, addr: VirtAddr) -> Result<T, EmuStop> {
        self.read_perms(addr, Perm(PERM_READ))
    }

    pub fn write<T: Primitive>(&mut self, addr: VirtAddr, val: T) -> Result<(), EmuStop> {
        let tmp = unsafe {
            core::slice::from_raw_parts(&val as *const T as *const u8, core::mem::size_of::<T>())
        };
        self.write_from(addr, tmp)
    }

    pub fn load_section(&mut self, file_contents: &[u8], section: &Section) -> Option<()> {
        self.set_permissions(section.virt_addr, section.mem_size, Perm(PERM_WRITE))?;

        self.write_from(
            section.virt_addr,
            file_contents
                .get(section.file_off..section.file_off.checked_add(section.file_size)?)?,
        )
        .ok()?;

        // Write in any padding with zeros
        if section.mem_size > section.file_size {
            let padding = vec![0u8; section.mem_size - section.file_size];
            self.write_from(
                VirtAddr(section.virt_addr.0.checked_add(section.file_size)?),
                &padding,
            )
            .ok()?;
        }

        // Demote permissions to originals
        self.set_permissions(section.virt_addr, section.mem_size, section.permissions)?;

        // Update the allocator beyond any sections we load
        self.cur_alc = VirtAddr(std::cmp::max(
            self.cur_alc.0,
            section.virt_addr.0 + section.mem_size,
        ));

        Some(())
    }
}

pub struct Section {
    pub file_off: usize,
    pub virt_addr: VirtAddr,
    pub file_size: usize,
    pub mem_size: usize,
    pub permissions: Perm,
}
