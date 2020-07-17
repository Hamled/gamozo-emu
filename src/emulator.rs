use crate::mmu::{Mmu, Perm, Section, VirtAddr, PERM_EXEC};
use std::path::Path;

const VERBOSE_GUEST_PRINTS: bool = false;

/// All the state of the emulated system
pub struct Emulator {
    /// Memory for the emulator
    pub memory: Mmu,
    pub registers: [u64; 33],
}

impl Emulator {
    /// Creates a new emulator with `size` bytes of memory
    pub fn new(size: usize) -> Self {
        Emulator {
            memory: Mmu::new(size),
            registers: [0; 33],
        }
    }

    /// Fork an emulator into a new emulator which will diff from the original
    pub fn fork(&self) -> Self {
        Emulator {
            memory: self.memory.fork(),
            registers: self.registers.clone(),
        }
    }

    /// Reset the state of `self` to `other`, assuming that `self` is
    /// forked off of `other`. If it is not, the results are invalid.
    pub fn reset(&mut self, other: &Self) {
        // Reset memory state
        self.memory.reset(&other.memory);

        // Reset register state
        self.registers = other.registers;
    }

    pub fn reg(&self, register: Register) -> u64 {
        if register != Register::Zero {
            self.registers[register as usize]
        } else {
            0
        }
    }

    pub fn set_reg(&mut self, register: Register, val: u64) {
        if register != Register::Zero {
            self.registers[register as usize] = val;
        }
    }

    /// Load a file into the emulators addres space using the sections as described
    pub fn load<P: AsRef<Path>>(&mut self, filename: P, sections: &[Section]) -> Option<()> {
        // Read the input file
        let contents = std::fs::read(filename).ok()?;

        // Go through each section and load it
        for section in sections {
            self.memory.load_section(&contents, section);
        }

        Some(())
    }

    pub fn run(&mut self, instrs_execed: &mut u64) -> Result<(), EmuStop> {
        loop {
            // Get the current program counter
            let pc = self.reg(Register::Pc);
            let inst: u32 = self
                .memory
                .read_perms(VirtAddr(pc as usize), Perm(PERM_EXEC))?;

            *instrs_execed += 1;

            // Execute the instruction if possible
            match self.exec_inst(pc, inst) {
                Ok(new_pc) => {
                    // Update PC to the next instruction
                    self.set_reg(Register::Pc, new_pc);
                }
                Err(EmuStop::Syscall) => match self.handle_syscall() {
                    Ok(_) => self.set_reg(Register::Pc, pc.wrapping_add(4)),
                    Err(EmuStop::Exit) => return Ok(()),
                    Err(reason) => return Err(reason),
                },
                Err(EmuStop::Exit) => return Ok(()),
                Err(reason) => return Err(reason),
            }
        }
    }

    fn handle_syscall(&mut self) -> Result<(), EmuStop> {
        // Get the syscall number
        let num = self.reg(Register::A7);

        match num {
            29 => {
                // ioctl()
                self.set_reg(Register::A0, !0);
                Ok(())
            }
            66 => {
                // writev()
                let fd = self.reg(Register::A0);
                let iov = self.reg(Register::A1);
                let iovcnt = self.reg(Register::A2);

                // We currently only handle stdout and stderr
                if fd != 1 && fd != 2 {
                    // Return error
                    self.set_reg(Register::A0, !0);
                    return Ok(());
                }

                let mut bytes_written = 0;

                for idx in 0..iovcnt {
                    // Compute the pointer to the IO vector entry
                    // corresponding to this index and validate that it
                    // will not overflow pointer size for the size of
                    // the `_iovec`
                    let ptr = 16u64
                        .checked_mul(idx)
                        .and_then(|x| x.checked_add(iov))
                        .and_then(|x| x.checked_add(15))
                        .ok_or(EmuStop::SyscallIntegerOverflow)?
                        as usize
                        - 15;

                    // Read the iovec entry pointer and length
                    let buf: usize = self.memory.read(VirtAddr(ptr))?;
                    let len: usize = self.memory.read(VirtAddr(ptr + 8))?;

                    // Look at the buffer
                    let data = self.memory.peek(VirtAddr(buf), len)?;

                    if VERBOSE_GUEST_PRINTS {
                        if let Ok(output) = core::str::from_utf8(data) {
                            print!("{}", output);
                        }
                    }

                    bytes_written += data.len() as u64;
                }

                self.set_reg(Register::A0, bytes_written);
                Ok(())
            }
            94 => Err(EmuStop::Exit),
            96 => {
                // set_tid_address(), just return the TID
                self.set_reg(Register::A0, 1337);
                Ok(())
            }
            _ => panic!("Unhandled syscall {}\n", num),
        }
    }

    fn exec_inst(&mut self, pc: u64, inst: u32) -> Result<u64, EmuStop> {
        // Extract the opcode from the instruction
        let opcode = inst & 0b1111111;

        match opcode {
            0b0110111 => {
                // LUI
                let inst = Utype::from(inst);
                self.set_reg(inst.rd, inst.imm as i64 as u64);
            }
            0b0010111 => {
                // AUIPC
                let inst = Utype::from(inst);
                self.set_reg(inst.rd, (inst.imm as i64 as u64).wrapping_add(pc))
            }
            0b1101111 => {
                // JAL
                let inst = Jtype::from(inst);
                self.set_reg(inst.rd, pc.wrapping_add(4));
                return Ok(pc.wrapping_add(inst.imm as i64 as u64));
            }
            0b1100111 => {
                // We know it's an Itype
                let inst = Itype::from(inst);

                match inst.funct3 {
                    0b000 => {
                        // JALR
                        let target = self.reg(inst.rs1).wrapping_add(inst.imm as i64 as u64);
                        self.set_reg(inst.rd, pc.wrapping_add(4));
                        return Ok(target);
                    }
                    _ => unimplemented!("Unexpected 0b1100111"),
                }
            }
            0b1100011 => {
                // We know it's an Btype
                let inst = Btype::from(inst);
                let rs1 = self.reg(inst.rs1);
                let rs2 = self.reg(inst.rs2);

                match inst.funct3 {
                    0b000 => {
                        // BEQ
                        if rs1 == rs2 {
                            return Ok(pc.wrapping_add(inst.imm as i64 as u64));
                        }
                    }
                    0b001 => {
                        // BNE
                        if rs1 != rs2 {
                            return Ok(pc.wrapping_add(inst.imm as i64 as u64));
                        }
                    }
                    0b100 => {
                        // BLT
                        if (rs1 as i64) < (rs2 as i64) {
                            return Ok(pc.wrapping_add(inst.imm as i64 as u64));
                        }
                    }
                    0b101 => {
                        // BGE
                        if (rs1 as i64) >= (rs2 as i64) {
                            return Ok(pc.wrapping_add(inst.imm as i64 as u64));
                        }
                    }
                    0b110 => {
                        // BLTU
                        if (rs1 as u64) < (rs2 as u64) {
                            return Ok(pc.wrapping_add(inst.imm as i64 as u64));
                        }
                    }
                    0b111 => {
                        // BGEU
                        if (rs1 as u64) >= (rs2 as u64) {
                            return Ok(pc.wrapping_add(inst.imm as i64 as u64));
                        }
                    }
                    _ => unimplemented!("Unexpected 0b1100011"),
                }
            }
            0b0000011 => {
                // We know it's an Itype
                let inst = Itype::from(inst);

                // Compute the address
                let addr =
                    VirtAddr(self.reg(inst.rs1).wrapping_add(inst.imm as i64 as u64) as usize);

                match inst.funct3 {
                    0b000 => {
                        // LB
                        let mut tmp = [0u8; 1];
                        self.memory.read_into(addr, &mut tmp)?;
                        self.set_reg(inst.rd, i8::from_le_bytes(tmp) as i64 as u64);
                    }
                    0b001 => {
                        // LH
                        let mut tmp = [0u8; 2];
                        self.memory.read_into(addr, &mut tmp)?;
                        self.set_reg(inst.rd, i16::from_le_bytes(tmp) as i64 as u64);
                    }
                    0b010 => {
                        // LW
                        let mut tmp = [0u8; 4];
                        self.memory.read_into(addr, &mut tmp)?;
                        self.set_reg(inst.rd, i32::from_le_bytes(tmp) as i64 as u64);
                    }
                    0b011 => {
                        // LD
                        let mut tmp = [0u8; 8];
                        self.memory.read_into(addr, &mut tmp)?;
                        self.set_reg(inst.rd, i64::from_le_bytes(tmp) as u64);
                    }
                    0b100 => {
                        // LBU
                        let mut tmp = [0u8; 1];
                        self.memory.read_into(addr, &mut tmp)?;
                        self.set_reg(inst.rd, u8::from_le_bytes(tmp) as u64);
                    }
                    0b101 => {
                        // LHU
                        let mut tmp = [0u8; 2];
                        self.memory.read_into(addr, &mut tmp)?;
                        self.set_reg(inst.rd, u16::from_le_bytes(tmp) as u64);
                    }
                    0b110 => {
                        // LWU
                        let mut tmp = [0u8; 4];
                        self.memory.read_into(addr, &mut tmp)?;
                        self.set_reg(inst.rd, u32::from_le_bytes(tmp) as u64);
                    }
                    0b111 => {
                        // LDU
                        let mut tmp = [0u8; 8];
                        self.memory.read_into(addr, &mut tmp)?;
                        self.set_reg(inst.rd, u64::from_le_bytes(tmp) as u64);
                    }
                    _ => unimplemented!("Unexpected 0b0000111"),
                }
            }
            0b0100011 => {
                // We know it's an Stype
                let inst = Stype::from(inst);

                // Compute the address
                let addr =
                    VirtAddr(self.reg(inst.rs1).wrapping_add(inst.imm as i64 as u64) as usize);

                match inst.funct3 {
                    0b000 => {
                        // SB
                        let val = self.reg(inst.rs2) as u8;
                        self.memory.write(addr, val)?;
                    }
                    0b001 => {
                        // SH
                        let val = self.reg(inst.rs2) as u16;
                        self.memory.write(addr, val)?;
                    }
                    0b010 => {
                        // SW
                        let val = self.reg(inst.rs2) as u32;
                        self.memory.write(addr, val)?;
                    }
                    0b011 => {
                        // SD
                        let val = self.reg(inst.rs2) as u64;
                        self.memory.write(addr, val)?;
                    }
                    _ => unimplemented!("Unexpected 0b0100111"),
                }
            }
            0b0010011 => {
                // We know it's an Itype
                let inst = Itype::from(inst);

                let rs1 = self.reg(inst.rs1);
                let imm = inst.imm as i64 as u64;

                match inst.funct3 {
                    0b000 => {
                        // ADDI
                        self.set_reg(inst.rd, rs1.wrapping_add(imm));
                    }
                    0b001 => {
                        // SLLI
                        let shamt = inst.imm & 0b111111;
                        self.set_reg(inst.rd, rs1 << shamt);
                    }
                    0b010 => {
                        // SLTI
                        if (rs1 as i64) < (imm as i64) {
                            self.set_reg(inst.rd, 1);
                        } else {
                            self.set_reg(inst.rd, 0);
                        }
                    }
                    0b011 => {
                        // SLTUI
                        if (rs1 as u64) < (imm as u64) {
                            self.set_reg(inst.rd, 1);
                        } else {
                            self.set_reg(inst.rd, 0);
                        }
                    }
                    0b100 => {
                        // XORI
                        self.set_reg(inst.rd, rs1 ^ imm);
                    }
                    0b101 => {
                        let mode = (inst.imm >> 6) & 0b111111;
                        match mode {
                            0b000000 => {
                                // SRLI
                                let shamt = inst.imm & 0b111111;
                                self.set_reg(inst.rd, rs1 >> shamt);
                            }
                            0b010000 => {
                                // SRAI
                                let shamt = inst.imm & 0b111111;
                                self.set_reg(inst.rd, ((rs1 as i64) >> shamt) as u64);
                            }
                            _ => unimplemented!("Unexpected 0b0010011"),
                        }
                    }
                    0b110 => {
                        // ORI
                        self.set_reg(inst.rd, rs1 | imm);
                    }
                    0b111 => {
                        // ANDI
                        self.set_reg(inst.rd, rs1 & imm);
                    }
                    _ => unimplemented!("Unexpected 0b0010011"),
                }
            }
            0b0110011 => {
                // We know it's an Rtype
                let inst = Rtype::from(inst);

                let rs1 = self.reg(inst.rs1);
                let rs2 = self.reg(inst.rs2);

                match (inst.funct7, inst.funct3) {
                    (0b0000000, 0b000) => {
                        // ADD
                        self.set_reg(inst.rd, rs1.wrapping_add(rs2));
                    }
                    (0b0100000, 0b000) => {
                        // SUB
                        self.set_reg(inst.rd, rs1.wrapping_sub(rs2));
                    }
                    (0b0000000, 0b001) => {
                        // SLL
                        let shamt = rs2 & 0b111111;
                        self.set_reg(inst.rd, rs1 << shamt);
                    }
                    (0b0000000, 0b010) => {
                        // SLT
                        if (rs1 as i64) < (rs2 as i64) {
                            self.set_reg(inst.rd, 1);
                        } else {
                            self.set_reg(inst.rd, 0);
                        }
                    }
                    (0b0000000, 0b011) => {
                        // SLTU
                        if (rs1 as u64) < (rs2 as u64) {
                            self.set_reg(inst.rd, 1);
                        } else {
                            self.set_reg(inst.rd, 0);
                        }
                    }
                    (0b0000000, 0b100) => {
                        // XOR
                        self.set_reg(inst.rd, rs1 ^ rs2);
                    }
                    (0b0000000, 0b101) => {
                        // SRL
                        let shamt = rs2 & 0b111111;
                        self.set_reg(inst.rd, rs1 >> shamt);
                    }
                    (0b0100000, 0b101) => {
                        // SRA
                        let shamt = rs2 & 0b111111;
                        self.set_reg(inst.rd, ((rs1 as i64) >> shamt) as u64);
                    }
                    (0b0000000, 0b110) => {
                        // OR
                        self.set_reg(inst.rd, rs1 | rs2);
                    }
                    (0b0000000, 0b111) => {
                        // AND
                        self.set_reg(inst.rd, rs1 & rs2);
                    }
                    _ => unreachable!(),
                }
            }
            0b0001111 => {
                let inst = Itype::from(inst);

                match inst.funct3 {
                    0b000 => {
                        // FENCE
                        panic!("FENCE");
                    }
                    _ => unreachable!(),
                }
            }
            0b1110011 => match inst {
                0b000000000000001110011 => {
                    // ECALL
                    return Err(EmuStop::Syscall);
                }
                0b100000000000001110011 => {
                    // EBREAK
                    panic!("EBREAK");
                }
                _ => unreachable!(),
            },
            0b0011011 => {
                // We know it's an Itype
                let inst = Itype::from(inst);

                let rs1 = self.reg(inst.rs1) as u32;
                let imm = inst.imm as u32;

                match inst.funct3 {
                    0b000 => {
                        // ADDI
                        self.set_reg(inst.rd, rs1.wrapping_add(imm) as i32 as i64 as u64);
                    }
                    0b001 => {
                        let mode = (inst.imm >> 5) & 0b1111111;
                        match mode {
                            0b000000 => {
                                // SLLIW
                                let shamt = inst.imm & 0b11111;
                                self.set_reg(inst.rd, (rs1 << shamt) as i32 as i64 as u64);
                            }
                            _ => unimplemented!("Unexpected 0b0011011"),
                        }
                    }
                    0b101 => {
                        let mode = (inst.imm >> 5) & 0b1111111;
                        match mode {
                            0b000000 => {
                                // SRLIW
                                let shamt = inst.imm & 0b11111;
                                self.set_reg(inst.rd, (rs1 >> shamt) as i32 as i64 as u64);
                            }
                            0b010000 => {
                                // SRAIW
                                let shamt = inst.imm & 0b11111;
                                self.set_reg(inst.rd, ((rs1 as i32) >> shamt) as i64 as u64);
                            }
                            _ => unimplemented!("Unexpected 0b0011011"),
                        }
                    }
                    _ => unimplemented!("Unexpected 0b0011011"),
                }
            }
            0b0111011 => {
                // We know it's an Rtype
                let inst = Rtype::from(inst);

                let rs1 = self.reg(inst.rs1) as u32;
                let rs2 = self.reg(inst.rs2) as u32;

                match (inst.funct7, inst.funct3) {
                    (0b0000000, 0b000) => {
                        // ADDW
                        self.set_reg(inst.rd, rs1.wrapping_add(rs2) as i32 as i64 as u64);
                    }
                    (0b0100000, 0b000) => {
                        // SUBW
                        self.set_reg(inst.rd, rs1.wrapping_sub(rs2) as i32 as i64 as u64);
                    }
                    (0b0000000, 0b001) => {
                        // SLLW
                        let shamt = rs2 & 0b111111;
                        self.set_reg(inst.rd, (rs1 << shamt) as i32 as i64 as u64);
                    }
                    (0b0000000, 0b101) => {
                        // SRLW
                        let shamt = rs2 & 0b111111;
                        self.set_reg(inst.rd, (rs1 >> shamt) as i32 as i64 as u64);
                    }
                    (0b0100000, 0b101) => {
                        // SRAW
                        let shamt = rs2 & 0b111111;
                        self.set_reg(inst.rd, ((rs1 as i32) >> shamt) as i64 as u64);
                    }
                    _ => unreachable!(),
                }
            }
            _ => unimplemented!("Unhandled opcode {:#09b}\n", opcode),
        }

        Ok(pc.wrapping_add(4))
    }
}

#[derive(Debug)]
struct Rtype {
    funct7: u32,
    rs2: Register,
    rs1: Register,
    funct3: u32,
    rd: Register,
}

impl From<u32> for Rtype {
    fn from(inst: u32) -> Self {
        Rtype {
            funct7: (inst >> 25) & 0b1111111,
            rs2: Register::from((inst >> 20) & 0b11111),
            rs1: Register::from((inst >> 15) & 0b11111),
            funct3: (inst >> 12) & 0b111,
            rd: Register::from((inst >> 7) & 0b11111),
        }
    }
}

#[derive(Debug)]
struct Stype {
    imm: i32,
    rs2: Register,
    rs1: Register,
    funct3: u32,
}

impl From<u32> for Stype {
    fn from(inst: u32) -> Self {
        let imm115 = (inst >> 25) & 0b1111111;
        let imm40 = (inst >> 7) & 0b11111;

        let imm = (imm115 << 5) | imm40;

        Stype {
            imm: ((imm as i32) << 20) >> 20,
            rs2: Register::from((inst >> 20) & 0b11111),
            rs1: Register::from((inst >> 15) & 0b11111),
            funct3: (inst >> 12) & 0b111,
        }
    }
}

#[derive(Debug)]
struct Btype {
    imm: i32,
    rs2: Register,
    rs1: Register,
    funct3: u32,
}

impl From<u32> for Btype {
    fn from(inst: u32) -> Self {
        let imm12 = (inst >> 31) & 1;
        let imm105 = (inst >> 25) & 0b111111;
        let imm41 = (inst >> 8) & 0b1111;
        let imm11 = (inst >> 7) & 1;

        let imm = (imm12 << 12) | (imm11 << 11) | (imm105 << 5) | (imm41 << 1);

        Btype {
            imm: ((imm as i32) << 19) >> 19,
            rs2: Register::from((inst >> 20) & 0b11111),
            rs1: Register::from((inst >> 15) & 0b11111),
            funct3: (inst >> 12) & 0b111,
        }
    }
}

#[derive(Debug)]
struct Itype {
    imm: i32,
    rs1: Register,
    funct3: u32,
    rd: Register,
}

impl From<u32> for Itype {
    fn from(inst: u32) -> Self {
        Itype {
            imm: (inst as i32) >> 20,
            rs1: Register::from((inst >> 15) & 0b11111),
            funct3: (inst >> 12) & 0b111,
            rd: Register::from((inst >> 7) & 0b11111),
        }
    }
}

#[derive(Debug)]
struct Jtype {
    imm: i32,
    rd: Register,
}

impl From<u32> for Jtype {
    fn from(inst: u32) -> Self {
        let imm20 = (inst >> 30) & 1;
        let imm101 = (inst >> 21) & 0b1111111111;
        let imm11 = (inst >> 20) & 1;
        let imm1912 = (inst >> 12) & 0b11111111;

        let imm = (imm20 << 20) | (imm1912 << 12) | (imm11 << 11) | (imm101 << 1);

        Jtype {
            imm: ((imm as i32) << 11) >> 11,
            rd: Register::from((inst >> 7) & 0b11111),
        }
    }
}

#[derive(Debug)]
struct Utype {
    imm: i32,
    rd: Register,
}

impl From<u32> for Utype {
    fn from(inst: u32) -> Self {
        Utype {
            imm: (inst & !0xfff) as i32,
            rd: Register::from((inst >> 7) & 0b11111),
        }
    }
}

/// RISC-V 64-bit registers
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Register {
    Zero = 0,
    Ra,
    Sp,
    Gp,
    Tp,
    T0,
    T1,
    T2,
    S0,
    S1,
    A0,
    A1,
    A2,
    A3,
    A4,
    A5,
    A6,
    A7,
    S2,
    S3,
    S4,
    S5,
    S6,
    S7,
    S8,
    S9,
    S10,
    S11,
    T3,
    T4,
    T5,
    T6,
    Pc,
}

impl From<u32> for Register {
    fn from(val: u32) -> Self {
        assert!(val < 32);
        unsafe { core::ptr::read_unaligned(&(val as usize) as *const usize as *const Register) }
    }
}

/// Reasons for emulation stopping
#[derive(Debug)]
pub enum EmuStop {
    /// Emulation stopped through normal exit
    Exit,

    /// Emulation stopped because a syscall was made
    Syscall,

    /// Emulation stopped because an overflow happened in syscall
    SyscallIntegerOverflow,

    /// An address calculation overflowed
    AddressOverflow,

    /// The address requested was not in bounds of the guest memory space
    AddressMiss(VirtAddr, usize),

    /// A read of `VirtAddr` failed due to invalid permissions
    ReadFault(VirtAddr),

    /// A write of `VirtAddr` failed due to invalid permissions
    WriteFault(VirtAddr),
}
