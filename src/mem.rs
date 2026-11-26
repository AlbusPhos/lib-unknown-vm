use crate::Result;
use crate::reg::{self, Registers};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

pub const SEG_SHIFT: u64 = 56;
pub const OFFSET_MASK: u64 = (1u64 << SEG_SHIFT) - 1;

#[inline(always)]
pub const fn make_addr(seg_index: usize, offset: usize) -> u64 {
    (((seg_index + 1) as u64) << SEG_SHIFT) | ((offset as u64) & OFFSET_MASK)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permission(pub u8);

impl Permission {
    pub const NONE: Self = Self(0b000);
    pub const R: Self = Self(0b001);
    pub const W: Self = Self(0b010);
    pub const X: Self = Self(0b100);
    pub const RW: Self = Self(0b011);
    pub const RX: Self = Self(0b101);
    pub const RWX: Self = Self(0b111);

    #[inline(always)]
    pub const fn can_read(self) -> bool {
        (self.0 & Self::R.0) != 0
    }
    #[inline(always)]
    pub const fn can_write(self) -> bool {
        (self.0 & Self::W.0) != 0
    }
    #[inline(always)]
    pub const fn can_exec(self) -> bool {
        (self.0 & Self::X.0) != 0
    }
}

pub enum Area<'a> {
    Slice(&'a [u8]),
    SliceMut(&'a mut [u8]),
    #[cfg(feature = "alloc")]
    Owned(Vec<u8>),
}

impl<'a> Area<'a> {
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Slice(s) => s,
            Self::SliceMut(s) => s,
            #[cfg(feature = "alloc")]
            Self::Owned(v) => v.as_slice(),
        }
    }

    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> Result<&mut [u8]> {
        match self {
            Self::Slice(_) => Err("Cannot write to immutable Area::Slice"),
            Self::SliceMut(s) => Ok(s),
            #[cfg(feature = "alloc")]
            Self::Owned(v) => Ok(v.as_mut_slice()),
        }
    }
}

pub struct Segment<'a> {
    pub name: &'a str,
    pub area: Area<'a>,
    pub permission: Permission,
}

impl<'a> Segment<'a> {
    #[inline(always)]
    pub fn resolve_addr(segs: &[Self], addr: u64) -> Result<(usize, usize)> {
        let seg_id = (addr >> SEG_SHIFT) as usize;
        if seg_id == 0 || seg_id > segs.len() {
            return Err("Segmentation fault: null or invalid segment index");
        }
        Ok((seg_id - 1, (addr & OFFSET_MASK) as usize))
    }

    #[inline(always)]
    pub fn get_slice_from(segs: &[Self], addr: u64, len: usize) -> Result<&[u8]> {
        let (seg_idx, off) = Self::resolve_addr(segs, addr)?;
        let seg = &segs[seg_idx];
        if !seg.permission.can_read() {
            return Err("Memory access violation: read permission denied");
        }
        let end = off
            .checked_add(len)
            .ok_or("Memory access offset overflow")?;
        seg.area
            .as_slice()
            .get(off..end)
            .ok_or("Memory access out of bounds")
    }

    #[inline(always)]
    pub fn get_mut_slice_from(segs: &mut [Self], addr: u64, len: usize) -> Result<&mut [u8]> {
        let (seg_idx, off) = Self::resolve_addr(segs, addr)?;
        let seg = &mut segs[seg_idx];
        if !seg.permission.can_write() {
            return Err("Memory write violation: segment is read-only");
        }
        let end = off
            .checked_add(len)
            .ok_or("Memory access offset overflow")?;
        seg.area
            .as_mut_slice()?
            .get_mut(off..end)
            .ok_or("Memory write out of bounds")
    }
}

/// 统一 64 位虚拟地址格式：[SegID: 8 bits][Offset: 56 bits]
/// - 0       : NULL 空指针拦截区
/// - 1       : 栈 (mem[0])
/// - 2..=N-2 : 常规内存段 (mem[1..=N-3])
/// - N-1     : 虚拟机字节码段 (mem[N-2])
/// - N       : C/Rust FFI 导入导出段 (mem[N-1])
pub struct Memory<'a, const N: usize = 4> {
    pub mem: [Segment<'a>; N],
}

impl<'a, const N: usize> Memory<'a, N> {
    #[inline(always)]
    pub fn read_bytes(&self, addr: u64, len: usize) -> Result<&[u8]> {
        Segment::get_slice_from(&self.mem, addr, len)
    }

    #[inline(always)]
    pub fn write_bytes(&mut self, addr: u64, len: usize) -> Result<&mut [u8]> {
        Segment::get_mut_slice_from(&mut self.mem, addr, len)
    }

    /// 从虚拟地址获取待执行的指令切片
    #[inline(always)]
    pub fn fetch_code(&self, ip: u64) -> Result<&[u8]> {
        let (seg_idx, off) = Segment::resolve_addr(&self.mem, ip)?;
        let seg = &self.mem[seg_idx];
        if !seg.permission.can_exec() {
            return Err("Memory access violation: execute permission denied");
        }
        seg.area
            .as_slice()
            .get(off..)
            .ok_or("Instruction pointer out of bounds")
    }

    /// 按目标寄存器位宽从虚拟地址加载数据
    #[inline(always)]
    pub fn load_reg(&self, addr: u64, dst_reg: u8, regs: &mut Registers) -> Result<()> {
        let width = Registers::byte_width(dst_reg)?;
        let s = self.read_bytes(addr, width)?;
        match dst_reg & reg::TYPE_MASK {
            reg::TAG_B => regs.write_int(dst_reg, s[0] as u64),
            reg::TAG_W => regs.write_int(dst_reg, u16::from_le_bytes([s[0], s[1]]) as u64),
            reg::TAG_D => {
                regs.write_int(dst_reg, u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as u64)
            }
            reg::TAG_Q => regs.write_int(dst_reg, u64::from_le_bytes(s.try_into().unwrap())),
            reg::TAG_FF => regs.write_f32(dst_reg, f32::from_le_bytes([s[0], s[1], s[2], s[3]])),
            reg::TAG_FD => regs.write_f64(dst_reg, f64::from_le_bytes(s.try_into().unwrap())),
            reg::TAG_SPEC => match width {
                1 => regs.write_int(dst_reg, s[0] as u64),
                8 => regs.write_int(dst_reg, u64::from_le_bytes(s.try_into().unwrap())),
                _ => Err("Invalid special register load"),
            },
            _ => Err("Invalid register for Load"),
        }
    }

    /// 按源寄存器位宽向虚拟地址写入数据
    #[inline(always)]
    pub fn store_reg(&mut self, addr: u64, src_reg: u8, regs: &Registers) -> Result<()> {
        let width = Registers::byte_width(src_reg)?;
        match src_reg & reg::TYPE_MASK {
            reg::TAG_B => {
                let val = regs.read_int(src_reg)? as u8;
                self.write_bytes(addr, 1)?[0] = val;
            }
            reg::TAG_W => {
                let val = (regs.read_int(src_reg)? as u16).to_le_bytes();
                self.write_bytes(addr, 2)?.copy_from_slice(&val);
            }
            reg::TAG_D => {
                let val = (regs.read_int(src_reg)? as u32).to_le_bytes();
                self.write_bytes(addr, 4)?.copy_from_slice(&val);
            }
            reg::TAG_Q => {
                let val = regs.read_int(src_reg)?.to_le_bytes();
                self.write_bytes(addr, 8)?.copy_from_slice(&val);
            }
            reg::TAG_FF => {
                let val = regs.read_f32(src_reg)?.to_le_bytes();
                self.write_bytes(addr, 4)?.copy_from_slice(&val);
            }
            reg::TAG_FD => {
                let val = regs.read_f64(src_reg)?.to_le_bytes();
                self.write_bytes(addr, 8)?.copy_from_slice(&val);
            }
            reg::TAG_SPEC => match width {
                1 => {
                    let val = regs.read_int(src_reg)? as u8;
                    self.write_bytes(addr, 1)?[0] = val;
                }
                8 => {
                    let val = regs.read_int(src_reg)?.to_le_bytes();
                    self.write_bytes(addr, 8)?.copy_from_slice(&val);
                }
                _ => return Err("Invalid special register store"),
            },
            _ => return Err("Invalid register for Store"),
        }
        Ok(())
    }
}
