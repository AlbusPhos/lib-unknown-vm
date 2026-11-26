use crate::Result;

pub const TYPE_MASK: u8 = 0xF0;
pub const IDX_MASK: u8 = 0x0F;

pub const TAG_SPEC: u8 = 0x00;
pub const TAG_B: u8 = 0x10; // u8  / i8  / bool (ub[0..15])
pub const TAG_W: u8 = 0x20; // u16 / i16        (uw[0..15])
pub const TAG_D: u8 = 0x30; // u32 / i32        (ud[0..15])
pub const TAG_Q: u8 = 0x40; // u64 / i64 / ptr  (uq[0..15])
pub const TAG_FF: u8 = 0x50; // f32              (ff[0..15])
pub const TAG_FD: u8 = 0x60; // f64              (fd[0..15])

pub const NONE: u8 = 0x00;
pub const IP: u8 = 0x01;
pub const SP: u8 = 0x02;
pub const RF: u8 = 0x03;
pub const FP: u8 = 0x04; // 新增：栈帧指针寄存器

pub const fn ub(idx: u8) -> u8 {
    TAG_B | (idx & 0x0F)
}
pub const fn uw(idx: u8) -> u8 {
    TAG_W | (idx & 0x0F)
}
pub const fn ud(idx: u8) -> u8 {
    TAG_D | (idx & 0x0F)
}
pub const fn uq(idx: u8) -> u8 {
    TAG_Q | (idx & 0x0F)
}
pub const fn ff(idx: u8) -> u8 {
    TAG_FF | (idx & 0x0F)
}
pub const fn fd(idx: u8) -> u8 {
    TAG_FD | (idx & 0x0F)
}

#[derive(Clone, Debug, Default)]
pub struct Registers {
    pub uq: [u64; 16], // uq[0] 返回值, uq[1..=7] 函数传参
    pub ud: [u32; 16],
    pub uw: [u16; 16],
    pub ub: [u8; 16],
    pub ff: [f32; 16],
    pub fd: [f64; 16],
    pub ip: u64,  // 下一条指令虚拟地址
    pub sp: u64,  // 栈顶虚拟地址
    pub fp: u64,  // 栈帧基址虚拟地址
    pub rf: bool, // 标志寄存器
}

impl Registers {
    #[inline(always)]
    pub const fn is_float(reg_id: u8) -> bool {
        matches!(reg_id & TYPE_MASK, TAG_FF | TAG_FD)
    }

    /// 获取寄存器对应的内存读写字节宽度
    #[inline(always)]
    pub const fn byte_width(reg_id: u8) -> Result<usize> {
        match reg_id & TYPE_MASK {
            TAG_B => Ok(1),
            TAG_W => Ok(2),
            TAG_D | TAG_FF => Ok(4),
            TAG_Q | TAG_FD => Ok(8),
            TAG_SPEC => match reg_id {
                RF => Ok(1),
                IP | SP | FP => Ok(8),
                _ => Err("Invalid special register for byte width"),
            },
            _ => Err("Unknown register type tag"),
        }
    }

    /// 读取整数或特殊寄存器（零扩展为 u64）
    #[inline(always)]
    pub fn read_int(&self, reg_id: u8) -> Result<u64> {
        let idx = (reg_id & IDX_MASK) as usize;
        match reg_id & TYPE_MASK {
            TAG_SPEC => match reg_id {
                NONE => Ok(0),
                IP => Ok(self.ip),
                SP => Ok(self.sp),
                FP => Ok(self.fp),
                RF => Ok(self.rf as u64),
                _ => Err("Invalid special register read"),
            },
            TAG_B => Ok(self.ub[idx] as u64),
            TAG_W => Ok(self.uw[idx] as u64),
            TAG_D => Ok(self.ud[idx] as u64),
            TAG_Q => Ok(self.uq[idx]),
            _ => Err("Type mismatch: expected integer/special register"),
        }
    }

    /// 读取整数寄存器并按其自身位宽符号扩展为 i64
    #[inline(always)]
    pub fn read_sint(&self, reg_id: u8) -> Result<i64> {
        let idx = (reg_id & IDX_MASK) as usize;
        match reg_id & TYPE_MASK {
            TAG_B => Ok((self.ub[idx] as i8) as i64),
            TAG_W => Ok((self.uw[idx] as i16) as i64),
            TAG_D => Ok((self.ud[idx] as i32) as i64),
            TAG_Q | TAG_SPEC => Ok(self.read_int(reg_id)? as i64),
            _ => Err("Type mismatch: expected integer register for signed op"),
        }
    }

    /// 写入整数或特殊寄存器（自动按目标位宽截断，写入 NONE 静默丢弃）
    #[inline(always)]
    pub fn write_int(&mut self, reg_id: u8, val: u64) -> Result<()> {
        let idx = (reg_id & IDX_MASK) as usize;
        match reg_id & TYPE_MASK {
            TAG_SPEC => match reg_id {
                NONE => Ok(()),
                IP => {
                    self.ip = val;
                    Ok(())
                }
                SP => {
                    self.sp = val;
                    Ok(())
                }
                FP => {
                    self.fp = val;
                    Ok(())
                }
                RF => {
                    self.rf = val != 0;
                    Ok(())
                }
                _ => Err("Invalid special register write"),
            },
            TAG_B => {
                self.ub[idx] = val as u8;
                Ok(())
            }
            TAG_W => {
                self.uw[idx] = val as u16;
                Ok(())
            }
            TAG_D => {
                self.ud[idx] = val as u32;
                Ok(())
            }
            TAG_Q => {
                self.uq[idx] = val;
                Ok(())
            }
            _ => Err("Type mismatch: cannot write integer to float/invalid register"),
        }
    }

    /// 通用位模式读取（用于 Mov / Select / Bitcast / Push，支持整数和浮点）
    #[inline(always)]
    pub fn read_bits(&self, reg_id: u8) -> Result<u64> {
        let idx = (reg_id & IDX_MASK) as usize;
        match reg_id & TYPE_MASK {
            TAG_FF => Ok(self.ff[idx].to_bits() as u64),
            TAG_FD => Ok(self.fd[idx].to_bits()),
            _ => self.read_int(reg_id),
        }
    }

    /// 通用位模式写入（用于 Mov / Select / Bitcast / Pop，支持整数和浮点）
    #[inline(always)]
    pub fn write_bits(&mut self, reg_id: u8, bits: u64) -> Result<()> {
        let idx = (reg_id & IDX_MASK) as usize;
        match reg_id & TYPE_MASK {
            TAG_FF => {
                self.ff[idx] = f32::from_bits(bits as u32);
                Ok(())
            }
            TAG_FD => {
                self.fd[idx] = f64::from_bits(bits);
                Ok(())
            }
            _ => self.write_int(reg_id, bits),
        }
    }

    #[inline(always)]
    pub fn read_f32(&self, reg_id: u8) -> Result<f32> {
        if (reg_id & TYPE_MASK) != TAG_FF {
            return Err("Type mismatch: expected f32 (TAG_FF) register");
        }
        Ok(self.ff[(reg_id & IDX_MASK) as usize])
    }

    #[inline(always)]
    pub fn write_f32(&mut self, reg_id: u8, val: f32) -> Result<()> {
        if (reg_id & TYPE_MASK) != TAG_FF {
            return Err("Type mismatch: expected f32 (TAG_FF) register");
        }
        self.ff[(reg_id & IDX_MASK) as usize] = val;
        Ok(())
    }

    #[inline(always)]
    pub fn read_f64(&self, reg_id: u8) -> Result<f64> {
        if (reg_id & TYPE_MASK) != TAG_FD {
            return Err("Type mismatch: expected f64 (TAG_FD) register");
        }
        Ok(self.fd[(reg_id & IDX_MASK) as usize])
    }

    #[inline(always)]
    pub fn write_f64(&mut self, reg_id: u8, val: f64) -> Result<()> {
        if (reg_id & TYPE_MASK) != TAG_FD {
            return Err("Type mismatch: expected f64 (TAG_FD) register");
        }
        self.fd[(reg_id & IDX_MASK) as usize] = val;
        Ok(())
    }
}
