use crate::Result;

/// 紧凑变长指令编码：[Opcode:8][ArgFlag:8] + [Dst?:8][Src1?:8][Src2?:8][Imm?:1/2/4/8B]
pub mod arg_flag {
    pub const NONE: u8 = 0b0000_0000;
    pub const DST: u8 = 0b0000_0001;
    pub const S1: u8 = 0b0000_0010;
    pub const S2: u8 = 0b0000_0100;
    pub const IMM: u8 = 0b0000_1000;
    pub const IMM8: u8 = IMM | (0 << 4);
    pub const IMM16: u8 = IMM | (1 << 4);
    pub const IMM32: u8 = IMM | (2 << 4);
    pub const IMM64: u8 = IMM | (3 << 4);

    // Bit 6..7 : AUX 辅助位
    pub const AUX_UNSIGNED: u8 = 0b0000_0000;
    pub const AUX_SIGNED: u8 = 0b0100_0000; // CmpLt/CmpLe 有符号比较
    pub const AUX_BR_TRUE: u8 = 0b0000_0000; // Br/Select: 当 rf == true 时生效
    pub const AUX_BR_FALSE: u8 = 0b0100_0000; // Br/Select: 当 rf == false 时生效
    pub const AUX_REL: u8 = 0b1000_0000; // Jmp/Br/Call: 立即数解释为相对于当前指令的 IP 偏移
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Nop = 0x00,
    Halt = 0x01,
    Jmp = 0x02,
    Br = 0x03,
    Call = 0x04, // 可调用 VM 内部代码段地址或 Host 导入的 FFI 符号地址
    Ret = 0x05,
    Trap = 0x06,

    Mov = 0x10,
    Select = 0x11, // 三元选择(dst = cond ? s1 : s2)；若省略 S2 则等价于 CMov(if cond { dst = s1 })
    Push = 0x12,
    Pop = 0x13,

    Add = 0x20,
    Sub = 0x21,
    Mul = 0x22,
    UDiv = 0x23,
    SDiv = 0x24,
    URem = 0x25,
    SRem = 0x26,

    And = 0x30,
    Or = 0x31,
    Xor = 0x32,
    Shl = 0x33,
    LShr = 0x34,
    AShr = 0x35,
    Not = 0x36,
    Bswap = 0x37,

    CastU = 0x40,
    CastI = 0x41,
    Bitcast = 0x42,

    CmpEq = 0x50,
    CmpNe = 0x51,
    CmpLt = 0x52,
    CmpLe = 0x53,

    Load = 0x60,
    Store = 0x61,
    MemCpy = 0x62,
    MemSet = 0x63,
}

impl Opcode {
    #[inline(always)]
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x00 => Ok(Self::Nop),
            0x01 => Ok(Self::Halt),
            0x02 => Ok(Self::Jmp),
            0x03 => Ok(Self::Br),
            0x04 => Ok(Self::Call),
            0x05 => Ok(Self::Ret),
            0x06 => Ok(Self::Trap),
            0x10 => Ok(Self::Mov),
            0x11 => Ok(Self::Select),
            0x12 => Ok(Self::Push),
            0x13 => Ok(Self::Pop),
            0x20 => Ok(Self::Add),
            0x21 => Ok(Self::Sub),
            0x22 => Ok(Self::Mul),
            0x23 => Ok(Self::UDiv),
            0x24 => Ok(Self::SDiv),
            0x25 => Ok(Self::URem),
            0x26 => Ok(Self::SRem),
            0x30 => Ok(Self::And),
            0x31 => Ok(Self::Or),
            0x32 => Ok(Self::Xor),
            0x33 => Ok(Self::Shl),
            0x34 => Ok(Self::LShr),
            0x35 => Ok(Self::AShr),
            0x36 => Ok(Self::Not),
            0x37 => Ok(Self::Bswap),
            0x40 => Ok(Self::CastU),
            0x41 => Ok(Self::CastI),
            0x42 => Ok(Self::Bitcast),
            0x50 => Ok(Self::CmpEq),
            0x51 => Ok(Self::CmpNe),
            0x52 => Ok(Self::CmpLt),
            0x53 => Ok(Self::CmpLe),
            0x60 => Ok(Self::Load),
            0x61 => Ok(Self::Store),
            0x62 => Ok(Self::MemCpy),
            0x63 => Ok(Self::MemSet),
            _ => Err("Illegal opcode"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DecodedInst {
    pub op: Opcode,
    pub flag: u8,
    pub dst: u8,
    pub s1: u8,
    pub s2: u8,
    pub uimm: u64,
    pub simm: u64,
    pub imm_bytes: usize,
    pub len: usize,
}

impl DecodedInst {
    #[inline(always)]
    pub fn decode(code: &[u8]) -> Result<Self> {
        if code.len() < 2 {
            return Err("Instruction fetch truncated at header");
        }
        let op = Opcode::from_u8(code[0])?;
        let flag = code[1];
        let mut cursor = 2usize;

        let dst = if (flag & arg_flag::DST) != 0 {
            let r = *code.get(cursor).ok_or("Truncated DST operand")?;
            cursor += 1;
            r
        } else {
            0
        };
        let s1 = if (flag & arg_flag::S1) != 0 {
            let r = *code.get(cursor).ok_or("Truncated S1 operand")?;
            cursor += 1;
            r
        } else {
            0
        };
        let s2 = if (flag & arg_flag::S2) != 0 {
            let r = *code.get(cursor).ok_or("Truncated S2 operand")?;
            cursor += 1;
            r
        } else {
            0
        };

        let (uimm, simm, imm_bytes) = if (flag & arg_flag::IMM) != 0 {
            let size_code = (flag >> 4) & 0b11;
            let imm_len = 1usize << size_code;
            let bytes = code
                .get(cursor..cursor + imm_len)
                .ok_or("Truncated IMM operand")?;
            cursor += imm_len;
            match size_code {
                0 => {
                    let v = bytes[0];
                    (v as u64, (v as i8 as i64) as u64, 1)
                }
                1 => {
                    let v = u16::from_le_bytes([bytes[0], bytes[1]]);
                    (v as u64, (v as i16 as i64) as u64, 2)
                }
                2 => {
                    let v = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    (v as u64, (v as i32 as i64) as u64, 4)
                }
                _ => {
                    let v = u64::from_le_bytes(bytes.try_into().unwrap());
                    (v, v, 8)
                }
            }
        } else {
            (0, 0, 0)
        };

        Ok(Self {
            op,
            flag,
            dst,
            s1,
            s2,
            uimm,
            simm,
            imm_bytes,
            len: cursor,
        })
    }
}
/// 零分配字节码构造器（支持自动计算相对跳转偏移与前向跳转回填）
pub struct CodeBuf<'a> {
    pub buf: &'a mut [u8],
    pub pos: usize,
}

impl<'a> CodeBuf<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline(always)]
    pub const fn offset(&self) -> usize {
        self.pos
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    #[inline(always)]
    fn push_u8(&mut self, b: u8) -> Result<()> {
        *self.buf.get_mut(self.pos).ok_or("CodeBuf overflow")? = b;
        self.pos += 1;
        Ok(())
    }

    #[inline(always)]
    fn push_slice(&mut self, s: &[u8]) -> Result<()> {
        let end = self.pos.checked_add(s.len()).ok_or("CodeBuf overflow")?;
        self.buf.get_mut(self.pos..end).ok_or("CodeBuf overflow")?.copy_from_slice(s);
        self.pos = end;
        Ok(())
    }

    /// 通用指令编码入口：根据 flag 自动写入对应操作数与立即数
    pub fn emit(&mut self, op: Opcode, flag: u8, dst: u8, s1: u8, s2: u8, imm: u64) -> Result<usize> {
        let start = self.pos;
        self.push_u8(op as u8)?;
        self.push_u8(flag)?;
        if (flag & arg_flag::DST) != 0 {
            self.push_u8(dst)?;
        }
        if (flag & arg_flag::S1) != 0 {
            self.push_u8(s1)?;
        }
        if (flag & arg_flag::S2) != 0 {
            self.push_u8(s2)?;
        }
        if (flag & arg_flag::IMM) != 0 {
            match (flag >> 4) & 0b11 {
                0 => self.push_u8(imm as u8)?,
                1 => self.push_slice(&(imm as u16).to_le_bytes())?,
                2 => self.push_slice(&(imm as u32).to_le_bytes())?,
                _ => self.push_slice(&imm.to_le_bytes())?,
            }
        }
        Ok(start)
    }

    // ==================== 常用指令快捷构造方法 ====================

    pub fn op0(&mut self, op: Opcode) -> Result<usize> {
        self.emit(op, arg_flag::NONE, 0, 0, 0, 0)
    }

    pub fn dst_s1(&mut self, op: Opcode, dst: u8, s1: u8) -> Result<usize> {
        self.emit(op, arg_flag::DST | arg_flag::S1, dst, s1, 0, 0)
    }

    pub fn dst_imm8(&mut self, op: Opcode, dst: u8, imm: u8) -> Result<usize> {
        self.emit(op, arg_flag::DST | arg_flag::IMM8, dst, 0, 0, imm as u64)
    }

    pub fn dst_imm32(&mut self, op: Opcode, dst: u8, imm: u32) -> Result<usize> {
        self.emit(op, arg_flag::DST | arg_flag::IMM32, dst, 0, 0, imm as u64)
    }

    pub fn dst_imm64(&mut self, op: Opcode, dst: u8, imm: u64) -> Result<usize> {
        self.emit(op, arg_flag::DST | arg_flag::IMM64, dst, 0, 0, imm)
    }

    pub fn dst_s1_s2(&mut self, op: Opcode, dst: u8, s1: u8, s2: u8) -> Result<usize> {
        self.emit(op, arg_flag::DST | arg_flag::S1 | arg_flag::S2, dst, s1, s2, 0)
    }

    pub fn dst_s1_imm8(&mut self, op: Opcode, dst: u8, s1: u8, imm: u8) -> Result<usize> {
        self.emit(op, arg_flag::DST | arg_flag::S1 | arg_flag::IMM8, dst, s1, 0, imm as u64)
    }

    pub fn dst_s1_imm32(&mut self, op: Opcode, dst: u8, s1: u8, imm: u32) -> Result<usize> {
        self.emit(op, arg_flag::DST | arg_flag::S1 | arg_flag::IMM32, dst, s1, 0, imm as u64)
    }

    pub fn cmp_reg(&mut self, op: Opcode, signed: bool, s1: u8, s2: u8) -> Result<usize> {
        let aux = if signed { arg_flag::AUX_SIGNED } else { arg_flag::AUX_UNSIGNED };
        self.emit(op, aux | arg_flag::S1 | arg_flag::S2, 0, s1, s2, 0)
    }

    pub fn cmp_imm8(&mut self, op: Opcode, signed: bool, s1: u8, imm: u8) -> Result<usize> {
        let aux = if signed { arg_flag::AUX_SIGNED } else { arg_flag::AUX_UNSIGNED };
        self.emit(op, aux | arg_flag::S1 | arg_flag::IMM8, 0, s1, 0, imm as u64)
    }

    /// 向已确定的目标偏移发射相对跳转
    pub fn jmp_rel8_to(&mut self, target_offset: usize) -> Result<usize> {
        let rel = (target_offset as isize - self.pos as isize) as i8;
        self.emit(Opcode::Jmp, arg_flag::AUX_REL | arg_flag::IMM8, 0, 0, 0, rel as u8 as u64)
    }

    pub fn br_rel8_to(&mut self, cond: bool, target_offset: usize) -> Result<usize> {
        let aux = if cond { arg_flag::AUX_BR_TRUE } else { arg_flag::AUX_BR_FALSE };
        let rel = (target_offset as isize - self.pos as isize) as i8;
        self.emit(Opcode::Br, arg_flag::AUX_REL | aux | arg_flag::IMM8, 0, 0, 0, rel as u8 as u64)
    }

    /// 发射前向条件跳转占位指令，返回指令起始位置供后续 `patch_rel8` 回填
    pub fn br_rel8_fwd(&mut self, cond: bool) -> Result<usize> {
        let aux = if cond { arg_flag::AUX_BR_TRUE } else { arg_flag::AUX_BR_FALSE };
        self.emit(Opcode::Br, arg_flag::AUX_REL | aux | arg_flag::IMM8, 0, 0, 0, 0)
    }

    /// 将前向跳转指令的目标回填为当前 `pos`
    pub fn patch_rel8(&mut self, inst_offset: usize) -> Result<()> {
        let rel = (self.pos as isize)
            .checked_sub(inst_offset as isize)
            .and_then(|d| i8::try_from(d).ok())
            .ok_or("Relative jump offset out of i8 range")?;
        self.buf[inst_offset + 2] = rel as u8;
        Ok(())
    }
}