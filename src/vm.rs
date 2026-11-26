use crate::Result;
use crate::ffi::{Symbol, SymbolSource};
use crate::mem::{Memory, OFFSET_MASK, SEG_SHIFT, make_addr};
use crate::opcode::{DecodedInst, Opcode, arg_flag};
use crate::reg::{self, Registers};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmStatus {
    Running,
    Halted,
    Trapped,
}

pub struct Vm<'a, const N: usize = 4> {
    pub regs: Registers,
    pub mem: Memory<'a, N>,
    pub status: VmStatus,
}

impl<'a, const N: usize> Vm<'a, N> {
    pub fn new(mem: Memory<'a, N>, entry_offset: usize) -> Self {
        let mut regs = Registers::default();
        // 默认栈顶指向第 1 段 (mem[0]) 末尾（满递减栈）
        let stack_len = mem.mem[0].area.as_slice().len();
        regs.sp = make_addr(0, stack_len);
        regs.fp = regs.sp;
        // 默认 IP 指向第 N-1 段 (mem[N-2] 代码段) 的入口偏移
        regs.ip = make_addr(N - 2, entry_offset);

        Self {
            regs,
            mem,
            status: VmStatus::Running,
        }
    }

    /// 持续运行直到遇到 Halt / Trap 或发生错误
    pub fn run(&mut self) -> Result<VmStatus> {
        self.status = VmStatus::Running;
        while self.status == VmStatus::Running {
            self.step()?;
        }
        Ok(self.status)
    }

    /// 宿主机按名称查找并调用 FFI 段（第 N 段）中的导出函数
    /// - 参数按约定依次写入 `uq[1..=7]`
    /// - 返回值从 `uq[0]` 读取
    pub fn call_export(&mut self, name: &str, args: &[u64]) -> Result<u64> {
        if args.len() > 7 {
            return Err("Too many arguments: ABI supports up to 7 args in uq[1..=7]");
        }
        for (i, &val) in args.iter().enumerate() {
            self.regs.write_int(reg::uq((i + 1) as u8), val)?;
        }

        let ffi_slice = self.mem.mem[N - 1].area.as_slice();
        let (_, sym) = Symbol::<N>::find_in_bytes(ffi_slice, name)?;

        match sym.source {
            SymbolSource::Host(host_fn) => {
                host_fn(&mut self.regs, &mut self.mem)?;
            }
            SymbolSource::Vm(vm_addr) => {
                self.push_u64(u64::MAX >> 8)?;
                self.regs.ip = vm_addr;
                self.run()?;
            }
        }
        self.regs.read_int(reg::uq(0))
    }

    /// 单步执行一条指令
    #[inline]
    pub fn step(&mut self) -> Result<VmStatus> {
        let code = self.mem.fetch_code(self.regs.ip)?;
        let inst = DecodedInst::decode(code)?;
        let cur_ip = self.regs.ip;
        let next_ip = cur_ip.wrapping_add(inst.len as u64);
        self.regs.ip = next_ip;

        match inst.op {
            Opcode::Nop => {}
            Opcode::Halt => {
                self.status = VmStatus::Halted;
            }
            Opcode::Trap => {
                self.status = VmStatus::Trapped;
            }

            // ==================== 控制流指令 ====================
            Opcode::Jmp => {
                self.regs.ip = self.resolve_jump_target(&inst, cur_ip)?;
            }
            Opcode::Br => {
                let want_rf = (inst.flag & arg_flag::AUX_BR_FALSE) == 0;
                if self.regs.rf == want_rf {
                    self.regs.ip = self.resolve_jump_target(&inst, cur_ip)?;
                }
            }
            Opcode::Call => {
                let target = self.resolve_jump_target(&inst, cur_ip)?;
                let seg_id = (target >> SEG_SHIFT) as usize;

                if seg_id == N {
                    // 目标位于第 N 段（FFI 符号段）：解析 Symbol
                    let sym_bytes = self.mem.read_bytes(target, Symbol::<N>::SIZE)?;
                    let sym = Symbol::<N>::from_bytes(sym_bytes)?;
                    match sym.source {
                        SymbolSource::Host(host_fn) => {
                            host_fn(&mut self.regs, &mut self.mem)?;
                        }
                        SymbolSource::Vm(vm_addr) => {
                            self.push_u64(next_ip)?;
                            self.regs.ip = vm_addr;
                        }
                    }
                } else {
                    // 普通 VM 内部函数调用：返回地址压栈并跳转
                    self.push_u64(next_ip)?;
                    self.regs.ip = target;
                }
            }
            Opcode::Ret => {
                let ret_addr = self.pop_u64()?;
                if ret_addr >> 56 == 0 {
                    if ret_addr == u64::MAX >> 8 {
                        self.status = VmStatus::Halted;
                    } else {
                        self.status = VmStatus::Trapped;
                    }
                } else {
                    self.regs.ip = ret_addr;
                }
            }

            // ==================== 数据移动与栈指令 ====================
            Opcode::Mov => {
                let val = self.eval_unary_bits(&inst)?;
                self.regs.write_bits(inst.dst, val)?;
            }
            Opcode::Select => {
                let want_rf = (inst.flag & arg_flag::AUX_BR_FALSE) == 0;
                if self.regs.rf == want_rf {
                    let v1 = self.eval_unary_bits(&inst)?;
                    self.regs.write_bits(inst.dst, v1)?;
                } else if (inst.flag & arg_flag::S2) != 0 {
                    let v2 = self.regs.read_bits(inst.s2)?;
                    self.regs.write_bits(inst.dst, v2)?;
                } else if (inst.flag & arg_flag::IMM) != 0 && (inst.flag & arg_flag::S1) != 0 {
                    self.regs.write_bits(inst.dst, inst.uimm)?;
                }
                // 若条件不满足且未提供第 2 备选源，则保持 dst 不变（等价于 CMov）
            }
            Opcode::Push => {
                let src_reg = if (inst.flag & arg_flag::S1) != 0 {
                    inst.s1
                } else {
                    inst.dst
                };
                if src_reg != reg::NONE {
                    let width = Registers::byte_width(src_reg)? as u64;
                    let new_sp = self.regs.sp.checked_sub(width).ok_or("Stack overflow")?;
                    self.mem.store_reg(new_sp, src_reg, &self.regs)?;
                    self.regs.sp = new_sp;
                } else if (inst.flag & arg_flag::IMM) != 0 {
                    self.push_u64(inst.uimm)?;
                } else {
                    return Err("Push requires register or immediate operand");
                }
            }
            Opcode::Pop => {
                let width = Registers::byte_width(inst.dst)? as u64;
                self.mem.load_reg(self.regs.sp, inst.dst, &mut self.regs)?;
                self.regs.sp = self.regs.sp.checked_add(width).ok_or("Stack underflow")?;
            }

            // ==================== 算术运算指令 ====================
            Opcode::Add
            | Opcode::Sub
            | Opcode::Mul
            | Opcode::UDiv
            | Opcode::SDiv
            | Opcode::URem
            | Opcode::SRem => {
                self.exec_arith(&inst)?;
            }

            // ==================== 位运算指令 ====================
            Opcode::And => {
                let (a, b) = self.eval_bin_int(&inst)?;
                self.regs.write_int(inst.dst, a & b)?;
            }
            Opcode::Or => {
                let (a, b) = self.eval_bin_int(&inst)?;
                self.regs.write_int(inst.dst, a | b)?;
            }
            Opcode::Xor => {
                let (a, b) = self.eval_bin_int(&inst)?;
                self.regs.write_int(inst.dst, a ^ b)?;
            }
            Opcode::Shl => {
                let (a, b) = self.eval_bin_int(&inst)?;
                self.regs.write_int(inst.dst, a.wrapping_shl(b as u32))?;
            }
            Opcode::LShr => {
                let (a, b) = self.eval_bin_int(&inst)?;
                self.regs.write_int(inst.dst, a.wrapping_shr(b as u32))?;
            }
            Opcode::AShr => {
                let a = self.regs.read_sint(inst.s1)?;
                let b = self.eval_rhs_int(&inst)?;
                self.regs
                    .write_int(inst.dst, a.wrapping_shr(b as u32) as u64)?;
            }
            Opcode::Not => {
                let a = self.eval_unary_bits(&inst)?;
                self.regs.write_int(inst.dst, !a)?;
            }
            Opcode::Bswap => {
                let a = self.eval_unary_bits(&inst)?;
                let swapped = match Registers::byte_width(inst.dst)? {
                    1 => a,
                    2 => (a as u16).swap_bytes() as u64,
                    4 => (a as u32).swap_bytes() as u64,
                    8 => a.swap_bytes(),
                    _ => return Err("Invalid register width for Bswap"),
                };
                self.regs.write_int(inst.dst, swapped)?;
            }

            // ==================== 类型转换指令 ====================
            Opcode::CastU | Opcode::CastI | Opcode::Bitcast => {
                self.exec_cast(&inst)?;
            }

            // ==================== 比较指令 ====================
            Opcode::CmpEq | Opcode::CmpNe | Opcode::CmpLt | Opcode::CmpLe => {
                self.exec_cmp(&inst)?;
            }

            // ==================== 内存指令 ====================
            Opcode::Load => {
                let addr = self.eval_mem_addr(&inst)?;
                self.mem.load_reg(addr, inst.dst, &mut self.regs)?;
            }
            Opcode::Store => {
                let addr = self.eval_mem_addr(&inst)?;
                self.mem.store_reg(addr, inst.dst, &self.regs)?;
            }
            Opcode::MemCpy => {
                let dst_addr = self.regs.read_int(inst.dst)?;
                let src_addr = self.regs.read_int(inst.s1)?;
                let len = self.eval_rhs_int(&inst)? as usize;
                // 逐字节拷贝以支持段内重叠或跨段拷贝
                for i in 0..len {
                    let b = self.mem.read_bytes(src_addr + i as u64, 1)?[0];
                    self.mem.write_bytes(dst_addr + i as u64, 1)?[0] = b;
                }
            }
            Opcode::MemSet => {
                let dst_addr = self.regs.read_int(inst.dst)?;
                let val = if (inst.flag & arg_flag::S1) != 0 {
                    self.regs.read_int(inst.s1)? as u8
                } else {
                    inst.uimm as u8
                };
                let len = if (inst.flag & arg_flag::S2) != 0 {
                    self.regs.read_int(inst.s2)? as usize
                } else {
                    inst.uimm as usize
                };
                let slice = self.mem.write_bytes(dst_addr, len)?;
                slice.fill(val);
            }
        }

        Ok(self.status)
    }

    // ==================== 内部辅助函数 ====================

    #[inline(always)]
    fn push_u64(&mut self, val: u64) -> Result<()> {
        let new_sp = self.regs.sp.checked_sub(8).ok_or("Stack overflow")?;
        self.mem
            .write_bytes(new_sp, 8)?
            .copy_from_slice(&val.to_le_bytes());
        self.regs.sp = new_sp;
        Ok(())
    }

    #[inline(always)]
    fn pop_u64(&mut self) -> Result<u64> {
        let bytes = self.mem.read_bytes(self.regs.sp, 8)?;
        let val = u64::from_le_bytes(bytes.try_into().unwrap());
        self.regs.sp = self.regs.sp.checked_add(8).ok_or("Stack underflow")?;
        Ok(val)
    }

    /// 计算有效内存地址：addr = s1 + s2 + simm (未设置的寄存器自动读为 0)
    #[inline(always)]
    fn eval_mem_addr(&self, inst: &DecodedInst) -> Result<u64> {
        let base = self.regs.read_int(inst.s1)?;
        let index = self.regs.read_int(inst.s2)?;
        Ok(base.wrapping_add(index).wrapping_add(inst.simm))
    }

    /// 计算跳转/调用目标地址：
    /// - 若带 AUX_REL：cur_ip + simm
    /// - 否则：s1 + s2 + uimm（若结果不含段号，自动继承当前代码段号，方便短立即数跳转）
    #[inline(always)]
    fn resolve_jump_target(&self, inst: &DecodedInst, cur_ip: u64) -> Result<u64> {
        if (inst.flag & arg_flag::AUX_REL) != 0 {
            return Ok(cur_ip.wrapping_add(inst.simm));
        }
        let target = self
            .regs
            .read_int(inst.s1)?
            .wrapping_add(self.regs.read_int(inst.s2)?)
            .wrapping_add(inst.uimm);
        if (target >> SEG_SHIFT) == 0 {
            Ok((cur_ip & !OFFSET_MASK) | (target & OFFSET_MASK))
        } else {
            Ok(target)
        }
    }

    #[inline(always)]
    fn eval_unary_bits(&self, inst: &DecodedInst) -> Result<u64> {
        if (inst.flag & arg_flag::S1) != 0 {
            self.regs.read_bits(inst.s1)
        } else {
            Ok(inst.uimm)
        }
    }

    #[inline(always)]
    fn eval_rhs_int(&self, inst: &DecodedInst) -> Result<u64> {
        if (inst.flag & arg_flag::S2) != 0 {
            self.regs.read_int(inst.s2)
        } else {
            Ok(inst.uimm)
        }
    }

    #[inline(always)]
    fn eval_bin_int(&self, inst: &DecodedInst) -> Result<(u64, u64)> {
        Ok((self.regs.read_int(inst.s1)?, self.eval_rhs_int(inst)?))
    }

    fn exec_arith(&mut self, inst: &DecodedInst) -> Result<()> {
        match inst.dst & reg::TYPE_MASK {
            reg::TAG_FF => {
                let a = self.regs.read_f32(inst.s1)?;
                let b = if (inst.flag & arg_flag::S2) != 0 {
                    self.regs.read_f32(inst.s2)?
                } else {
                    f32::from_bits(inst.uimm as u32)
                };
                let res = match inst.op {
                    Opcode::Add => a + b,
                    Opcode::Sub => a - b,
                    Opcode::Mul => a * b,
                    Opcode::UDiv | Opcode::SDiv => a / b,
                    Opcode::URem | Opcode::SRem => a % b,
                    _ => unreachable!(),
                };
                self.regs.write_f32(inst.dst, res)
            }
            reg::TAG_FD => {
                let a = self.regs.read_f64(inst.s1)?;
                let b = if (inst.flag & arg_flag::S2) != 0 {
                    self.regs.read_f64(inst.s2)?
                } else {
                    f64::from_bits(inst.uimm)
                };
                let res = match inst.op {
                    Opcode::Add => a + b,
                    Opcode::Sub => a - b,
                    Opcode::Mul => a * b,
                    Opcode::UDiv | Opcode::SDiv => a / b,
                    Opcode::URem | Opcode::SRem => a % b,
                    _ => unreachable!(),
                };
                self.regs.write_f64(inst.dst, res)
            }
            _ => match inst.op {
                Opcode::Add => {
                    let (a, b) = self.eval_bin_int(inst)?;
                    self.regs.write_int(inst.dst, a.wrapping_add(b))
                }
                Opcode::Sub => {
                    let (a, b) = self.eval_bin_int(inst)?;
                    self.regs.write_int(inst.dst, a.wrapping_sub(b))
                }
                Opcode::Mul => {
                    let (a, b) = self.eval_bin_int(inst)?;
                    self.regs.write_int(inst.dst, a.wrapping_mul(b))
                }
                Opcode::UDiv => {
                    let (a, b) = self.eval_bin_int(inst)?;
                    if b == 0 {
                        return Err("Division by zero");
                    }
                    self.regs.write_int(inst.dst, a / b)
                }
                Opcode::URem => {
                    let (a, b) = self.eval_bin_int(inst)?;
                    if b == 0 {
                        return Err("Remainder by zero");
                    }
                    self.regs.write_int(inst.dst, a % b)
                }
                Opcode::SDiv => {
                    let a = self.regs.read_sint(inst.s1)?;
                    let b = if (inst.flag & arg_flag::S2) != 0 {
                        self.regs.read_sint(inst.s2)?
                    } else {
                        inst.simm as i64
                    };
                    if b == 0 {
                        return Err("Division by zero");
                    }
                    self.regs.write_int(inst.dst, a.wrapping_div(b) as u64)
                }
                Opcode::SRem => {
                    let a = self.regs.read_sint(inst.s1)?;
                    let b = if (inst.flag & arg_flag::S2) != 0 {
                        self.regs.read_sint(inst.s2)?
                    } else {
                        inst.simm as i64
                    };
                    if b == 0 {
                        return Err("Remainder by zero");
                    }
                    self.regs.write_int(inst.dst, a.wrapping_rem(b) as u64)
                }
                _ => unreachable!(),
            },
        }
    }

    fn exec_cast(&mut self, inst: &DecodedInst) -> Result<()> {
        if inst.op == Opcode::Bitcast {
            let bits = self.eval_unary_bits(inst)?;
            return self.regs.write_bits(inst.dst, bits);
        }

        let src_tag = inst.s1 & reg::TYPE_MASK;
        let dst_tag = inst.dst & reg::TYPE_MASK;
        let signed = inst.op == Opcode::CastI;

        match (src_tag, dst_tag) {
            (reg::TAG_FF, reg::TAG_FD) => self
                .regs
                .write_f64(inst.dst, self.regs.read_f32(inst.s1)? as f64),
            (reg::TAG_FD, reg::TAG_FF) => self
                .regs
                .write_f32(inst.dst, self.regs.read_f64(inst.s1)? as f32),
            (reg::TAG_FF, _) => {
                let f = self.regs.read_f32(inst.s1)?;
                let v = if signed { (f as i64) as u64 } else { f as u64 };
                self.regs.write_int(inst.dst, v)
            }
            (reg::TAG_FD, _) => {
                let f = self.regs.read_f64(inst.s1)?;
                let v = if signed { (f as i64) as u64 } else { f as u64 };
                self.regs.write_int(inst.dst, v)
            }
            (_, reg::TAG_FF) => {
                let f = if signed {
                    self.regs.read_sint(inst.s1)? as f32
                } else {
                    self.regs.read_int(inst.s1)? as f32
                };
                self.regs.write_f32(inst.dst, f)
            }
            (_, reg::TAG_FD) => {
                let f = if signed {
                    self.regs.read_sint(inst.s1)? as f64
                } else {
                    self.regs.read_int(inst.s1)? as f64
                };
                self.regs.write_f64(inst.dst, f)
            }
            _ => {
                let v = if signed {
                    self.regs.read_sint(inst.s1)? as u64
                } else {
                    self.regs.read_int(inst.s1)?
                };
                self.regs.write_int(inst.dst, v)
            }
        }
    }

    fn exec_cmp(&mut self, inst: &DecodedInst) -> Result<()> {
        let res = match inst.s1 & reg::TYPE_MASK {
            reg::TAG_FF => {
                let a = self.regs.read_f32(inst.s1)?;
                let b = if (inst.flag & arg_flag::S2) != 0 {
                    self.regs.read_f32(inst.s2)?
                } else {
                    f32::from_bits(inst.uimm as u32)
                };
                match inst.op {
                    Opcode::CmpEq => a == b,
                    Opcode::CmpNe => a != b,
                    Opcode::CmpLt => a < b,
                    Opcode::CmpLe => a <= b,
                    _ => unreachable!(),
                }
            }
            reg::TAG_FD => {
                let a = self.regs.read_f64(inst.s1)?;
                let b = if (inst.flag & arg_flag::S2) != 0 {
                    self.regs.read_f64(inst.s2)?
                } else {
                    f64::from_bits(inst.uimm)
                };
                match inst.op {
                    Opcode::CmpEq => a == b,
                    Opcode::CmpNe => a != b,
                    Opcode::CmpLt => a < b,
                    Opcode::CmpLe => a <= b,
                    _ => unreachable!(),
                }
            }
            _ => {
                if (inst.flag & arg_flag::AUX_SIGNED) != 0 {
                    let a = self.regs.read_sint(inst.s1)?;
                    let b = if (inst.flag & arg_flag::S2) != 0 {
                        self.regs.read_sint(inst.s2)?
                    } else {
                        inst.simm as i64
                    };
                    match inst.op {
                        Opcode::CmpEq => a == b,
                        Opcode::CmpNe => a != b,
                        Opcode::CmpLt => a < b,
                        Opcode::CmpLe => a <= b,
                        _ => unreachable!(),
                    }
                } else {
                    let (a, b) = self.eval_bin_int(inst)?;
                    match inst.op {
                        Opcode::CmpEq => a == b,
                        Opcode::CmpNe => a != b,
                        Opcode::CmpLt => a < b,
                        Opcode::CmpLe => a <= b,
                        _ => unreachable!(),
                    }
                }
            }
        };

        // 比较结果总是更新 rf，同时若指定了 DST 寄存器（如 ub[0]），也一并写入
        self.regs.rf = res;
        if (inst.flag & arg_flag::DST) != 0 {
            self.regs.write_int(inst.dst, res as u64)?;
        }
        Ok(())
    }
}
