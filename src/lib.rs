#![no_std]
#[cfg(feature = "alloc")]
extern crate alloc;

pub mod ffi;
pub mod mem;
pub mod opcode;
pub mod reg;
pub mod vm;

pub type Result<T> = core::result::Result<T, &'static str>;

#[cfg(test)]
mod tests {
    use super::*;
    use ffi::{Symbol, SymbolSource};
    use mem::{Area, Memory, Permission, Segment, make_addr};
    use opcode::{Opcode, arg_flag};
    use reg::{self, Registers};
    use vm::{Vm, VmStatus};

    // 宿主机函数示例：将 uq[1] + uq[2] 的结果翻倍后放入 uq[0]
    fn host_double_add(regs: &mut Registers, _mem: &mut Memory<'_, 4>) -> Result<()> {
        let a = regs.read_int(reg::uq(1))?;
        let b = regs.read_int(reg::uq(2))?;
        regs.write_int(reg::uq(0), (a + b) * 2)?;
        Ok(())
    }

    #[test]
    fn test_vm_and_ffi_call() {
        let mut stack = [0u8; 256];
        let mut data = [0u8; 64];

        // 构造 FFI 段中的第 0 个符号
        let sym = Symbol::<4> {
            name: *b"host_double_add\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            source: SymbolSource::Host(host_double_add),
        };
        let ffi_bytes = sym.to_ne_bytes();
        let ffi_addr = make_addr(3, 0); // 第 4 段 (index = 3) 偏移 0

        // 构造字节码：
        // 1. Mov uq[1], 10
        // 2. Mov uq[2], 20
        // 3. Call ffi_addr
        // 4. Halt
        let mut code = [0u8; 64];
        let mut c = 0;
        // Mov uq[1], 10
        code[c..c + 4].copy_from_slice(&[
            Opcode::Mov as u8,
            arg_flag::DST | arg_flag::IMM8,
            reg::uq(1),
            10,
        ]);
        c += 4;
        // Mov uq[2], 20
        code[c..c + 4].copy_from_slice(&[
            Opcode::Mov as u8,
            arg_flag::DST | arg_flag::IMM8,
            reg::uq(2),
            20,
        ]);
        c += 4;
        // Call IMM64(ffi_addr)
        code[c] = Opcode::Call as u8;
        code[c + 1] = arg_flag::IMM64;
        code[c + 2..c + 10].copy_from_slice(&ffi_addr.to_le_bytes());
        c += 10;
        // Halt
        code[c..c + 2].copy_from_slice(&[Opcode::Halt as u8, arg_flag::NONE]);

        let mem = Memory {
            mem: [
                Segment {
                    name: "stack",
                    area: Area::SliceMut(&mut stack),
                    permission: Permission::RW,
                },
                Segment {
                    name: "data",
                    area: Area::SliceMut(&mut data),
                    permission: Permission::RW,
                },
                Segment {
                    name: "code",
                    area: Area::Slice(&code),
                    permission: Permission::RX,
                },
                Segment {
                    name: "ffi",
                    area: Area::Slice(&ffi_bytes),
                    permission: Permission::R,
                },
            ],
        };

        let mut vm = Vm::new(mem, 0);
        let status = vm.run().unwrap();
        assert_eq!(status, VmStatus::Halted);
        assert_eq!(vm.regs.read_int(reg::uq(0)).unwrap(), 60);
    }


    #[test]
    fn test_vm_symbol_export() {
        use opcode::CodeBuf;

        let mut stack = [0u8; 256];
        let mut data = [0u8; 64];
        let mut raw_code = [0u8; 128];
        let mut cb = CodeBuf::new(&mut raw_code);

        // =================================================================
        // 导出函数 0: fn vm_square(x: uq[1]) -> uq[0]
        // 逻辑: uq[0] = uq[1] * uq[1]; Ret
        // =================================================================
        let fn_square_offset = cb.offset();
        cb.dst_s1_s2(Opcode::Mul, reg::uq(0), reg::uq(1), reg::uq(1)).unwrap();
        cb.op0(Opcode::Ret).unwrap();

        // =================================================================
        // 导出函数 1: fn vm_sum_of_squares(a: uq[1], b: uq[2]) -> uq[0]
        // 逻辑: 通过 FFI 导出表调用两次 vm_square，计算 a*a + b*b
        // =================================================================
        let fn_sum_sq_offset = cb.offset();
        let ffi_square_addr = make_addr(3, 0); // FFI 段第 0 个符号 (vm_square)

        // Push uq[2] (保存参数 b)
        cb.emit(Opcode::Push, arg_flag::S1, 0, reg::uq(2), 0, 0).unwrap();
        // Call vm_square(a) -> 结果在 uq[0]
        cb.emit(Opcode::Call, arg_flag::IMM64, 0, 0, 0, ffi_square_addr).unwrap();
        // Pop uq[1] (将之前保存的 b 弹出作为下一次调用的第 1 参数 uq[1])
        cb.emit(Opcode::Pop, arg_flag::DST, reg::uq(1), 0, 0, 0).unwrap();
        // Push uq[0] (保存 a*a 的结果)
        cb.emit(Opcode::Push, arg_flag::S1, 0, reg::uq(0), 0, 0).unwrap();
        // Call vm_square(b) -> 结果在 uq[0]
        cb.emit(Opcode::Call, arg_flag::IMM64, 0, 0, 0, ffi_square_addr).unwrap();
        // Pop uq[3] (弹出 a*a)
        cb.emit(Opcode::Pop, arg_flag::DST, reg::uq(3), 0, 0, 0).unwrap();
        // uq[0] = uq[3] + uq[0] (即 a*a + b*b)
        cb.dst_s1_s2(Opcode::Add, reg::uq(0), reg::uq(3), reg::uq(0)).unwrap();
        cb.op0(Opcode::Ret).unwrap();

        // =================================================================
        // 构建 FFI 导出符号表（位于第 4 段 index=3，导出两个 VM 内部函数）
        // =================================================================
        let sym_square = Symbol::<4>::new(
            "vm_square",
            SymbolSource::Vm(make_addr(2, fn_square_offset)),
        );
        let sym_sum_sq = Symbol::<4>::new(
            "vm_sum_of_squares",
            SymbolSource::Vm(make_addr(2, fn_sum_sq_offset)),
        );

        let mut ffi_table = [0u8; Symbol::<4>::SIZE * 2];
        ffi_table[..Symbol::<4>::SIZE].copy_from_slice(&sym_square.to_ne_bytes());
        ffi_table[Symbol::<4>::SIZE..].copy_from_slice(&sym_sum_sq.to_ne_bytes());

        let mem = Memory {
            mem: [
                Segment { name: "stack", area: Area::SliceMut(&mut stack),     permission: Permission::RW },
                Segment { name: "data",  area: Area::SliceMut(&mut data),      permission: Permission::RW },
                Segment { name: "code",  area: Area::Slice(cb.as_slice()),     permission: Permission::RX },
                Segment { name: "ffi",   area: Area::Slice(&ffi_table),        permission: Permission::R },
            ],
        };

        let mut vm = Vm::new(mem, 0);

        // 1. 宿主机按名称调用导出的单层 VM 函数：vm_square(9) == 81
        let res1 = vm.call_export("vm_square", &[9]).unwrap();
        assert_eq!(res1, 81);

        // 2. 宿主机按名称调用导出的嵌套 VM 函数：vm_sum_of_squares(3, 4) == 3^2 + 4^2 == 25
        let res2 = vm.call_export("vm_sum_of_squares", &[3, 4]).unwrap();
        assert_eq!(res2, 25);

        // 3. 查找不存在的导出符号应返回错误
        assert!(vm.call_export("non_existent_fn", &[]).is_err());
    }
}
