use lib_unknown_vm::mem::{Area, Memory, Permission, Segment, make_addr};
use lib_unknown_vm::opcode::{CodeBuf, Opcode};
use lib_unknown_vm::reg;
use lib_unknown_vm::vm::{Vm, VmStatus};

/// 使用虚拟机字节码计算标准 IEEE 802.3 CRC-32
fn vm_calc_crc32(input: &[u8]) -> u32 {
    let mut raw_code = [0u8; 128];
    let mut cb = CodeBuf::new(&mut raw_code);

    // 寄存器分配约定：
    // uq[1] : 输入数据段基地址 ptr (调用前由宿主传入)
    // uq[2] : 输入数据字节长度 len (调用前由宿主传入)
    // uq[3] : 外层字节循环索引 i
    // ud[0] : crc 累加器 (32-bit，同时作为返回值寄存器)
    // ub[1] / ud[1] : 当前读取的字节 byte
    // ub[2] : 内层位循环计数器 bit_cnt (8..0)
    // ud[2] : 临时寄存器 (crc & 1)
    // ud[3] : 临时寄存器 (crc >> 1) ^ 0xEDB88320

    // crc = 0xFFFF_FFFF; i = 0;
    cb.dst_imm32(Opcode::Mov, reg::ud(0), 0xFFFF_FFFF).unwrap();
    cb.dst_imm8(Opcode::Mov, reg::uq(3), 0).unwrap();

    // .byte_loop:
    let byte_loop = cb.offset();
    // if i == len -> goto .done
    cb.cmp_reg(Opcode::CmpEq, false, reg::uq(3), reg::uq(2)).unwrap();
    let br_done = cb.br_rel8_fwd(true).unwrap();

    // ub[1] = input[ptr + i]; ud[1] = (u32)ub[1]; crc ^= ud[1];
    cb.dst_s1_s2(Opcode::Load, reg::ub(1), reg::uq(1), reg::uq(3)).unwrap();
    cb.dst_s1(Opcode::CastU, reg::ud(1), reg::ub(1)).unwrap();
    cb.dst_s1_s2(Opcode::Xor, reg::ud(0), reg::ud(0), reg::ud(1)).unwrap();

    // bit_cnt = 8
    cb.dst_imm8(Opcode::Mov, reg::ub(2), 8).unwrap();

    // .bit_loop:
    let bit_loop = cb.offset();
    // rf = (crc & 1) != 0
    cb.dst_s1_imm8(Opcode::And, reg::ud(2), reg::ud(0), 1).unwrap();
    cb.cmp_imm8(Opcode::CmpNe, false, reg::ud(2), 0).unwrap();
    // crc >>= 1
    cb.dst_s1_imm8(Opcode::LShr, reg::ud(0), reg::ud(0), 1).unwrap();
    // ud[3] = crc ^ 0xEDB88320
    cb.dst_s1_imm32(Opcode::Xor, reg::ud(3), reg::ud(0), 0xEDB8_8320).unwrap();
    // if rf { crc = ud[3] } (利用 Select 的单源 CMov 模式消除分支)
    cb.dst_s1(Opcode::Select, reg::ud(0), reg::ud(3)).unwrap();

    // bit_cnt -= 1; if bit_cnt != 0 -> goto .bit_loop
    cb.dst_s1_imm8(Opcode::Sub, reg::ub(2), reg::ub(2), 1).unwrap();
    cb.cmp_imm8(Opcode::CmpNe, false, reg::ub(2), 0).unwrap();
    cb.br_rel8_to(true, bit_loop).unwrap();

    // i += 1; goto .byte_loop
    cb.dst_s1_imm8(Opcode::Add, reg::uq(3), reg::uq(3), 1).unwrap();
    cb.jmp_rel8_to(byte_loop).unwrap();

    // .done:
    cb.patch_rel8(br_done).unwrap();
    // crc = !crc
    cb.dst_s1(Opcode::Not, reg::ud(0), reg::ud(0)).unwrap();
    cb.op0(Opcode::Halt).unwrap();

    let mut stack = [0u8; 128];
    let mem = Memory {
        mem: [
            Segment { name: "stack", area: Area::SliceMut(&mut stack),  permission: Permission::RW },
            Segment { name: "input", area: Area::Slice(input),          permission: Permission::R },
            Segment { name: "code",  area: Area::Slice(cb.as_slice()),  permission: Permission::RX },
            Segment { name: "ffi",   area: Area::Slice(&[]),            permission: Permission::R },
        ],
    };

    let mut vm = Vm::new(mem, 0);
    // 通过 uq[1], uq[2] 传入 input 的虚拟地址与长度
    vm.regs.write_int(reg::uq(1), make_addr(1, 0)).unwrap();
    vm.regs.write_int(reg::uq(2), input.len() as u64).unwrap();

    let status = vm.run().unwrap();
    assert_eq!(status, VmStatus::Halted);
    vm.regs.read_int(reg::ud(0)).unwrap() as u32
}

fn main() {
    let payload = b"123456789";
    let crc = vm_calc_crc32(payload);
    println!("CRC32(\"123456789\") = 0x{:08X}", crc);
    // IEEE 802.3 标准测试向量："123456789" 的 CRC32 固定为 0xCBF43926
    assert_eq!(crc, 0xCBF4_3926);

    let empty_crc = vm_calc_crc32(b"");
    assert_eq!(empty_crc, 0x0000_0000);
}