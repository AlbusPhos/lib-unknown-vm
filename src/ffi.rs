use crate::mem::Memory;
use crate::reg::Registers;

pub type VmHostFn<const N: usize = 4> = fn(&mut Registers, &mut Memory<'_, N>) -> crate::Result<()>;

#[repr(C)]
#[derive(Clone, Copy)]
pub enum SymbolSource<const N: usize = 4> {
    /// 虚拟机内部字节码函数：存储指向第 N-1 段（代码段）的虚拟地址
    Vm(u64),
    /// 宿主机 C/Rust 函数：存储统一包装后的函数入口
    Host(VmHostFn<N>),
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Symbol<const N: usize = 4> {
    pub name: [u8; 32],
    pub source: SymbolSource<N>,
}

impl<const N: usize> Symbol<N> {
    pub const SIZE: usize = size_of::<Self>();

    /// 便捷构造函数：自动将字符串名称填入 32 字节定长数组（多余截断，不足补 0）
    pub fn new(name: &str, source: SymbolSource<N>) -> Self {
        let mut buf = [0u8; 32];
        let bytes = name.as_bytes();
        let len = bytes.len().min(32);
        buf[..len].copy_from_slice(&bytes[..len]);
        Self { name: buf, source }
    }

    /// 读取符号名称字符串（去除末尾填充的 '\0'）
    #[inline]
    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(self.name.len());
        core::str::from_utf8(&self.name[..len]).unwrap_or("")
    }

    /// 在 FFI 段字节流中按名称查找符号，返回 (符号在段内的字节偏移, Symbol)
    pub fn find_in_bytes(ffi_bytes: &[u8], target_name: &str) -> crate::Result<(usize, Self)> {
        for (idx, chunk) in ffi_bytes.chunks_exact(Self::SIZE).enumerate() {
            let sym = Self::from_bytes(chunk)?;
            if sym.name_str() == target_name {
                return Ok((idx * Self::SIZE, sym));
            }
        }
        Err("FFI symbol not found")
    }

    #[inline(always)]
    pub fn to_ne_bytes(self) -> [u8; size_of::<Symbol>()] {
        unsafe { core::mem::transmute_copy(&self) }
    }

    #[inline(always)]
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() < Self::SIZE {
            return Err("FFI symbol slice out of bounds");
        }
        Ok(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const Self) })
    }
}