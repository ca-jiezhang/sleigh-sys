#[cxx::bridge(namespace="ghidra")]
pub mod ffi {

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u32)]
    enum spacetype {
        IPTR_CONSTANT = 0,
        IPTR_PROCESSOR = 1,
        IPTR_SPACEBASE = 2,
        IPTR_INTERNAL = 3,
        IPTR_FSPEC = 4,
        IPTR_IOP = 5,
        IPTR_JOIN = 6,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u32)]
    enum OpCode {
          CPUI_COPY = 1,		///< Copy one operand to another
          CPUI_LOAD = 2,		///< Load from a pointer into a specified address space
          CPUI_STORE = 3,		///< Store at a pointer into a specified address space
          CPUI_BRANCH = 4,		///< Always branch
          CPUI_CBRANCH = 5,		///< Conditional branch
          CPUI_BRANCHIND = 6,		///< Indirect branch (jumptable)
          CPUI_CALL = 7,		///< Call to an absolute address
          CPUI_CALLIND = 8,		///< Call through an indirect address
          CPUI_CALLOTHER = 9,		///< User-defined operation
          CPUI_RETURN = 10,		///< Return from subroutine
          CPUI_INT_EQUAL = 11,		///< Integer comparison, equality (==)
          CPUI_INT_NOTEQUAL = 12,	///< Integer comparison, in-equality (!=)
          CPUI_INT_SLESS = 13,		///< Integer comparison, signed less-than (<)
          CPUI_INT_SLESSEQUAL = 14,	///< Integer comparison, signed less-than-or-equal (<=)
          CPUI_INT_LESS = 15,		///< Integer comparison, unsigned less-than (<)
          CPUI_INT_LESSEQUAL = 16,	///< Integer comparison, unsigned less-than-or-equal (<=)
          CPUI_INT_ZEXT = 17,		///< Zero extension
          CPUI_INT_SEXT = 18,		///< Sign extension
          CPUI_INT_ADD = 19,		///< Addition, signed or unsigned (+)
          CPUI_INT_SUB = 20,		///< Subtraction, signed or unsigned (-)
          CPUI_INT_CARRY = 21,		///< Test for unsigned carry
          CPUI_INT_SCARRY = 22,		///< Test for signed carry
          CPUI_INT_SBORROW = 23,	///< Test for signed borrow
          CPUI_INT_2COMP = 24,		///< Twos complement
          CPUI_INT_NEGATE = 25,		///< Logical/bitwise negation (~)
          CPUI_INT_XOR = 26,		///< Logical/bitwise exclusive-or (^)
          CPUI_INT_AND = 27,		///< Logical/bitwise and (&)
          CPUI_INT_OR = 28,		///< Logical/bitwise or (|)
          CPUI_INT_LEFT = 29,		///< Left shift (<<)
          CPUI_INT_RIGHT = 30,		///< Right shift, logical (>>)
          CPUI_INT_SRIGHT = 31,		///< Right shift, arithmetic (>>)
          CPUI_INT_MULT = 32,		///< Integer multiplication, signed and unsigned (*)
          CPUI_INT_DIV = 33,		///< Integer division, unsigned (/)
          CPUI_INT_SDIV = 34,		///< Integer division, signed (/)
          CPUI_INT_REM = 35,		///< Remainder/modulo, unsigned (%)
          CPUI_INT_SREM = 36,		///< Remainder/modulo, signed (%)
          CPUI_BOOL_NEGATE = 37,	///< Boolean negate (!)
          CPUI_BOOL_XOR = 38,		///< Boolean exclusive-or (^^)
          CPUI_BOOL_AND = 39,		///< Boolean and (&&)
          CPUI_BOOL_OR = 40,		///< Boolean or (||)
          CPUI_FLOAT_EQUAL = 41,        ///< Floating-point comparison, equality (==)
          CPUI_FLOAT_NOTEQUAL = 42,	///< Floating-point comparison, in-equality (!=)
          CPUI_FLOAT_LESS = 43,		///< Floating-point comparison, less-than (<)
          CPUI_FLOAT_LESSEQUAL = 44,	///< Floating-point comparison, less-than-or-equal (<=)
          CPUI_FLOAT_NAN = 46,	        ///< Not-a-number test (NaN)
          CPUI_FLOAT_ADD = 47,          ///< Floating-point addition (+)
          CPUI_FLOAT_DIV = 48,          ///< Floating-point division (/)
          CPUI_FLOAT_MULT = 49,         ///< Floating-point multiplication (*)
          CPUI_FLOAT_SUB = 50,          ///< Floating-point subtraction (-)
          CPUI_FLOAT_NEG = 51,          ///< Floating-point negation (-)
          CPUI_FLOAT_ABS = 52,          ///< Floating-point absolute value (abs)
          CPUI_FLOAT_SQRT = 53,         ///< Floating-point square root (sqrt)
          CPUI_FLOAT_INT2FLOAT = 54,    ///< Convert an integer to a floating-point
          CPUI_FLOAT_FLOAT2FLOAT = 55,  ///< Convert between different floating-point sizes
          CPUI_FLOAT_TRUNC = 56,        ///< Round towards zero
          CPUI_FLOAT_CEIL = 57,         ///< Round towards +infinity
          CPUI_FLOAT_FLOOR = 58,        ///< Round towards -infinity
          CPUI_FLOAT_ROUND = 59,	///< Round towards nearest
          CPUI_MULTIEQUAL = 60,		///< Phi-node operator
          CPUI_INDIRECT = 61,		///< Copy with an indirect effect
          CPUI_PIECE = 62,		///< Concatenate
          CPUI_SUBPIECE = 63,		///< Truncate
          CPUI_CAST = 64,		///< Cast from one data-type to another
          CPUI_PTRADD = 65,		///< Index into an array ([])
          CPUI_PTRSUB = 66,		///< Drill down to a sub-field  (->)
          CPUI_SEGMENTOP = 67,		///< Look-up a \e segmented address
          CPUI_CPOOLREF = 68,		///< Recover a value from the \e constant \e pool
          CPUI_NEW = 69,		///< Allocate a new object (new)
          CPUI_INSERT = 70,		///< Insert a bit-range
          CPUI_EXTRACT = 71,		///< Extract a bit-range
          CPUI_POPCOUNT = 72,		///< Count the 1-bits
          CPUI_LZCOUNT = 73,		///< Count the leading 0-bits
          CPUI_MAX = 74,
    }

    unsafe extern "C++" {
        include!("binding.hh");
        
        // customized types:
    
        type RContext;
        
        fn new_context(filename: &str) -> UniquePtr<RContext>;
        fn set_variable_default(self: Pin<&mut RContext>, name: &str, value: u32);
        fn disassemble(self: Pin<&mut RContext>, data: &[u8], addr: u64) -> Result<UniquePtr<RAssemblyInstruction>>;
        fn translate(self: Pin<&mut RContext>, data: &[u8], addr: u64) -> Result<UniquePtr<RTranslation>>;

        type RTranslation;

        fn instruction_address(self: &RTranslation) -> u64;
        fn next_instruction_address(self: &RTranslation) -> u64;
        fn instruction_size(self: &RTranslation) -> u32;
        fn count(self: &RTranslation) -> u32;
        fn code(self: &RTranslation, index: u32) -> Result<&RPcode>;

        type RPcode;

        fn opcode(self: &RPcode) -> OpCode;
        fn output(self: &RPcode) -> Result<&RVarnodeData>;
        fn argc(self: &RPcode) -> u32;
        fn argv(self: &RPcode, index: u32) -> Result<&RVarnodeData>;
        
        type RAssemblyInstruction;

        fn address(self: &RAssemblyInstruction) -> u64;
        fn size(self: &RAssemblyInstruction) -> u32;
        fn mnem(self: &RAssemblyInstruction) -> &str;
        fn body(self: &RAssemblyInstruction) -> &str;

        type RVarnodeData;

        fn space(self: &RVarnodeData) -> UniquePtr<RAddrSpace>;
        fn offset(self: &RVarnodeData) -> u64;
        fn size(self: &RVarnodeData) -> u32;

        fn register_name(self: &RVarnodeData) -> Result<String>;
        fn user_defined_op_name(self: &RVarnodeData) -> Result<String>;
        fn space_from_const(self: &RVarnodeData) -> UniquePtr<RAddrSpace>;

        type RAddress;
        
        fn space(self: &RAddress) -> UniquePtr<RAddrSpace>;
        fn offset(self: &RAddress) -> u64;

        type RAddrSpace;

        fn name(self: &RAddrSpace) -> &str;
        fn kind(self: &RAddrSpace) -> spacetype;

        // sleigh builtin types:

        type spacetype;
        type OpCode;
    }
}

#[cfg(test)]
mod test {
    use super::ffi;

    #[test]
    fn test() {

        /// dump VarnodeData as String
        fn dump_var(v: &ffi::RVarnodeData) -> String {
            if let Ok(reg) = v.register_name() {
                reg
            } else {
                format!("{}<{:#?}>_{:X}:{}", v.space().name(), v.space().kind(), v.offset(), v.size())
            }
        }

        // sla file
        let x86_sla: std::path::PathBuf = [
            env!("CARGO_MANIFEST_DIR"),
            "assets",
            "x86.sla",
        ].iter().collect();

        // sla file must be exist
        assert!(x86_sla.exists());

        let sleigh_filename = format!("<sleigh>{}</sleigh>", x86_sla.display());

        let mut ctx = ffi::new_context(&sleigh_filename);

        ctx.pin_mut().set_variable_default("opsize", 1);
        ctx.pin_mut().set_variable_default("addrsize", 1);

        let code: &[u8] = &[
                        0x0F, 0xA2,     // cpuid
                        0x55,           // push ebp
                        0x8b, 0x03,     // mov eax, [ebx]
                        0x89, 0x18,     // mov [eax], ebx
                        0xEB, 0xFF,     // jmp $
                        0x74, 0xFF,     // jz $
                ];

        let mut addr: u64 = 0x401000;
        let mut pos: usize = 0;

        while pos < code.len() {

            // disassemble binary code with sleigh
            if let Ok(insn) = ctx.pin_mut().disassemble(&code[pos..], addr) {
                println!("{:X} {} {} ; {} bytes", insn.address(), insn.mnem(), insn.body(), insn.size());
            } else {
                break;
            }

            // translate binary code to sleigh pcodes
            if let Ok(block) = ctx.pin_mut().translate(&code[pos..], addr) {

                for i in 0..block.count() {
                    let ii = block.code(i).unwrap();

                    // show pcode index in the block
                    print!("[{}] ", i);

                    // if there is a output VarnodeData, show it properly
                    if let Ok(out) = ii.output() {
                        print!("{} = ", dump_var(out));
                    }

                    // display opcode
                    let opcode = ii.opcode();
                    print!("{:#?} ", opcode);

                    // show all input arguments
                    for j in 0..ii.argc() {

                        if opcode == ffi::OpCode::CPUI_CALLOTHER && j==0 {
                            // CALLOTHER <user_defined_op_name>, ...
                            print!("{}", ii.argv(j).unwrap()
                                .user_defined_op_name().unwrap_or("N/A".to_string()));

                        } else if (ii.opcode() == ffi::OpCode::CPUI_STORE || ii.opcode() == ffi::OpCode::CPUI_LOAD) && j==0 {
                            // STORE/LOAD <encoded_space_const>, ...
                            print!("{}", ii.argv(j).unwrap().space_from_const().name());
                        } else {
                            if j!=0 {
                                print!(", ");
                            }

                            // dump other VarnodeData
                            print!("{}", dump_var(ii.argv(j).unwrap()));
                        }
                    }

                    println!("");
                }

                addr = block.next_instruction_address();
                pos += block.instruction_size() as usize;

            } else {
                break;
            }

            println!("");
        }
    }
}
