# dasm - a simple shellcode assembler

This is a simple shellcode assembler that is powered by the [Keystone Assembler Engine](https://www.keystone-engine.org/).

I created this to have a small utility that I can quickly write some assembly instructions and get them assembled for basic shellcode purposes. I only plan on using this for x86/64, ARM and MIPS but I incorporated support for all architectures supported by keystone.

A statically compiled x64 linux binary is available at `bin/dasm` if you don't wish to build yourself

## build

requirements: [keystone](https://www.keystone-engine.org/)

`make` to build

`make static` to build a static binary if you built libkeystone statically

## usage

dasm supports reading assembly instructions from a `path` or `stdin`.  If a `path` is  not detected, dasm will default to parsing `stdin` and the user can terminate input by entering the sequence `ctrl+d` to send an `EOF`.

### reading from path

```
$ ./dasm -a x86 -m 64 shellcode.s 
Architecture: X86
Mode: 64-bit
Endianess: Little-endian


Provided assembly:
pop rax;
pop rcx;
ret;
Assembled: 3 bytes, 6 statements

Raw shellcode:
5859c3

Escaped shellcode:
\x58\x59\xc3
```

### redirecting to stdin

```
$ cat shellcode.s | ./dasm -a x86 -m 64
Architecture: X86
Mode: 64-bit
Endianess: Little-endian


Reading from STDIN... ctrl+d when done
Provided assembly:
pop rax;
pop rcx;
ret;
Assembled: 3 bytes, 6 statements

Raw shellcode:
5859c3

Escaped shellcode:
\x58\x59\xc3
```

### directly using stdin

```
$ ./dasm 
Architecture: X86
Mode: 64-bit
Endianess: Little-endian


Reading from STDIN... ctrl+d when done
xor eax, eax
inc eax
inc eax
<ctrl+d>
Provided assembly:
xor eax, eax
inc eax
inc eax
Assembled: 6 bytes, 3 statements

Raw shellcode:
31c0ffc0ffc0

Escaped shellcode:
\x31\xc0\xff\xc0\xff\xc0
```

### supported options

```
Usage: dasm -a [architecture] [options] {file/stdin} 
  -h    Print this help and exit.
ARCHITECTURE:
  -a
        ARM        ARM architecture (including Thumb, Thumb-2)
        ARM64      ARM-64, also called AArch64
        MIPS       Mips architecture
        X86        X86 architecture (including x86 & x86-64)
        PPC        PowerPC architecture
        SPARC      Sparc architecture
        SYSTEMZ    SystemZ architecture (S390X)
        HEXAGON    Hexagon architecture
        EVM        Ethereum Virtual Machine architecture
[OPTIONS]
MODE:
  -m
        ARM:
          ARM      ARM mode
          THUMB    THUMB mode (including Thumb-2)
          V8       ARMv8 A32 encodings for ARM
        ARM64: Only supports Little-endian any mode input is discarded
        MIPS:
          MICRO       MicroMips mode
          MIPS3       Mips III ISA
          MIPS32R6    Mips32r6 ISA
          MIPS32      Mips32 ISA
          MIPS64      Mips64 ISA
        X86/X64:
          16    16-bit mode
          32    32-bit mode
          64    64-bit mode
        PPC:
          PPC32    32-bit mode
          PPC64    64-bit mode
          QPX      Quad Processing eXtensions mode
        SPARC:
          SPARC32    32-bit mode
          SPARC64    64-bit mode
          V9         SparcV9 mode
SYNTAX:
  -s: Syntax is only supported for x86
          INTEL      X86 Intel syntax
          ATT        X86 ATT asm syntax
          NASM       X86 Nasm syntax
          MASM       X86 Masm syntax
          GAS        X86 GNU GAS syntax
          RADIX16    All immediates are in hex format (i.e 12 is 0x12)
ENDIANESS:
  -e: Big-Endian is only supported for ARM, Hexagon, Mips, PowerPC, Sparc and SystemZ
          LITTLE    Little-endian mode (default mode)
          BIG       Big-endian mode
Source Repository: https://github.com/droogie/dasm
```

