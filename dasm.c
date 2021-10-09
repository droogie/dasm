//dasm - simple shellcode assembler
//powered by the keystone assembler engine
//github.com/droogie
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <keystone/keystone.h>

#define BUF_SIZE 1024
#define ARRAY_SIZE(arr)     (sizeof(arr) / sizeof((arr)[0]))

struct arg_enum {
    unsigned int code;
    const char *name;
};

struct arg_enum _arch_enum[] = {
    {KS_ARCH_ARM, "ARM"},
    {KS_ARCH_ARM64, "ARM64"},
    {KS_ARCH_MIPS, "MIPS"},
    {KS_ARCH_X86, "X86"},
    {KS_ARCH_PPC, "PPC"},
    {KS_ARCH_SPARC, "SPARC"},
    {KS_ARCH_SYSTEMZ, "SYSTEMZ"},
    {KS_ARCH_HEXAGON, "HEXAGON"},
    {KS_ARCH_EVM, "EVM"}
};

struct arg_enum _mode_enum[] = {
    {KS_MODE_ARM, "ARM"},       
    {KS_MODE_THUMB, "THUMB"},     
    {KS_MODE_V8, "V8"},        
    {KS_MODE_MICRO, "MICRO"},     
    {KS_MODE_MIPS3, "MIPS3"},     
    {KS_MODE_MIPS32R6, "MIPS32R6"},  
    {KS_MODE_MIPS32, "MIPS32"},    
    {KS_MODE_MIPS64, "MIPS64"},    
    {KS_MODE_16, "16"},        
    {KS_MODE_32, "32"},        
    {KS_MODE_64, "64"},        
    {KS_MODE_PPC32, "PPC32"},     
    {KS_MODE_PPC64, "PPC64"},     
    {KS_MODE_QPX, "QPX"},       
    {KS_MODE_SPARC32, "SPARC32"},   
    {KS_MODE_SPARC64, "SPARC64"},   
    {KS_MODE_V9, "V9"},
};

struct arg_enum _endian_enum[] = {
    {KS_MODE_LITTLE_ENDIAN, "LITTLE"},
    {KS_MODE_BIG_ENDIAN, "BIG"},
};

struct arg_enum _syntax_enum[] = {
    {KS_OPT_SYNTAX_INTEL  , "INTEL"},
    {KS_OPT_SYNTAX_ATT    , "ATT"},
    {KS_OPT_SYNTAX_NASM   , "NASM"},
    {KS_OPT_SYNTAX_MASM   , "MASM"},
    {KS_OPT_SYNTAX_GAS    , "GAS"},
    {KS_OPT_SYNTAX_RADIX16, "RADIX16"},
};

int get_enum_code(struct arg_enum aenum[], size_t size, char *optarg) {
    for (int i=0; i < size; i++) {
        if (!strcasecmp(optarg, aenum[i].name)) {
            return aenum[i].code;
            break;
        }
    }

    printf("Unexpected Error: get_enum_code() failed to find a match\n");
    exit(-1);
}

char *get_enum_string(struct arg_enum aenum[], size_t size, int optarg) {
    for (int i=0; i < size; i++) {
        if (optarg == _arch_enum[i].code) {
            return (char *)_arch_enum[i].name;
            break;
        }
    }

    printf("Unexpected Error: get_enum_string() failed to find a match\n");
    exit(-1);
}

ks_engine *init_keystone(ks_arch arch, int mode, int syntax) {
    ks_err ret;
    ks_engine *ks;

    if(ks_open(arch, mode, &ks)) {
        return NULL;
    }

    if(arch == KS_ARCH_X86) {
        ks_option(ks, KS_OPT_SYNTAX, syntax);
    }

    return ks;
}

void dump_rawshellcode(unsigned char *shellcode, size_t size) {
    printf("Raw shellcode:\n");
    for (size_t i=0; i<size; i++) {
        printf("%x", shellcode[i]);
    }
    printf("\n\n");

}

void dump_escapedshellcode(unsigned char *shellcode, size_t size) {
    printf("Escaped shellcode:\n");
    for (size_t i=0; i<size; i++) {
        printf("\\x%x", shellcode[i]);
    }
    printf("\n\n");
}

static int assemble(ks_arch arch, int mode, const char *assembly, int syntax) {
    ks_engine *ks;
    size_t size;
    size_t count;
    unsigned char *shellcode;

    ks = init_keystone(arch, mode, syntax);
    if (!ks) {
        printf("init_keystone() failed!\n");
        printf("Ensure that you are providing a valid architecture and mode!\n");
        return -1;
    }

    if (ks_asm(ks, assembly, 0, &shellcode, &size, &count)) {
        printf("ERROR: ks_asm() failed!\n[%u] %s\n", ks_errno(ks), ks_strerror(ks_errno(ks)));
        return -1;
    }
    
    printf("Provided assembly:\n%s", assembly);
    printf("Assembled: %lu bytes, %lu statements\n\n", size, count);

    dump_rawshellcode(shellcode, size);

    dump_escapedshellcode(shellcode, size);

    ks_free(shellcode);
    ks_close(ks);
    return 0;
}

void usage (FILE *fp, const char *path)
{
    const char *basename = strrchr(path, '/');
    basename = basename ? basename + 1 : path;

    fprintf (fp, "Usage: %s -a [architecture] [options] {file/stdin} \n", basename);
    fprintf (fp, "  -h\tPrint this help and exit.\n");
    fprintf (fp, "ARCHITECTURE:\n");
    fprintf (fp, "  -a\n");
    fprintf (fp, "  \tARM        ARM architecture (including Thumb, Thumb-2)\n");
    fprintf (fp, "  \tARM64      ARM-64, also called AArch64\n");
    fprintf (fp, "  \tMIPS       Mips architecture\n");
    fprintf (fp, "  \tX86        X86 architecture (including x86 & x86-64)\n");
    fprintf (fp, "  \tPPC        PowerPC architecture\n");
    fprintf (fp, "  \tSPARC      Sparc architecture\n");
    fprintf (fp, "  \tSYSTEMZ    SystemZ architecture (S390X)\n");
    fprintf (fp, "  \tHEXAGON    Hexagon architecture\n");
    fprintf (fp, "  \tEVM        Ethereum Virtual Machine architecture\n");
    fprintf (fp, "[OPTIONS]\n");
    fprintf (fp, "MODE:\n");
    fprintf (fp, "  -m\n");
    fprintf (fp, "  \tARM:\n");
    fprintf (fp, "  \t  ARM      ARM mode\n");
    fprintf (fp, "  \t  THUMB    THUMB mode (including Thumb-2)\n");
    fprintf (fp, "  \t  V8       ARMv8 A32 encodings for ARM\n");
    fprintf (fp, "  \tARM64: Only supports Little-endian any mode input is discarded\n");
    fprintf (fp, "  \tMIPS:\n");
    fprintf (fp, "  \t  MICRO       MicroMips mode\n");
    fprintf (fp, "  \t  MIPS3       Mips III ISA\n");
    fprintf (fp, "  \t  MIPS32R6    Mips32r6 ISA\n");
    fprintf (fp, "  \t  MIPS32      Mips32 ISA\n");
    fprintf (fp, "  \t  MIPS64      Mips64 ISA\n");
    fprintf (fp, "  \tX86/X64:\n");
    fprintf (fp, "  \t  16    16-bit mode\n");
    fprintf (fp, "  \t  32    32-bit mode\n");
    fprintf (fp, "  \t  64    64-bit mode\n");
    fprintf (fp, "  \tPPC:\n");
    fprintf (fp, "  \t  PPC32    32-bit mode\n");
    fprintf (fp, "  \t  PPC64    64-bit mode\n");
    fprintf (fp, "  \t  QPX      Quad Processing eXtensions mode\n");
    fprintf (fp, "  \tSPARC:\n");
    fprintf (fp, "  \t  SPARC32    32-bit mode\n");
    fprintf (fp, "  \t  SPARC64    64-bit mode\n");
    fprintf (fp, "  \t  V9         SparcV9 mode\n");    
    fprintf (fp, "SYNTAX:\n");
    fprintf (fp, "  -s: Syntax is only supported for x86\n");
    fprintf (fp, "  \t  INTEL      X86 Intel syntax\n");
    fprintf (fp, "  \t  ATT        X86 ATT asm syntax\n");
    fprintf (fp, "  \t  NASM       X86 Nasm syntax\n");
    fprintf (fp, "  \t  MASM       X86 Masm syntax\n");
    fprintf (fp, "  \t  GAS        X86 GNU GAS syntax\n");
    fprintf (fp, "  \t  RADIX16    All immediates are in hex format (i.e 12 is 0x12)\n");
    fprintf (fp, "ENDIANESS:\n");
    fprintf (fp, "  -e: Big-Endian is only supported for ARM, Hexagon, Mips, PowerPC, Sparc and SystemZ\n");
    fprintf (fp, "  \t  LITTLE    Little-endian mode (default mode)\n");
    fprintf (fp, "  \t  BIG       Big-endian mode\n");
    fprintf (fp, "Source Repository: https://github.com/droogie/dasm\n");
}

int main(int argc, char *argv[]) {

    int help_flag = 0;
    int arch = KS_ARCH_X86; // just default to x86
    int mode = 0;
    int endian = -1;
    int syntax = 0;
    char *path;
    char *assembly;
    int opt;

    while (1) {
        opt = getopt(argc, argv, "ha:m:e:s:");

        if (opt == -1) {
            break;
        }

        switch (opt) {
        case 'h':
            help_flag = 1;
            break;

        case 'a':
            if (strcasecmp(optarg, "ARM")     != 0 && 
                strcasecmp(optarg, "ARM64")   != 0 &&
                strcasecmp(optarg, "MIPS")    != 0 &&
                strcasecmp(optarg, "X86")     != 0 &&
                strcasecmp(optarg, "PPC")     != 0 &&
                strcasecmp(optarg, "SPARC")   != 0 &&
                strcasecmp(optarg, "SYSTEMZ") != 0 &&
                strcasecmp(optarg, "HEXAGON") != 0 &&
                strcasecmp(optarg, "EVM")) {
                printf("Invalid architecture provided! (%s)\n", optarg);
                help_flag = 1;
                break;
            }
            arch = get_enum_code(_arch_enum, ARRAY_SIZE(_arch_enum), optarg);

            break;

        case 'm':
            if (strcasecmp(optarg, "ARM")       != 0 && 
                strcasecmp(optarg, "THUMB")     != 0 &&
                strcasecmp(optarg, "V8")     != 0 &&
                strcasecmp(optarg, "MICRO")     != 0 &&
                strcasecmp(optarg, "MIPS3")     != 0 &&
                strcasecmp(optarg, "MIPS32R6")  != 0 &&
                strcasecmp(optarg, "MIPS32")    != 0 &&
                strcasecmp(optarg, "MIPS64")    != 0 &&
                strcasecmp(optarg, "16")        != 0 && 
                strcasecmp(optarg, "32")        != 0 && 
                strcasecmp(optarg, "64")        != 0 && 
                strcasecmp(optarg, "PPC32")     != 0 && 
                strcasecmp(optarg, "PPC64")     != 0 && 
                strcasecmp(optarg, "QPX")       != 0 && 
                strcasecmp(optarg, "SPARC32")   != 0 && 
                strcasecmp(optarg, "SPARC64")   != 0 && 
                strcasecmp(optarg, "V9")) {
                printf("Invalid mode provided! (%s)\n", optarg);
                help_flag = 1;
                break;
            }

            mode = get_enum_code(_mode_enum, ARRAY_SIZE(_mode_enum), optarg);

            break;

        case 'e':
            if (strcasecmp(optarg, "LITTLE")       != 0 && 
                strcasecmp(optarg, "BIG")) {
                printf("Invalid endian provided! (%s)\n", optarg);
                help_flag = 1;
                break;
            }

            endian = get_enum_code(_endian_enum, ARRAY_SIZE(_endian_enum), optarg);

            break;

        case 's':
            if (strcasecmp(optarg, "INTEL")    != 0 && 
                strcasecmp(optarg, "ATT")      != 0 && 
                strcasecmp(optarg, "NASM")     != 0 && 
                strcasecmp(optarg, "MASM")     != 0 && 
                strcasecmp(optarg, "GAS")      != 0 && 
                strcasecmp(optarg, "RADIX16")) {
                printf("Invalid syntax provided! (%s)\n", optarg);
                help_flag = 1;
                break;
            }

            for (int i=0; i < sizeof(_syntax_enum) / sizeof(_syntax_enum[0]); i++) {
                if (!strcasecmp(optarg, _syntax_enum[i].name)) {
                    syntax = _syntax_enum[i].code;
                    break;
                }
            }
            break;

        case '?':
            usage (stderr, argv[0]);
            return 1;

        default:
            break;
        }
    }

    if (help_flag) {
        usage (stdout, argv[0]);
        return 0;
    }

    if (arch != KS_ARCH_X86 && syntax != 0) {
        printf("Provided an invalid syntax with the selected architecture! Ignoring it...\n");
        syntax = 0;
    }

    if (arch == KS_ARCH_ARM) {
        // Default ARM mode Little-endian
        if (!mode) {
            mode = KS_MODE_ARM;
        }
        if (endian == -1) {
            endian = KS_MODE_LITTLE_ENDIAN;
        }
        if ((mode != KS_MODE_ARM) && (mode != KS_MODE_THUMB)) {
            printf("Provided an invalid mode for ARM!\n");
            help_flag = 1;
        }

        printf("Architecture: ARM\n");
        printf("Mode: %s\n", (mode == KS_MODE_ARM ? "ARM" : "THUMB"));
        printf("Endianess: %s\n", (endian == 0 ? "Little-endian" : "Big-endian"));
    }
    else if (arch == KS_ARCH_ARM64) {
        // ARM64 Little-endian (keystone does not support Big-endian for AArch64)
        if (mode && mode != KS_MODE_V8) {
            mode = 0;
            printf("ARM64 only supports optionally ARMv8 mode\n");
        }
        
        if (endian != -1 && endian != KS_MODE_LITTLE_ENDIAN) {
            endian = KS_MODE_LITTLE_ENDIAN;
            printf("ARM64 only supports Little-endian (keystone)\n");
        }

        printf("Architecture: ARM64 (AArch64)\n");
        printf("Mode: %s\n", (mode == 0 ? "64-bit" : "ARMv8 A32 encodings for ARM"));
        printf("Endianess: Little-endian\n");
    }
    else if (arch == KS_ARCH_MIPS) {
        // Default MIPS64 mode Little-endian
        if(!mode) {
            mode = KS_MODE_MIPS64;
        }
        if(endian == -1) {
            endian = KS_MODE_LITTLE_ENDIAN;
        }

        if ((mode != KS_MODE_MICRO) && (mode != KS_MODE_MIPS3) && (mode != KS_MODE_MIPS32R6) && \
            (mode != KS_MODE_MIPS32) && KS_MODE_MIPS64) {
            printf("Provided an invalid mode for MIPS!\n");
            mode = KS_MODE_MIPS64;
        }

        printf("Architecture: MIPS\n");
        char *modestr;
        switch(mode) {
            case KS_MODE_MICRO:
                modestr = (char *)"MicroMips";
                break;

            case KS_MODE_MIPS3:
                modestr = (char *)"Mips III ISA";
                break;

            case KS_MODE_MIPS32:
                modestr = (char *)"Mips32 ISA";
                break;

            case KS_MODE_MIPS32R6:
                modestr = (char *)"Mips32r6 ISA";
                break;

            case KS_MODE_MIPS64:
                modestr = (char *)"Mips64 ISA";
                break;
        }
        printf("Mode: %s\n", modestr);
        printf("Endianess: %s\n", (endian == 0 ? "Little-endian" : "Big-endian"));

    }
    else if (arch == KS_ARCH_X86) {
        // Default 64bit mode
        if (!mode) {
            mode = KS_MODE_64;
        }
        if(endian == -1) {
            endian = KS_MODE_LITTLE_ENDIAN;
        }

        if ((mode != KS_MODE_16) && (mode != KS_MODE_32) && (mode != KS_MODE_64)) {
            printf("Provided an invalid mode for X86!\n");
            help_flag = 1;
        } else if (endian != KS_MODE_LITTLE_ENDIAN) {
            endian = KS_MODE_LITTLE_ENDIAN;
            printf("Provided an invalid endian for X86!\n");
        }

        printf("Architecture: X86\n");
        char *modestr;
        switch(mode) {
            case KS_MODE_16:
                modestr = (char *)"16-bit";
                break;
            case KS_MODE_32:
                modestr = (char *)"32-bit";
                break;
            case KS_MODE_64:
                modestr = (char *)"64-bit";
                break;
        }
        printf("Mode: %s\n", modestr);
        printf("Endianess: %s\n", (endian == 0 ? "Little-endian" : "Big-endian"));
    }
    else if (arch == KS_ARCH_PPC) {
        // Default 64bit mode with Big-endian
        if (!mode) {
            mode = KS_MODE_PPC64;
        }
        if (endian == -1) {
            endian = KS_MODE_BIG_ENDIAN;
        }

        if ((mode != KS_MODE_PPC32) && (mode != KS_MODE_PPC64) && (mode != KS_MODE_QPX)) {
            printf("Provided an invalid mode for PPC!\n");
            help_flag = 1;
        }
        printf("Architecture: PPC\n");
        char *modestr;
        switch(mode) {
            case KS_MODE_PPC32:
                modestr = (char *)"32-bit";
                break;
            case KS_MODE_PPC64:
                modestr = (char *)"64-bit";
                break;
            case KS_MODE_QPX:
                modestr = (char *)"Quad Processing eXtensions";
                break;
        }
        printf("Mode: %s\n", modestr);
        printf("Endianess: %s\n", (endian == 0 ? "Little-endian" : "Big-endian"));
    }
    else if (arch == KS_ARCH_SPARC) {
        // Default 32bit mode with Little-endian
        if (!mode) {
            mode = KS_MODE_SPARC32;
        }
        if (endian == -1) {
            endian = KS_MODE_LITTLE_ENDIAN;
        }

        if ((mode != KS_MODE_SPARC32) && (mode != KS_MODE_SPARC64) && (mode != KS_MODE_V9)) {
            printf("Provided an invalid mode for SPARC!\n");
            help_flag = 1;
        }

        printf("Architecture: SPARC\n");
        char *modestr;
        switch(mode) {
            case KS_MODE_SPARC32:
                modestr = (char *)"32-bit";
                break;
            case KS_MODE_SPARC64:
                modestr = (char *)"64-bit";
                break;
            case KS_MODE_V9:
                modestr = (char *)"SparcV9";
                break;
        }
        printf("Mode: %s\n", modestr);
        printf("Endianess: %s\n", (endian == 0 ? "Little-endian" : "Big-endian"));

    }
    else if (arch == KS_ARCH_SYSTEMZ) {
        // Only supports Big-endian
        if (endian == -1) {
            endian = KS_MODE_BIG_ENDIAN;
        }
        if (endian != KS_MODE_BIG_ENDIAN) {
            printf("Provided an invalid endian for SYSTEMZ!\n");
            endian = KS_MODE_BIG_ENDIAN;
        }

        printf("Architecture: SYSTEMZ\n");
        printf("Endianess: %s\n", (endian == 0 ? "Little-endian" : "Big-endian"));
    }
    else if (arch == KS_ARCH_HEXAGON) {
        // Only supports Big-endian
        if (endian == -1) {
            endian = KS_MODE_BIG_ENDIAN;
        }
        if (endian != KS_MODE_BIG_ENDIAN) {
            printf("Provided an invalid endian for HEXAGON!\n");
            endian = KS_MODE_BIG_ENDIAN;
        }

        printf("Architecture: HEXAGON\n");
        printf("Endianess: %s\n", (endian == 0 ? "Little-endian" : "Big-endian"));

    }
    else if (arch == KS_ARCH_EVM) {
        mode = 0;
        endian = 0;
        printf("Architecture: Ethereum Virtual Machine\n");
    }

    // check if last parameter is a valid path (not provided as a param)
    // if so read the file contents, else read from STDIN
    if (argc > 1) {
        path = argv[argc-1];
    };

    printf("\n\n");

    if( path && (access(path, F_OK) == 0) && (strncmp(argv[argc-2], "-", 1) != 0)) {
        FILE *fd = fopen(path, "r");
        fseek(fd, 0, SEEK_END);
        long size = ftell(fd);
        fseek(fd, 0, SEEK_SET);

        assembly = (char *)malloc(size + 1);
        if(assembly == NULL)
        {
            perror("malloc()");
            exit(1);
        }

        fread(assembly, 1, size, fd);
        fclose(fd);

        assembly[size] = 0;
    } 
    else {
        // Simply read input from STDIN (redirected or manually)
        printf("Reading from STDIN... ctrl+d when done\n");
        
        char input[BUF_SIZE];
        size_t cur_size = 1;
        assembly = (char *)malloc(sizeof(char) * BUF_SIZE);

        if(assembly == NULL)
        {
            perror("malloc()");
            exit(1);
        }

        assembly[0] = '\0';

        while(fgets(input, BUF_SIZE, stdin))
        {
            char *aref = assembly;
            cur_size += strlen(input);
            assembly = (char *)realloc(assembly, cur_size);

            if(assembly == NULL) {
                perror("realloc()\n");
                free(aref);
                exit(-1);
            }

            strcat(assembly, input);
        }
    }

    assemble((ks_arch)arch, mode + endian, assembly, syntax);

    return 0;
}
