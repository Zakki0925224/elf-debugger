#include <elf.h>
#include <sys/user.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

#define OPCODE_INT3 0xcc

typedef struct
{
    Elf64_Addr addr;
} Breakpoint;

typedef struct
{
    char *fileName;
    pid_t pid;
    struct user_regs_struct regs;
} DebugInfo;

typedef struct
{
    Elf64_Ehdr *ehdr;   // ELF header
    Elf64_Phdr *phdrs;  // program headers
    Elf64_Shdr *shdrs;  // section headers
    uint8_t *shst;      // section header string table
    Elf64_Sym *symt;    // symbol table
    Elf64_Sym *dynsymt; // dynamic symbol table
    bool hasDynsymt;
    uint64_t symtlen;
    uint64_t dynsymtlen;
    uint8_t *symst;    // symbol string table
    uint8_t *dynsymst; // dynamic symbol string table

    Breakpoint *bps;  // breakpoints
    u_int64_t *bpins; // original instructions at breakpoints
    uint64_t bpslen;

    DebugInfo dbgInfo;
} ElfInfo;

bool isValidElfFile(ElfInfo *elfInfo);
bool loadElf(char *filePath, ElfInfo *elfInfo);
void printHeaders(ElfInfo *elfInfo);
Elf64_Addr lookupSymbolAddrByName(char *name, ElfInfo *elfInfo);
void setBreakpoint(Elf64_Addr addr, ElfInfo *elfInfo);
void printBreakpoints(ElfInfo *elfInfo);
void printRegisters(ElfInfo *elfInfo);
void trace(ElfInfo *elfInfo);
void execute(ElfInfo *elfInfo, char *args[]);
bool shellMain(ElfInfo *elfInfo);