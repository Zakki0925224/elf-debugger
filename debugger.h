#include <elf.h>
#include <sys/user.h>
#include <stdint.h>
#include <stdbool.h>

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
    struct user_regs_struct regs;
} ElfInfo;

bool isValidElfFile(ElfInfo *elfInfo);
bool loadElf(char *filePath, ElfInfo *elfInfo);
void printHeaders(ElfInfo *elfInfo);
Elf64_Addr lookupSymbolAddrByName(char *name, ElfInfo *elfInfo);
bool shellMain(ElfInfo *elfInfo);