#include <elf.h>
#include <sys/user.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct
{
    Elf64_Ehdr *ehdr;  // ELF header
    Elf64_Phdr *phdrs; // program headers
    Elf64_Shdr *shdrs; // section headers
    uint8_t *shst;     // section header string table
    struct user_regs_struct regs;
} ElfInfo;

bool isValidElfFile(ElfInfo *elfInfo);
bool loadElf(char *filePath, ElfInfo *elfInfo);
void printHeaders(ElfInfo *elfInfo);
bool shellMain(ElfInfo *elfInfo);