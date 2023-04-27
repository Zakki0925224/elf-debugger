#include <elf.h>
#include <sys/user.h>
#include <stdbool.h>

typedef struct
{
    Elf64_Ehdr *ehdr;  // ELF header
    Elf64_Phdr *phdrs; // program headers
    Elf64_Shdr *shdrs; // section headers
    struct user_regs_struct regs;
} ElfInfo;

bool isValidElfFile(ElfInfo *elfInfo);
bool loadElf(char *filePath, ElfInfo *elfInfo);
void printHeaders(ElfInfo *elfInfo);
bool shellMain(ElfInfo *elfInfo);