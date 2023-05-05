#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>
#include "debugger.h"

bool isValidElfFile(ElfInfo *elfInfo)
{
    if (!(elfInfo->ehdr->e_ident[0] == ELFMAG0 &&
          elfInfo->ehdr->e_ident[1] == ELFMAG1 &&
          elfInfo->ehdr->e_ident[2] == ELFMAG2 &&
          elfInfo->ehdr->e_ident[3] == ELFMAG3))
    {
        fprintf(stderr, "This file is not ELF binary\n");
        return false;
    }

    if (elfInfo->ehdr->e_type != ET_EXEC)
    {
        fprintf(stderr, "This file is not executable ELF binary\n");
        return false;
    }

    if (elfInfo->ehdr->e_machine != EM_X86_64)
    {
        fprintf(stderr, "This file is not x86_64 ELF binary\n");
        return false;
    }

    if (elfInfo->ehdr->e_shstrndx == 0 || elfInfo->ehdr->e_shoff == 0 || elfInfo->ehdr->e_shnum == 0)
    {
        fprintf(stderr, "No section headers\n");
        return false;
    }

    return true;
}

bool loadElf(char *fileName, ElfInfo *elfInfo)
{
    FILE *fp;
    Elf64_Ehdr *ehdr = malloc(sizeof(Elf64_Ehdr));
    Elf64_Phdr *phdrs;
    Elf64_Shdr *shdrs;
    uint8_t *shst;
    uint8_t *symst;
    uint8_t *dynsymst;
    Elf64_Sym *symt;
    Elf64_Sym *dynsymt;

    elfInfo->dbgInfo.fileName = fileName;
    elfInfo->dbgInfo.pid = 0;

    fp = fopen(fileName, "r");

    if (fp == NULL)
        return false;

    // read ELF header
    fread(ehdr, sizeof(Elf64_Ehdr), 1, fp);
    elfInfo->ehdr = ehdr;

    if (!isValidElfFile(elfInfo))
        return false;

    // read program headers
    int phnum = elfInfo->ehdr->e_phnum;
    phdrs = malloc(sizeof(Elf64_Phdr) * phnum);
    fseek(fp, ehdr->e_phoff, SEEK_SET);
    fread(phdrs, sizeof(Elf64_Phdr) * phnum, 1, fp);
    elfInfo->phdrs = phdrs;

    // read section headers
    int shnum = elfInfo->ehdr->e_shnum;
    shdrs = malloc(sizeof(Elf64_Shdr) * shnum);
    fseek(fp, ehdr->e_shoff, SEEK_SET);
    fread(shdrs, sizeof(Elf64_Shdr) * shnum, 1, fp);
    elfInfo->shdrs = shdrs;

    // read section header string table
    uint64_t shst_size = shdrs[ehdr->e_shstrndx].sh_size;
    uint64_t shst_offset = shdrs[ehdr->e_shstrndx].sh_offset;
    shst = malloc(shst_size);
    fseek(fp, shst_offset, SEEK_SET);
    fread(shst, shst_size, 1, fp);
    elfInfo->shst = shst;

    // read symbol table
    bool foundSymt = false;
    for (int i = 0; i < ehdr->e_shnum; i++)
    {
        char *hdrname = (char *)(shst + shdrs[i].sh_name);
        if (strcmp(hdrname, ".symtab") == 0)
        {
            uint64_t symt_size = shdrs[i].sh_size;
            uint64_t symt_offset = shdrs[i].sh_offset;
            symt = malloc(symt_size);
            fseek(fp, symt_offset, SEEK_SET);
            fread(symt, symt_size, 1, fp);
            elfInfo->symt = symt;
            elfInfo->symtlen = symt_size / sizeof(Elf64_Sym);

            foundSymt = true;
            break;
        }
    }

    if (!foundSymt)
    {
        fprintf(stderr, "Symbol table was not found\n");
        return false;
    }

    // read symbol string table
    bool foundSymst = false;
    for (int i = 0; i < ehdr->e_shnum; i++)
    {
        char *hdrname = (char *)(shst + shdrs[i].sh_name);
        if (strcmp(hdrname, ".strtab") == 0)
        {
            uint64_t symst_size = shdrs[i].sh_size;
            uint64_t symst_offset = shdrs[i].sh_offset;
            symst = malloc(symst_size);
            fseek(fp, symst_offset, SEEK_SET);
            fread(symst, symst_size, 1, fp);
            elfInfo->symst = symst;

            foundSymst = true;
            break;
        }
    }

    if (!foundSymst)
    {
        fprintf(stderr, "Symbol string table was not found\n");
        return false;
    }

    // read dynamic symbol table
    elfInfo->hasDynsymt = false;
    for (int i = 0; i < ehdr->e_shnum; i++)
    {
        char *hdrname = (char *)(shst + shdrs[i].sh_name);
        if (strcmp(hdrname, ".dynsym") == 0)
        {
            uint64_t dynsymt_size = shdrs[i].sh_size;
            uint64_t dynsymt_offset = shdrs[i].sh_offset;
            dynsymt = malloc(dynsymt_size);
            fseek(fp, dynsymt_offset, SEEK_SET);
            fread(dynsymt, dynsymt_size, 1, fp);
            elfInfo->dynsymt = dynsymt;
            elfInfo->hasDynsymt = true;
            elfInfo->dynsymtlen = dynsymt_size / sizeof(Elf64_Sym);
            break;
        }
    }

    if (!elfInfo->hasDynsymt)
        printf("Dynamic symbol table was not found");

    else
    {
        // read dynamic symbol string table
        bool foundDynsymst = false;
        for (int i = 0; i < ehdr->e_shnum; i++)
        {
            char *hdrname = (char *)(shst + shdrs[i].sh_name);
            if (strcmp(hdrname, ".dynstr") == 0)
            {
                uint64_t dynsymst_size = shdrs[i].sh_size;
                uint64_t dynsymst_offset = shdrs[i].sh_offset;
                dynsymst = malloc(dynsymst_size);
                fseek(fp, dynsymst_offset, SEEK_SET);
                fread(dynsymst, dynsymst_size, 1, fp);
                elfInfo->dynsymst = dynsymst;

                foundDynsymst = true;
                break;
            }
        }

        if (!foundSymst)
        {
            fprintf(stderr, "Dynamic symbol string table was not found\n");
            return false;
        }
    }

    fclose(fp);

    // allocate breakpoints
    elfInfo->bps = malloc(sizeof(Elf64_Addr));
    elfInfo->bpslen = 0;

    return true;
}

void printHeaders(ElfInfo *elfInfo)
{
    Elf64_Ehdr *ehdr = elfInfo->ehdr;
    Elf64_Phdr *phdrs = elfInfo->phdrs;
    Elf64_Shdr *shdrs = elfInfo->shdrs;
    uint8_t *shst = elfInfo->shst;
    uint8_t *symst = elfInfo->symst;
    uint8_t *dynsymst = elfInfo->dynsymst;
    Elf64_Sym *symt = elfInfo->symt;
    Elf64_Sym *dynsymt = elfInfo->dynsymt;

    printf("ELF header: \n");
    printf("  Magic:\t\t\t\t");
    for (int i = 0; i < EI_NIDENT; i++)
    {
        printf("%02x ", ehdr->e_ident[i]);
    }
    printf("\n  Type:\t\t\t\t\t0x%x\n", ehdr->e_type);
    printf("  Architecture:\t\t\t\t0x%x\n", ehdr->e_machine);
    printf("  Version:\t\t\t\t0x%x\n", ehdr->e_version);
    printf("  Entry:\t\t\t\t0x%x\n", ehdr->e_entry);
    printf("  Program header table file offset:\t0x%x\n", ehdr->e_phoff);
    printf("  Section header table file offset:\t0x%x\n", ehdr->e_shoff);
    printf("  Flags:\t\t\t\t0x%x\n", ehdr->e_flags);
    printf("  ELF header size:\t\t\t%d bytes\n", ehdr->e_ehsize);
    printf("  Program header table entry size:\t%d bytes\n", ehdr->e_phentsize);
    printf("  Program header table entry count:\t%d\n", ehdr->e_phnum);
    printf("  Section header table entry size:\t%d bytes\n", ehdr->e_shentsize);
    printf("  Section header table entry count:\t%d\n", ehdr->e_shnum);
    printf("  Section header string table index:\t%d\n", ehdr->e_shstrndx);

    printf("\nProgram headers: \n");
    printf("  Type         Flags        Offset      Virt addr     Phys addr     File size    Mem size    Align\n");
    for (int i = 0; i < ehdr->e_phnum; i++)
    {
        printf("  0x%-8x   0x%-8x   0x%-8x  0x%-8x    0x%-8x    %-8d     %-8d    %-8d\n",
               phdrs[i].p_type, phdrs[i].p_flags, phdrs[i].p_offset, phdrs[i].p_vaddr,
               phdrs[i].p_paddr, phdrs[i].p_filesz, phdrs[i].p_memsz, phdrs[i].p_align);
    }

    printf("\nSection headers: \n");
    printf("  Name                 Type       Flags      Addr       Offset     Size      Link     Info     Align      Entry size\n");
    for (int i = 0; i < ehdr->e_shnum; i++)
    {
        printf("  %-20s 0x%-8x 0x%-8x 0x%-8x 0x%-8x %-8d  %-8d %-8d 0x%-8x %-8d\n",
               (char *)(shst + shdrs[i].sh_name), shdrs[i].sh_type, shdrs[i].sh_flags,
               shdrs[i].sh_addr, shdrs[i].sh_offset, shdrs[i].sh_size,
               shdrs[i].sh_link, shdrs[i].sh_info, shdrs[i].sh_addralign, shdrs[i].sh_entsize);
    }

    printf("\nSymbol table entries: \n");
    printf("  Name                           Info       Other      Sh index Value      Size\n");
    for (int i = 0; i < elfInfo->symtlen; i++)
    {
        printf("  %-30s 0x%-8x 0x%-8x %-8d 0x%-8x %-8d\n",
               (char *)(symst + symt[i].st_name), symt[i].st_info, symt[i].st_other, symt[i].st_shndx,
               symt[i].st_value, symt[i].st_size);
    }

    if (!elfInfo->hasDynsymt)
        return;

    printf("\nDynamic symbol table entries: \n");
    printf("  Name                           Info       Other      Sh index Value      Size\n");
    for (int i = 0; i < elfInfo->dynsymtlen; i++)
    {
        printf("  %-30s 0x%-8x 0x%-8x %-8d 0x%-8x %-8d\n",
               (char *)(dynsymst + dynsymt[i].st_name), dynsymt[i].st_info, dynsymt[i].st_other, dynsymt[i].st_shndx,
               dynsymt[i].st_value, dynsymt[i].st_size);
    }
}

Elf64_Addr lookupSymbolAddrByName(char *name, ElfInfo *elfInfo)
{
    uint8_t *symst = elfInfo->symst;
    uint8_t *dynsymst = elfInfo->dynsymst;
    Elf64_Sym *symt = elfInfo->symt;
    Elf64_Sym *dynsymt = elfInfo->dynsymt;
    uint16_t nameLen = 0;
    Elf64_Addr addr = ULONG_MAX;

    for (int i = 0; name[i] != '\0'; i++)
    {
        nameLen++;
    }

    // lookup from symbol table
    for (int i = 0; i < elfInfo->symtlen; i++)
    {
        char *symname = (char *)(symst + symt[i].st_name);
        if (strcmp(name, symname) == 0)
        {
            addr = symt[i].st_value;
            break;
        }
    }

    if (addr < ULONG_MAX)
        return addr;

    // lookup from dynamic symbol table
    for (int i = 0; i < elfInfo->dynsymtlen; i++)
    {
        char *symname = (char *)(dynsymst + symt[i].st_name);
        if (strcmp(name, symname) == 0)
        {
            addr = dynsymt[i].st_value;
            break;
        }
    }

    return addr;
}

void setBreakpoint(Elf64_Addr addr, ElfInfo *elfInfo)
{
    Breakpoint *bps = elfInfo->bps;
    uint64_t bpslen = elfInfo->bpslen;

    for (int i = 0; i < bpslen; i++)
    {
        if (bps[i].addr == addr)
        {
            printf("Breakpoint (0x%x) is already set at #%d\n", addr, i);
            return;
        }
    }

    bps[bpslen].addr = addr;
    bps = realloc(bps, sizeof(Elf64_Addr) * (bpslen + 2));
    elfInfo->bps = bps;
    elfInfo->bpslen = bpslen + 1;

    printf("Set breakpoint (#%d) at 0x%x\n", bpslen, addr);
}

void printBreakpoints(ElfInfo *elfInfo)
{
    Breakpoint *bps = elfInfo->bps;
    uint64_t bpslen = elfInfo->bpslen;

    for (int i = 0; i < bpslen; i++)
    {
        printf("#%d - 0x%x\n", i, bps[i].addr);
    }
}

void execute(ElfInfo *elfInfo, char *args[])
{
    pid_t pid = fork();
    if (pid > 0) // parent
    {
        printf("Running at pid: %d\n", pid);
        elfInfo->dbgInfo.pid = pid;

        int status;
        pid_t child_pid = wait(&status);
        WIFEXITED(status);
        printf("Child process (pid: %d) exited with status %d\n", child_pid, status);
    }
    else if (pid == 0) // child
    {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execve(elfInfo->dbgInfo.fileName, args, NULL);
        exit(EXIT_SUCCESS);
    }
    else
        printf("Failed to fork process\n");
}

void lntrim(char *str)
{
    char *p;
    p = strchr(str, '\n');
    if (p != NULL)
    {
        *p = '\0';
    }
}

bool shellMain(ElfInfo *elfInfo)
{
    int bufLen = 256;
    char tmp[bufLen];
    char strBuf[bufLen];

    while (1)
    {
        printf("\n(edb) ");
        fgets(strBuf, sizeof(char) * bufLen, stdin);
        lntrim(strBuf);
        memcpy(tmp, strBuf, sizeof(char) * bufLen);
        char *token = strtok(strBuf, " ");

        // quit
        if (strcmp(token, "quit") == 0 || strcmp(token, "q") == 0)
            break;

        else if (strcmp(token, "info") == 0 || strcmp(token, "i") == 0)
            printHeaders(elfInfo);

        else if (strcmp(token, "lookup") == 0 || strcmp(token, "l") == 0)
        {
            for (int i = 0; token != NULL; i++)
            {
                if (i != 0)
                {
                    Elf64_Addr addr = lookupSymbolAddrByName(token, elfInfo);
                    if (addr == ULONG_MAX)
                        printf("Symbol name \"%s\" was not found\n", token);
                    else
                        printf("\"%s\": 0x%x\n", token, addr);
                }

                token = strtok(NULL, " ");
            }
        }

        else if (strcmp(token, "breakpoint") == 0 || strcmp(token, "b") == 0)
        {
            bool isPrintBps = true;

            for (int i = 0; token != NULL; i++)
            {
                if (i != 0)
                {
                    Elf64_Addr addr = lookupSymbolAddrByName(token, elfInfo);
                    if (addr == ULONG_MAX)
                        printf("Symbol name \"%s\" was not found\n", token);
                    else
                        setBreakpoint(addr, elfInfo);

                    isPrintBps = false;
                }

                token = strtok(NULL, " ");
            }

            if (isPrintBps)
                printBreakpoints(elfInfo);
        }

        else if (strcmp(token, "run") == 0 || strcmp(token, "r") == 0)
        {
            int argsLen = 0;
            bool isPrevSpace = false;
            for (int i = 0; tmp[i] != '\0'; i++)
            {
                if (tmp[i] == ' ')
                {
                    isPrevSpace = true;
                    continue;
                }

                if (isPrevSpace)
                    argsLen++;

                isPrevSpace = false;
            }

            char *args[argsLen];
            char *argToken = strtok(tmp, " ");

            for (int i = 0; argToken != NULL; i++)
            {
                if (i != 0)
                {
                    args[i - 1] = argToken;
                }

                argToken = strtok(NULL, " ");
            }

            execute(elfInfo, args);
        }

        else if (strcmp(token, "help") == 0 || strcmp(token, "h") == 0)
        {
            printf("help, h - Show EDB commands.\n");
            printf("quit, q - Quit EDB.\n");
            printf("info, i - Show loaded ELF binary info, program headers, section headers and symbol table entries.\n");
            printf("lookup, l - Lookup symbol address by name. Ex: \"lookup _init _start\"\n");
            printf("breakpoint, b - Set breakpoint by symbol name. If none of args passed, show all breakpoints. Ex: \"bp _init _start\"\n");
            printf("run, r - Run ELF binary. You can append args for target process. Ex: \"run 0 1 2\"\n");
        }

        else if (strcmp(token, "") == 0)
            continue;

        else
            printf("Command \"%s\" was not found\n", token);
    }

    return true;
}