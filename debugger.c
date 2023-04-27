#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
               (char *)(dynsymst + symt[i].st_name), symt[i].st_info, symt[i].st_other, symt[i].st_shndx,
               symt[i].st_value, symt[i].st_size);
    }
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
    char strBuf[256];

    while (1)
    {
        printf("\n(edb) ");
        fgets(strBuf, sizeof(strBuf), stdin);
        lntrim(strBuf);

        // quit
        if (strcmp(strBuf, "q") == 0)
        {
            break;
        }

        else if (strcmp(strBuf, "info") == 0)
            printHeaders(elfInfo);

        else if (strcmp(strBuf, "") == 0)
            continue;

        else
            printf("Command \"%s\" was not found\n", strBuf);
    }

    return true;
}