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

    fclose(fp);

    return true;
}

void printHeaders(ElfInfo *elfInfo)
{
    Elf64_Ehdr *ehdr = elfInfo->ehdr;
    Elf64_Phdr *phdrs = elfInfo->phdrs;
    Elf64_Shdr *shdrs = elfInfo->shdrs;
    uint8_t *shst = elfInfo->shst;

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
               ((char *)(shst + shdrs[i].sh_name)), shdrs[i].sh_type, shdrs[i].sh_flags,
               shdrs[i].sh_addr, shdrs[i].sh_offset, shdrs[i].sh_size,
               shdrs[i].sh_link, shdrs[i].sh_info, shdrs[i].sh_addralign, shdrs[i].sh_entsize);
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