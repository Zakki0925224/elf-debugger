#include <stdio.h>
#include <stdlib.h>
#include "debugger.h"

int main(int argc, char *argv[])
{
    ElfInfo *elfInfo;

    if (argc != 2)
    {
        fprintf(stderr, "Invalid arguments\n");
        exit(1);
    }

    if (!loadElf(argv[1], elfInfo))
    {
        fprintf(stderr, "Failed to load ELF binary\n");
        exit(1);
    }

    if (!shellMain(elfInfo))
    {
        exit(1);
    }

    free(elfInfo->ehdr);
    free(elfInfo->phdrs);
    free(elfInfo->shdrs);
    free(elfInfo->shst);
    free(elfInfo->dynsymt);
    free(elfInfo->symst);
    free(elfInfo->dynsymst);
    free(elfInfo->dbgInfo.bps);

    return 0;
}
