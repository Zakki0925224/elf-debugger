#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

void printRegisters(int pid)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    printf("Registers: \n");
    printf("rbp   : 0x%llx\n", regs.rbp);
    printf("rbx   : 0x%llx\n", regs.rbx);
    printf("rax   : 0x%llx\n", regs.rax);
    printf("rcx   : 0x%llx\n", regs.rcx);
    printf("rdx   : 0x%llx\n", regs.rdx);
    printf("rsi   : 0x%llx\n", regs.rsi);
    printf("rdi   : 0x%llx\n", regs.rdi);
    printf("rip   : 0x%llx\n", regs.rip);
    printf("cs    : 0x%llx\n", regs.cs);
    printf("eflags: 0x%llx\n", regs.eflags);
    printf("rsp   : 0x%llx\n", regs.rsp);
    printf("ss    : 0x%llx\n", regs.ss);
    printf("ds    : 0x%llx\n", regs.ds);
    printf("es    : 0x%llx\n", regs.es);
    printf("fs    : 0x%llx\n", regs.fs);
    printf("gs    : 0x%llx\n", regs.gs);
}

int main(int argc, char *argv[])
{
    int pid, p_status;
    long tr_ret;

    if (argc != 2)
    {
        fprintf(stderr, "Invalid arguments\n");
        exit(1);
    }

    pid = atoi(argv[1]);

    if (pid == 0)
    {
        fprintf(stderr, "Failed to parse pid: \"%s\"\n", argv[1]);
        exit(1);
    }

    printf("Attach to pid: %d\n", pid);

    tr_ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);

    if (tr_ret < 0)
    {
        perror("Failed to attach");
        exit(1);
    }

    printf("Attached! (ret: %ld)\n", tr_ret);

    while (1)
    {
        waitpid(pid, &p_status, 0);

        if (WIFEXITED(p_status))
            break;

        else if (WIFSTOPPED(p_status))
        {
            printRegisters(pid);
        }

        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    }

    tr_ret = ptrace(PTRACE_DETACH, pid, NULL, NULL);

    if (tr_ret < 0)
    {
        perror("Failed to detach");
        exit(1);
    }

    printf("Detached! (ret: %ld)\n", tr_ret);

    return 0;
}