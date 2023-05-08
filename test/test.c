#include <stdio.h>

void print_string(char *s)
{
    printf("%s\n", s);
}

int main(int argc, char *argv[])
{
    print_string("Hello world1");
    print_string("Hello world2");
    print_string("Hello world3");

    printf("argc: %d\n", argc);

    for (int i = 0; i < argc; i++)
    {
        printf("arg#%d: \"%s\"\n", i, argv[i]);
    }

    return 0;
}