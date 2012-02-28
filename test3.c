#include <stdlib.h>

int main(int argc, char** argv)
{
    int a = 62394;
    int b = -340442;
    int c = a + b;
    c = c - a;
    b += c;
    c -= b;
    a = b + c;
}
