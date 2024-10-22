#include <stdlib.h>
// gcc -c -fno-pie -O3 stack_size.c stack_size_other.c; ld -lc -l  -dynamic-linker /lib64/ld-linux-x86-64.so.2 -r -o ss.o stack_size.o stack_size_other.o --entry main
// ld stack_size.o stack_size_other.o /lib/x86_64-linux-gnu/crt1.o /lib/x86_64-linux-gnu/crti.o /lib/x86_64-linux-gnu/crtn.o -lc -dynamic-linker /lib64/ld-linux-x86-64.so.2 -o ss.o 
// objdump -Sr ss.o | less
int recursion1(int n, int sum);

int
recursion2(int n, int sum)
{
	if(n == 0) return sum;
	sum = sum + n;

	return recursion1(n - 1, sum);

}

typedef int (*fn_t)(int, int);


int
functionpointer_tailcall(fn_t f, int a, int b)
{
	return f(a, b);
}

int
functionpointer(fn_t f, int a, int b)
{
	return f(a, b) + a + b;
}

int sum(int *arr, int sz);

int
dynamic_array1(int size)
{
	int *array = (int *)alloca(size * sizeof(int));
	int i;

	for (i = 0; i < size; i++) {
		array[i] = i * 2;
	}

	return sum(array, size); /* likely a tailcall */
}

int
dynamic_array2(int size)
{
	int array[size];
	int i;

	for (i = 0; i < size; i++) {
		array[i] = i * 2;
	}

	/* Prevent tailcalls on this one */
	return sum(array, size) + size;
}

int
static_array(void)
{
	int arr[16];
	int i;

	for (i = 0; i < 16; i++) {
		arr[i] = i * 2;
	}

	return sum(arr, 16);	/* tailcall */
}

int
static_array_large(void)
{
	int arr[1<<14];
	int i;

	for (i = 0; i < 16; i++) {
		arr[i] = i * 2;
	}

	return sum(arr, 16);	/* tailcall */
}

int add(int x, int y);
int multiply(int x, int y);

int
call(void)
{
	return add(5, 6) + multiply(5, 6) + 4;
}

int
tailcall(void)
{
	return add(5, 6);
}
