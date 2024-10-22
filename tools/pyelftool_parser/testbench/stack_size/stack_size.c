#include <stdio.h>
int recursion2(int n, int sum);

int
recursion1(int n, int sum)
{
	if(n == 0) return sum;
	sum = sum + n;

	return recursion2(n - 1, sum);

}

int
add(int x, int y)
{
	return x + y;
}

int
multiply(int x, int y)
{
	return x * y;
}


typedef int (*fn_t)(int, int);
int functionpointer_tailcall(fn_t f, int a, int b);
int functionpointer(fn_t f, int a, int b);

int dynamic_array1(int size);
int dynamic_array2(int size);

int
sum(int *arr, int sz)
{
	int i, s = 0;

	for (i = 0; i < sz; i++) {
		s += arr[i];
	}

	return s;
}

__attribute__((noinline)) int
should_fail(void)
{
	return recursion1(30, 0) + functionpointer(add, 1, 2) + functionpointer(multiply, 1, 2) + dynamic_array1(20) + dynamic_array2(20);
}

int call(void);
int tailcall(void);
int static_array(void);
int static_array_large(void);

__attribute__((noinline)) int
should_pass(void)
{
	return call() + tailcall() + static_array() + static_array_large();
}

int
main()
{
	int a = should_pass();
	int b = should_fail();
	printf("%d %d\n", a, b);

	return 0;
}
