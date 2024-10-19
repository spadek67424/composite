#include <stdio.h>
#include <stdlib.h>


int recursion(int n, int sum) {
    if(n == 0) {
        return sum;
    }
    sum = sum + n;
    return recursion(n - 1, sum);

}
int add(int x, int y) {
    return x + y;
}
int multiply(int x, int y){
    return x * y;
}

int functionpointer() {
    int (*function)(int, int);
    
    function = add;
    int temp = (*function)(3, 4);


    function = multiply;
    temp = (*function)(temp, temp + 4);
    return temp;
}

void dynamicArray(int size) {
    // Allocate memory on the stack for an array of integers
    int *array = (int *)alloca(size * sizeof(int));

    // Initialize and display the array
    for (int i = 0; i < size; i++) {
        array[i] = i * 2;  // Just filling it with some values
        printf("array[%d] = %d\n", i, array[i]);
    }

    // No need to free memory here, it's automatically freed when the function returns
}

int main() {
    int sum = recursion(30, 0);
    printf("%d\n", sum);
    sum = functionpointer();
    printf("%d\n", sum);
    dynamicArray(20);
}