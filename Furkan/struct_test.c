#include <stdio.h>


int main() {
    int arr[3]={25,30,33};
    int *p = arr;

    printf("p = %p \n",p);

    printf("p + 1 = %p \n",p + 1);

    printf("p + 2 = %p \n",p + 2);

    printf("p + size of = %p \n ",p +sizeof(int));
}

