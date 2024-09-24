#include<stdio.h>

int main(){
    int b=1;
    int *a=&b;
    printf("%d    %p       %p   %p\n",*a,a,&a,&b);
}