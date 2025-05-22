#include <stdio.h>
#include <stdlib.h>


void start_tracking();


void *my_malloc(size_t size);

int main() {
    // Start tracking
    start_tracking();

    // Allocate and free memory
    void *ptr1 = my_malloc(1024); 
    printf("Allocated memory at %p\n", ptr1);

    void *ptr2 = my_malloc(2048);
    printf("Allocated memory at %p\n", ptr2);

    free(ptr2);
    printf("Freed memory at %p\n", ptr2);

    // Intentionally leaking.....
    printf("Intentionally leaking memory at %p\n", ptr1);

    return 0;
}
