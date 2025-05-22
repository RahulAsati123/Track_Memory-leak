#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdatomic.h>


#define __NR_track_user_memory 451


//OpCode.....
#define OP_START_TRACKING 0
#define OP_TRACK_ALLOCATION 1
#define OP_TRACK_DEALLOCATION 2


long track_user_memory(pid_t pid, int operation, void *address, size_t size) {
    return syscall(__NR_track_user_memory, pid, operation, address, size);
}

static atomic_int tracking_enabled = 0;


static __thread int program_allocation = 0;

//wrapper for malloc
void *malloc(size_t size) {
    static void *(*real_malloc)(size_t) = NULL;
    if (!real_malloc) {
        real_malloc = dlsym(RTLD_NEXT, "malloc");
    }

    void *ptr = real_malloc(size);
    if (ptr && tracking_enabled && program_allocation) {
        // Debug print 
        printf("Allocated memory: Address=%p, Size=%zu bytes\n", ptr, size);

       
        if (track_user_memory(getpid(), OP_TRACK_ALLOCATION, ptr, size) < 0) {
            fprintf(stderr, "Failed to track allocation for %p\n", ptr);
        }
    }
    return ptr;
}

// Wrapper for free
void free(void *ptr) {
    static void (*real_free)(void *) = NULL;
    if (!real_free) {
        real_free = dlsym(RTLD_NEXT, "free");
    }

    if (ptr && tracking_enabled) {
        // Debug print 
        printf("Freeing memory: Address=%p\n", ptr);

      
        if (track_user_memory(getpid(), OP_TRACK_DEALLOCATION, ptr, 0) < 0) {
            fprintf(stderr, "Failed to track deallocation for %p\n", ptr);
        }
    }


    real_free(ptr);
}

// Function to enable tracking
void start_tracking() {
    pid_t pid = getpid();
    if (track_user_memory(pid, OP_START_TRACKING, NULL, 0) == 0) {
        tracking_enabled = 1;
        printf("Tracking enabled for PID %d\n", pid);
    } else {
        perror("Failed to start tracking");
    }
}

// Custom malloc function to mark program allocations
void *my_malloc(size_t size) {
    program_allocation = 1; 
    void *ptr = malloc(size);
    program_allocation = 0; 
    return ptr;
}
