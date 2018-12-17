#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler(struct intr_frame *);

static int write(int fd, void *pVoid, unsigned int size);

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}



static void
syscall_handler(struct intr_frame *f UNUSED) {
    // get system call number
    // and for the given number of arguments we choose from syscall0/1/2/3
    // HOW TO SEND THE ENUM (SYSCALL NUMBER) TO syscall0/1/2/3 ????????
    switch (*(int *) (f->esp)) {
        case SYS_HALT : {
            break;
        }
        case SYS_EXIT : {
            break;
        }
        case SYS_EXEC : {
            break;
        }
        case SYS_WAIT : {
            break;
        }
        case SYS_CREATE : {
            break;
        }
        case SYS_REMOVE : {
            break;
        }
        case SYS_OPEN : {
            break;
        }
        case SYS_FILESIZE : {
            break;
        }
        case SYS_READ : {
            break;
        }
        case SYS_WRITE : {
            int fd =*((int*)f->esp + 1);
            void* buffer = (void*)(*((int*)f->esp + 2));
            unsigned size =*((unsigned*)f->esp + 3);
            //stored in f->eax
            f->eax = (uint32_t) write(fd, buffer, size);
            break;
        }
        case SYS_SEEK : {
            break;
        }
        case SYS_TELL : {
            break;
        }
        case SYS_CLOSE : {
            break;
        }

    }


/*
  printf ("system call!\n");
  thread_exit ();
*/
}

int write(int fd, void *pVoid, unsigned int size) {
    return 0;
}

