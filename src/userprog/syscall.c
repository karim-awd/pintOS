#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <threads/vaddr.h>
#include <filesys/filesys.h>
#include <threads/malloc.h>
#include <filesys/file.h>
#include <devices/input.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "list.h"
#include "process.h"

struct opened_file_entry {
    struct file * file;
    int fd;
    struct list_elem elem;
};

struct opened_file_entry* list_search(struct list* files, int fd)
{

    struct list_elem *e;

    for (e = list_begin (files); e != list_end (files);
         e = list_next (e))
    {
        struct opened_file_entry *f = list_entry (e, struct opened_file_entry, elem);
        if(f->fd == fd)
            return f;
    }
    return NULL;
}



static void syscall_handler(struct intr_frame *);
bool validate(int* ptr , int argumentsNum);
static int write(int fd, void *pVoid, unsigned int size);




void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}



static void
syscall_handler(struct intr_frame *f UNUSED) {
    // get system call number

    //validation
    if(!validate(f->esp, 1)){  // bad pointer
        //exit(-1);
    }


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

            validate(((int*)f->esp +1),3);

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

bool create (const char* file, unsigned initial_size){
    return filesys_create(file, initial_size);
}


int
read (int fd, uint8_t* buffer, unsigned size){

    if (fd == 0){
        for (int i= 0; i< size; i++){
            buffer[i] =  input_getc();
        }
        return size;
    }
    else {
        struct opened_file_entry *readFromFileEntry = list_search(&thread_current()->opened_files,fd);
        if (readFromFileEntry== NULL)
            return -1;
        else {
            return file_read(readFromFileEntry->file,buffer,size);
        }
    }


}


int write(int fd, void *pVoid, unsigned int size) {
    return 0;
}



int open (const char *file){
    struct file * openedFile = filesys_open(filesys_open);
    if (openedFile == NULL)
        return -1;
    else{

        struct opened_file_entry *file_entry = malloc(sizeof(*file_entry));
        file_entry->file = openedFile;
        file_entry->fd = thread_current()->fd_value;
        thread_current()->fd_value ++;
        list_push_back(&thread_current()->opened_files, &file_entry->elem);
        return file_entry->fd;
    }
}

int filesize (int fd){
    return file_length(list_search(&thread_current()->opened_files,fd)->file);
}



bool
validate(int* ptr , int argumentsNum){
    for (int argumentIndex = 0; argumentIndex < argumentsNum ; argumentIndex++) {
        int* currentPtr =ptr+argumentIndex;
        if (currentPtr != NULL) {  // Null Check
            if(is_user_vaddr(currentPtr)){   // in User Virtual Memory space check
                uint32_t* pd = active_pd();                                   // in a page
                if(pagedir_get_page(pd,currentPtr) != NULL){
                    return true;
                }
            }
        }

    }
    return false;
}



