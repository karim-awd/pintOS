#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <threads/vaddr.h>
#include <filesys/filesys.h>
#include <devices/shutdown.h>
#include <threads/malloc.h>
#include <filesys/file.h>
#include <devices/input.h>
#include <lib/user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "list.h"
#include "process.h"
#include <string.h>

void halt();
void exit(int status);
pid_t exec(const char* cmd_line);
int wait(pid_t pid);
bool create(const char* file, unsigned initial_size);
bool remove(const char* file);
int open(const char* file);
int filesize (int fd);
int read (int fd, void* buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size) ;
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
static void syscall_handler(struct intr_frame *);
bool validate(void* ptr , int argumentsNum);

//todo note that you send f->esp (void*) and recive an (int*);

struct created_file_entry {
    const char *name;
    struct list_elem elem;
};


struct opened_file_entry {
    struct file * file;
    const char *name;
    int fd;
    struct list_elem elem;
};
struct created_file_entry* list_search_created(struct list* files, const char *name)
{

    struct list_elem *e;

    for (e = list_begin (files); e != list_end (files);
         e = list_next (e))
    {
        struct created_file_entry *f = list_entry (e, struct created_file_entry, elem);
        if(strcmp(f->name , name))
            return f;
    }
    return NULL;
}

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

struct opened_file_entry* list_search_name(struct list* files, char* name)
{

    struct list_elem *e;

    for (e = list_begin (files); e != list_end (files);
         e = list_next (e))
    {
        struct opened_file_entry *f = list_entry (e, struct opened_file_entry, elem);
        if(f->name == name)
            return f;
    }
    return NULL;
}



void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}



static void
syscall_handler(struct intr_frame *f UNUSED) {
    // get system call number

    //validation
    if(!validate(f->esp, 1)){  // bad pointer
        exit(-1);
    }


    switch (*(int *)(f->esp)) {
        case SYS_HALT : {
            halt();
            break;
        }
        case SYS_EXIT : {                             /////
            if(!validate(f->esp+4,1)){
                exit(-1);
            }
            int status = *(int*)(f->esp+4);
            exit(status);

            break;
        }
        case SYS_EXEC : {
            if(!validate(f->esp+4,1)) {
                exit(-1);
            }
            const char* cmd_line = (const char*)(*(int*)(f->esp+4));  //todo char* from int warning
            f->eax = (uint32_t) exec(cmd_line);
            break;
        }
        case SYS_WAIT : {
            if(!validate(f->esp+4,1)){
                exit(-1);
            }
            acquire_files_lock();
            f->eax = wait(*(int*)(f->esp+4));
            release_files_lock();
            break;
        }
        case SYS_CREATE : {
            if(!validate(f->esp+4,2)){
                exit(-1);
            }
            const char* file =(const char*)*((int*)(f->esp+4));         //todo char* from int warning
            unsigned initial_size = *((unsigned *)(f->esp+4));
            acquire_files_lock();
            f->eax = (uint32_t) create(file, initial_size);
            release_files_lock();
            break;
        }
        case SYS_REMOVE : {
            if(!validate(f->esp+4,1)){
                exit(-1);
            }
            acquire_files_lock();
            f->eax = (uint32_t) remove((const char*)(f->esp+4));
            release_files_lock();
            break;
        }
        case SYS_OPEN : {
            if(!validate(f->esp+4,1)){
                exit(-1);
            }
            const char* file = (const char*)*((int*)(f->esp+4));       //todo char* from int warning
            acquire_files_lock();
            f->eax = (uint32_t) open(file);
            release_files_lock();
            break;
        }
        case SYS_FILESIZE : {
            if(!validate(f->esp+4,1)){
                exit(-1);
            }
            int fd = *((int*)(f->esp+4));
            acquire_files_lock();
            f->eax = (uint32_t) filesize(fd);
            release_files_lock();
            break;
        }
        case SYS_READ : {
            if(!validate(f->esp+4,3)){
                exit(-1);
            }
            int fd = *((int*)(f->esp+4));
            void* buffer = (void*)(*((int*)(f->esp+8)));
            unsigned size =*((unsigned*)(f->esp+12));
            acquire_files_lock();
            f->eax = (uint32_t)read(fd,buffer,size);
            release_files_lock();
            break;
        }
        case SYS_WRITE : {

            if(!validate(((int*)f->esp+4),3)){
                exit(-1);
            }

            int fd =*((int*)(f->esp+4));
            void* buffer = (void*)(*((int*)(f->esp+8)));
            unsigned size =*((unsigned*)(f->esp+12));
            acquire_files_lock();
            f->eax = (uint32_t) write(fd, buffer, size);
            release_files_lock();
            break;
        }
        case SYS_SEEK : {
            if(!validate(f->esp+4,2)){
                exit(-1);
            }
            int fd = *((int*)(f->esp+4));
            unsigned position =(unsigned)(*(int*)(f->esp+8));
            acquire_files_lock();
            seek(fd,position);
            release_files_lock();
            break;
        }
        case SYS_TELL : {
            if(!validate(f->esp+4,1)){
                exit(-1);
            }
            acquire_files_lock();
            f->eax = tell(*((int*)(f->esp+4)));
            release_files_lock();
            break;
        }
        case SYS_CLOSE : {
            if(!validate(f->esp+4,1)){
                exit(-1);
            }
            int fd = *(int*)(f->esp+4);
            acquire_files_lock();
            close(fd);
            release_files_lock();
            break;
        }

    }


/*
  printf ("system call!\n");
  thread_exit ();
*/
}
void halt(){
    shutdown_power_off();
}

void exit(int status){
    thread_exit(status);
}

pid_t exec(const char* cmd_line){
    if(!validate(cmd_line,1)){
        exit(-1);
    }
    pid_t newId = process_execute(cmd_line);
    /* todo he parent process cannot return from the exec
     until it knows whether the child process
     successfully loaded its executable
    */
    //wait(newId);
    if(newId == TID_ERROR){
        return -1;
    }

    return newId;
}

int wait(pid_t pid){
    return process_wait(pid);
}

bool create(const char* file, unsigned initial_size){
    if(!validate(file,1)){
        exit(-1);
    }
    struct created_file_entry *created_file_entry = list_search_created(&thread_current()->created_files,file);
    if(created_file_entry != NULL){
        return filesys_create(file, initial_size);       // new create fails
    }
    else{
        if(filesys_create(file, initial_size)){
            created_file_entry = malloc(sizeof(*created_file_entry));
            created_file_entry->name = file;
            list_push_back(&thread_current()->created_files, &created_file_entry->elem);
            return true;
        }
        else{
            return false;
        }
    }
    return false;
}

bool remove(const char* file){
    //todo if wrong
    /**
     * Remove the file but keep it for all running processes currently using it
     * if there are descriptors associtaed with the File file then delay its removal
     * until they close it
     */
    return filesys_remove(file);
}

int open (const char *file){
    if(!validate(file,1)){
        exit(-1);
    }
    struct file * openedFile = filesys_open(file);
    if (openedFile == NULL)
        return -1;
    else{
        struct opened_file_entry *file_entry = malloc(sizeof(*file_entry));
        file_entry->file = openedFile;
        file_entry->fd = thread_current()->fd_value;
        file_entry->name = file;
        thread_current()->fd_value ++;
        list_push_back(&thread_current()->opened_files, &file_entry->elem);
        return file_entry->fd;
    }
}

int filesize (int fd){
    return file_length(list_search(&thread_current()->opened_files,fd)->file);
}

int read (int fd, void* buffer, unsigned size){
    if(!validate(buffer,1) || fd==1){
        exit(-1);
    }
    uint8_t* buf = (uint8_t*) buffer;
    if (fd == 0){
        for (int i= 0; i< size; i++){
            buf[i] =  input_getc();
        }
        return size;
    }
    else {
        struct opened_file_entry *readFromFileEntry = list_search(&thread_current()->opened_files,fd);
        if (readFromFileEntry== NULL)
            return -1;
        else {
            return file_read(readFromFileEntry->file,buf,size);
        }
    }


}

int write(int fd, const void *buffer, unsigned size)  {
    if (!validate(buffer, 1) || fd == 0 || fd < 0) {
        exit(-1);
    }
    if(fd == 1 ){
        putbuf(buffer,size);
        return size;                 // todo there is no limit on size when using putbuf
    }
    struct opened_file_entry *currentFileEntry = list_search(&thread_current()->opened_files, fd);
    if (currentFileEntry == NULL) {
        return 0;
    }
    struct file *currentFile = currentFileEntry->file;
    return file_write(currentFile, buffer, size);// size in file_write is off_t  and the return is off_t
}

void seek(int fd, unsigned position){
    struct opened_file_entry *currentFileEntry = list_search(&thread_current()->opened_files, fd);
    if (currentFileEntry == NULL) {
        exit(-1);
    }
    struct file *currentFile = currentFileEntry->file;
    if(currentFile!=NULL){
        if(position <= 0){
            position = 0;
        }
        file_seek(currentFile,position);
    }
}

unsigned tell(int fd){
    struct opened_file_entry *currentFileEntry = list_search(&thread_current()->opened_files, fd);
    if (currentFileEntry == NULL) {
        exit(-1);
    }
    struct file *currentFile = currentFileEntry->file;
    if(currentFile != NULL){
        return (unsigned)file_tell(currentFile);
    }
}

void close(int fd){
    if(fd ==0 || fd == 1 || fd < 0){
        exit(-1);
    }
    struct opened_file_entry * currentFileEntery = list_search(&thread_current()->opened_files,fd);
    if(currentFileEntery != NULL) {
        struct file * currentFile = currentFileEntery->file;
        if (currentFile != NULL) {
            file_close(currentFile);
            list_remove(&currentFileEntery->elem);
        }
    }

}


bool
validate(void* ptr , int argumentsNum){
    for (int argumentIndex = 0; argumentIndex < (argumentsNum*4) ; argumentIndex++) {
        void* currentPtr =ptr+argumentIndex;
        if (currentPtr != NULL && currentPtr>0) {  // Null Check
            if(is_user_vaddr(currentPtr)){   // in User Virtual Memory space check
                //uint32_t* pd = active_pd();                                   // in a page
                if(pagedir_get_page(thread_current()->pagedir,currentPtr) != NULL){
                    return true;
                }
            }
        }

    }
    return false;
}



