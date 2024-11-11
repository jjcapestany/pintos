#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/syscall.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <filesys/filesys.h>

static void syscall_handler(struct intr_frame *);
void sys_halt(void);
void sys_exit(int status);
int sys_write(int fd, char *buffer, unsigned size);
int sys_read(int fd, void *buffer, unsigned size);
int sys_open(const char *file_name);

static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

void
syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{


    /* Remove these when implementing syscalls */
    int * usp = f->esp;

    if (!is_user_vaddr(usp) || pagedir_get_page(thread_current()->pagedir,usp) == NULL) {
        sys_exit(-1);
    }

    int sys_call = *usp;

    switch (sys_call) {
        case SYS_HALT:
            sys_halt();
            break;
        case SYS_EXIT:
            if (!is_user_vaddr(usp + 1) || get_user((uint8_t *)usp + 1) == -1) sys_exit(-1);
            sys_exit(*(usp + 1));
            break;
        case SYS_EXEC:
            break;
        case SYS_WAIT:
            break;
        case SYS_CREATE:
            break;
        case SYS_REMOVE:
            break;
        case SYS_OPEN: {
                const char *file_name = (const char *)*(usp+1);
                if (!is_user_vaddr(file_name)) sys_exit(-1);
                if (file_name == NULL) sys_exit(-1);
                f->eax = sys_open(file_name);
            }
            break;
        case SYS_FILESIZE:
            break;
        case SYS_READ:
            f ->eax = sys_read(*(usp+1), (void*)*(usp+2), *(usp+3));
            break;
        case SYS_WRITE:
            f->eax = sys_write(*(usp+1), (char*)*(usp+2), *(usp+3));
            break;
        case SYS_SEEK:
            break;
        case SYS_TELL:
            break;
        case SYS_CLOSE:
            break;
        default:
            sys_exit(-1);
            break;
        }
}

void sys_halt(void) {
    shutdown_power_off();
}

int sys_open(const char *file_name){
    if(strcmp(file_name, "") == 0) return -1;
    struct file *file = filesys_open(file_name);
    if(file == NULL) sys_exit(-1);
    int fd = 2;
    fd++;
    return fd;
}

void sys_exit(int status){
    struct thread *cur = thread_current();
    cur->exitStatus = status;
    printf("%s: exit(%d)\n", cur->name, status);
    thread_exit();

}

int sys_write(int fd, char *buffer, unsigned size) {
    if (
        !is_user_vaddr(buffer)
        || pagedir_get_page(thread_current()->pagedir, buffer) == NULL
        || !is_user_vaddr(buffer + size)
        ||   pagedir_get_page(thread_current()->pagedir, buffer + size) == NULL
        ) sys_exit(-1);

    if (fd == 1) {
        putbuf(buffer, size);
        return size;
    }
    return -1;
}

int sys_read(int fd, void *buffer, unsigned size) {
    if (
        !is_user_vaddr(buffer)
        || pagedir_get_page(thread_current()->pagedir, buffer) == NULL
        || !is_user_vaddr(buffer + size)
        ||   pagedir_get_page(thread_current()->pagedir, buffer + size) == NULL
        ) sys_exit(-1);

    if (fd == 0) {
        unsigned i;
        for (i = 0; i < size; i++) {
            if (!put_user(((uint8_t *)buffer) + i, input_getc())) sys_exit(-1);
        }
        return size;
    }
    return -1;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}