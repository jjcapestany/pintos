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
#include <string.h>

static void syscall_handler(struct intr_frame *);
void sys_halt(void);
void sys_exit(int status);
int sys_write(int fd, char *buffer, unsigned size);
int sys_read(int fd, void *buffer, unsigned size);
int sys_open(const char *file_name);
bool sys_create(const char *file, unsigned initial_size);

static int get_user(const uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);
void check_user_vaddr(const void *vaddr);
void check_user_string(const char *str);

void
syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
    int *usp = f->esp;

    if (!is_user_vaddr(usp) || pagedir_get_page(thread_current()->pagedir, usp) == NULL) {
        sys_exit(-1);
    }

    int sys_call = *usp;

    switch (sys_call) {
        case SYS_HALT:
            sys_halt();
            break;
        case SYS_EXIT:
            if (!is_user_vaddr(usp + 1) || get_user((uint8_t *)(usp + 1)) == -1) sys_exit(-1);
            sys_exit(*(usp + 1));
            break;
        case SYS_EXEC:
            break;
        case SYS_WAIT:
            break;
        case SYS_CREATE: {
            check_user_vaddr(usp + 1);
            check_user_vaddr(usp + 2);

            const char *file = (const char *)*(usp + 1);
            unsigned initial_size = *(unsigned *)(usp + 2);

            // Validate the file pointer
            check_user_string(file);

            // Proceed with file creation
            f->eax = sys_create(file, initial_size);
        }
        break;
        case SYS_REMOVE:
            break;
        case SYS_OPEN: {
            check_user_vaddr(usp + 1);
            const char *file_name = (const char *)*(usp + 1);
            check_user_string(file_name);
            f->eax = sys_open(file_name);
        }
        break;
        case SYS_FILESIZE:
            break;
        case SYS_READ:
            f->eax = sys_read(*(usp + 1), (void *)*(usp + 2), *(usp + 3));
            break;
        case SYS_WRITE:
            f->eax = sys_write(*(usp + 1), (char *)*(usp + 2), *(usp + 3));
            break;
        case SYS_SEEK:
            break;
        case SYS_TELL:
            break;
        case SYS_CLOSE:
            if (!is_user_vaddr(usp + 1) || get_user((uint8_t *)usp + 1) == -1) sys_exit(-1);
            sys_close(*(usp + 1));
            break;
        default:
            sys_exit(-1);
            break;
    }
}

void sys_halt(void) {
    shutdown_power_off();
}

int sys_open(const char *file_name) {
    if (file_name == NULL || !is_user_vaddr(file_name)) {
        sys_exit(-1);  // Invalid file name
    }

    // Check the end of the file name for validity
    if (!is_user_vaddr(file_name + strlen(file_name))) {
        sys_exit(-1);  // Invalid pointer beyond the file name
    }

    lock_acquire(&filesys_lock);
    struct file *file = filesys_open(file_name);
    lock_release(&filesys_lock);

    // Check if the file exists
    if (file == NULL) {
        return -1;  // File does not exist, return error
    }

    struct thread *cur = thread_current();

    // Find an available slot in the file descriptor table
    int fd = -1;
    for (int i = 2; i < MAX_FILES; i++) {
        if (cur->fd_table[i] == NULL) {
            cur->fd_table[i] = file;
            fd = i;
            break;
        }
    }

    if (fd == -1) {
        file_close(file);  // No available slot, close the file
        return -1;
    }

    return fd;
}

void sys_close(int fd) {
    struct thread *cur = thread_current();

    if (fd < 2 || fd >= MAX_FILES || cur->fd_table[fd] == NULL) {
        sys_exit(-1);  // Invalid file descriptor
    }

    file_close(cur->fd_table[fd]);
    cur->fd_table[fd] = NULL;
}

void sys_exit(int status) {
    struct thread *cur = thread_current();
    cur->exitStatus = status;
    printf("%s: exit(%d)\n", cur->name, status);
    thread_exit();
}

int sys_write(int fd, char *buffer, unsigned size) {
    // Check if the buffer and its boundaries are valid user-space memory
    if (!is_user_vaddr(buffer) || pagedir_get_page(thread_current()->pagedir, buffer) == NULL
        || !is_user_vaddr(buffer + size) || pagedir_get_page(thread_current()->pagedir, buffer + size) == NULL) {
        sys_exit(-1);  // Invalid memory access
    }

    if (fd == 1) {
        putbuf(buffer, size);  // Write to stdout
        return size;
    }
    return -1;
}

int sys_read(int fd, void *buffer, unsigned size) {
    // Check if the buffer and its boundaries are valid user-space memory
    if (!is_user_vaddr(buffer) || pagedir_get_page(thread_current()->pagedir, buffer) == NULL
        || !is_user_vaddr(buffer + size) || pagedir_get_page(thread_current()->pagedir, buffer + size) == NULL) {
        sys_exit(-1);  // Invalid memory access
    }

    if (fd == 0) {  // Read from stdin
        unsigned i;
        for (i = 0; i < size; i++) {
            if (!put_user(((uint8_t *)buffer) + i, input_getc())) {
                sys_exit(-1);  // Invalid memory access while writing
            }
        }
        return size;
    }
    return -1;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int get_user(const uint8_t *uaddr) {
    int result;
    // Ensure that the address is below PHYS_BASE
    if (!is_user_vaddr(uaddr)) {
        return -1;  // Invalid address
    }
    asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool put_user(uint8_t *udst, uint8_t byte) {
    int error_code;
    // Ensure that the destination address is below PHYS_BASE
    if (!is_user_vaddr(udst)) {
        return false;  // Invalid address
    }
    asm ("movl $1f, %0; movb %b2, %1; 1:" : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}

bool sys_create(const char *file, unsigned initial_size) {
    // Check if the file pointer is NULL or invalid user-space pointer
    if (file == NULL || !is_user_vaddr(file)) {
        return false;  // Return false for invalid file pointer
    }

    // Check if the file name is valid and within user space
    if (!is_user_vaddr(file + strlen(file))) {
        return false;  // If the end of the string is not valid user memory
    }

    // Check for empty file name
    if (strlen(file) == 0) {
        return false;  // Empty file name is invalid
    }

    // Proceed with creating the file if all checks pass
    lock_acquire(&filesys_lock);
    bool success = filesys_create(file, initial_size);
    lock_release(&filesys_lock);

    return success;
}

void check_user_vaddr(const void *vaddr) {
    if (!is_user_vaddr(vaddr) || pagedir_get_page(thread_current()->pagedir, vaddr) == NULL) {
        sys_exit(-1);
    }
}

void check_user_string(const char *str) {
    if (!is_user_vaddr(str) || pagedir_get_page(thread_current()->pagedir, str) == NULL) {
        sys_exit(-1);
    }

    while (*str != '\0') {
        if (!is_user_vaddr(str) || pagedir_get_page(thread_current()->pagedir, str) == NULL) {
            sys_exit(-1);
        }
        str++;
    }
}
