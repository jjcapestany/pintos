#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "vm/page.h"
#include "vm/mmap.h"
#include "vm/frame.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <inttypes.h>
#include <list.h>

/* Process identifier. */
typedef int pid_t;
/* File identifier. */
typedef int fid_t;

static void syscall_handler (struct intr_frame *);

static void      sys_halt (void);
static void      sys_exit (int status);
static pid_t     sys_exec (const char *file);
static int       sys_wait (pid_t pid);
static bool      sys_create (const char *file, unsigned initial_size);
static bool      sys_remove (const char *file);
static int       sys_open (const char *file);
static int       sys_filesize (int fd);
static int       sys_read (int fd, void *buffer, unsigned size);
static int       sys_write (int fd, const void *buffer, unsigned size);
static void      sys_seek (int fd, unsigned position);
static unsigned  sys_tell (int fd);
static void      sys_close (int fd);
static mapid_t   sys_mmap (int fd, void *addr);
static void      sys_munmap (mapid_t mapid);

static struct user_file *file_by_fid (fid_t);
static fid_t allocate_fid (void);
static mapid_t allocate_mapid (void);

static struct lock file_lock;
static struct list file_list;

typedef int (*handler) (uint32_t, uint32_t, uint32_t);
static handler syscall_map[32];

static void *param_esp;

struct user_file
  {
    struct file *file;                 /* Pointer to the actual file */
    fid_t fid;                         /* File identifier */
    struct list_elem thread_elem;      /* List elem for a thread's file list */
  };

/* Initialization of syscall handlers */
void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  syscall_map[SYS_HALT]     = (handler)sys_halt;
  syscall_map[SYS_EXIT]     = (handler)sys_exit;
  syscall_map[SYS_EXEC]     = (handler)sys_exec;
  syscall_map[SYS_WAIT]     = (handler)sys_wait;
  syscall_map[SYS_CREATE]   = (handler)sys_create;
  syscall_map[SYS_REMOVE]   = (handler)sys_remove;
  syscall_map[SYS_OPEN]     = (handler)sys_open;
  syscall_map[SYS_FILESIZE] = (handler)sys_filesize;
  syscall_map[SYS_READ]     = (handler)sys_read;
  syscall_map[SYS_WRITE]    = (handler)sys_write;
  syscall_map[SYS_SEEK]     = (handler)sys_seek;
  syscall_map[SYS_TELL]     = (handler)sys_tell;
  syscall_map[SYS_CLOSE]    = (handler)sys_close;
  syscall_map[SYS_MMAP]     = (handler)sys_mmap;
  syscall_map[SYS_MUNMAP]   = (handler)sys_munmap;

  lock_init (&file_lock);
  list_init (&file_list);
}

/* Syscall handler calls the appropriate function. */
static void
syscall_handler (struct intr_frame *f)
{
  handler function;
  int *param = f->esp, ret;

  if ( !is_user_vaddr(param) )
    sys_exit (-1);

  if (!( is_user_vaddr (param + 1) && is_user_vaddr (param + 2) && is_user_vaddr (param + 3)))
    sys_exit (-1);

  if (*param < SYS_HALT || *param > SYS_INUMBER)
    sys_exit (-1);

  function = syscall_map[*param];

  param_esp = f->esp;
  ret = function (*(param + 1), *(param + 2), *(param + 3));
  f->eax = ret;

  return;
}

/* Halt the operating system. */
static void
sys_halt (void)
{
  shutdown_power_off ();
}

/* Terminate this process. */
void
sys_exit (int status)
{
  struct thread *t;
  struct list_elem *e;

  t = thread_current ();
  if (lock_held_by_current_thread (&file_lock) )
    lock_release (&file_lock);

  /* Close all opened files of the thread. */
  while (!list_empty (&t->files) )
    {
      e = list_begin (&t->files);
      sys_close ( list_entry (e, struct user_file, thread_elem)->fid );
    }
  /* Unmap all memory mapped files of the thread. */
  while (!list_empty (&t->mfiles) )
    {
      e = list_begin (&t->mfiles);
      sys_munmap ( list_entry (e, struct vm_mfile, thread_elem)->mapid );
    }

  t->ret_status = status;
  thread_exit ();
}

/* Start another process. */
static pid_t
sys_exec (const char *file)
{
  lock_acquire (&file_lock);
  int ret = process_execute (file);
  lock_release (&file_lock);
  return ret;
}

/* Wait for a child process to die. */
static int
sys_wait (pid_t pid)
{
  return process_wait (pid);
}

/* Create a file. */
static bool
sys_create (const char *file, unsigned initial_size)
{
  if (file == NULL)
    sys_exit (-1);

  int ret = filesys_create (file, initial_size);
  return ret;
}

/* Delete a file. */
static bool
sys_remove (const char *file)
{
   if (file == NULL)
     sys_exit (-1);

  return filesys_remove (file);
}

/* Open a file. */
static int
sys_open (const char *file)
{
  struct file *sys_file;
  struct user_file *f;

  if (file == NULL)
    return -1;

  sys_file = filesys_open (file);
  if (sys_file == NULL)
    return -1;

  f = (struct user_file *) malloc (sizeof (struct user_file));
  if (f == NULL)
    {
      file_close (sys_file);
      return -1;
    }

  lock_acquire (&file_lock);
  f->file = sys_file;
  f->fid = allocate_fid ();
  list_push_back (&thread_current ()->files, &f->thread_elem);
  lock_release (&file_lock);

  return f->fid;
}

/* Obtain a file's size. */
static int
sys_filesize (int fd)
{
  struct user_file *f;
  int size = -1;

  f = file_by_fid (fd);
  if (f == NULL)
    return -1;

  lock_acquire (&file_lock);
  size = file_length (f->file);
  lock_release (&file_lock);

  return size;
}

/* Read from a file. */
static int
sys_read (int fd, void *buffer, unsigned length)
{
  /* I experience a weird behaviour for page-mer-stk test. It needs
     to grow its stack when reading but the fault address it's 30 bytes
     above the stack pointer so it's not recognized as authentic stack
     access. We need to figure out this */
  const void *esp = (const void*)param_esp;

  struct user_file *f;
  int ret = -1;

  if (fd == STDIN_FILENO)
    {
      lock_acquire (&file_lock);
      unsigned i;
      for (i = 0; i < length; ++i)
        *(uint8_t *)(buffer + i) = input_getc ();
      lock_release (&file_lock);
      ret = length;
    }
  else if (fd == STDOUT_FILENO)
    ret = -1;
  else if ( !is_user_vaddr (buffer) || !is_user_vaddr (buffer + length) )
    sys_exit (-1);
  else
    {
      f = file_by_fid (fd);
      if (f == NULL)
        ret = -1;
      else
        {
          size_t rem = length;
          void *tmp_buffer = (void *)buffer;

          ret = 0;
          while (rem > 0)
            {
              size_t ofs = tmp_buffer - pg_round_down (tmp_buffer);
              struct vm_page *page = find_page (tmp_buffer - ofs);

              if (page == NULL && stack_access (esp, tmp_buffer) )
                page = vm_grow_stack (tmp_buffer - ofs, true);
              else if (page == NULL)
                sys_t_exit (-1);

              /* Load the page and pin the frame. */
              if ( !page->loaded )
                vm_load_page (page, tmp_buffer - ofs, true);

              size_t read_bytes = ofs + rem > PGSIZE ? rem - (ofs + rem - PGSIZE) : rem;
              lock_acquire (&file_lock);

              ASSERT (page->loaded);
              ret += file_read (f->file, tmp_buffer, read_bytes);
              lock_release (&file_lock);

              rem -= read_bytes;
              tmp_buffer += read_bytes;

              vm_frame_unpin (page->kpage);
            }
        }
    }
  return ret;
}

/* Write to a file. */
static int
sys_write (int fd, const void *buffer, unsigned length)
{
  const void *esp = (const void*)param_esp;

  struct user_file *f;
  int ret = -1;

  if (fd == STDIN_FILENO)
    ret = -1;
  else if (fd == STDOUT_FILENO)
    {
      lock_acquire (&file_lock);
      putbuf (buffer, length);
      lock_release (&file_lock);
      ret = length;
    }
  else if ( !is_user_vaddr (buffer) || !is_user_vaddr (buffer + length) )
    sys_exit (-1);
  else
    {
      f = file_by_fid (fd);
      if (f == NULL)
        ret = -1;
      else
        {
          size_t rem = length;
          void *tmp_buffer = (void *)buffer;

          ret = 0;
          while (rem > 0)
            {
              size_t ofs = tmp_buffer - pg_round_down (tmp_buffer);
              struct vm_page *page = find_page (tmp_buffer - ofs);

              if (page == NULL && stack_access(esp, tmp_buffer) )
                page = vm_grow_stack (tmp_buffer - ofs, true);
              else if (page == NULL)
                sys_t_exit (-1);

              /* Load the page and pin the frame. */
              if ( !page->loaded )
                vm_load_page (page, tmp_buffer - ofs, true);

              size_t write_bytes = ofs + rem > PGSIZE ? rem - (ofs + rem - PGSIZE) : rem;
              lock_acquire (&file_lock);

              ASSERT (page->loaded);
              ret += file_write (f->file, tmp_buffer, write_bytes);
              lock_release (&file_lock);

              rem -= write_bytes;
              tmp_buffer += write_bytes;

              vm_frame_unpin (page->kpage);
            }
        }
    }
  return ret;
}

/* Change position in a file. */
static void
sys_seek (int fd, unsigned position)
{
  struct user_file *f;

  f = file_by_fid (fd);
  if (!f)
    sys_exit (-1);

  lock_acquire (&file_lock);
  file_seek (f->file, position);
  lock_release (&file_lock);
}

/* Report current position in a file. */
static unsigned
sys_tell (int fd)
{
  struct user_file *f;
  unsigned status;

  f = file_by_fid (fd);
  if (!f)
    sys_exit (-1);

  lock_acquire (&file_lock);
  status = file_tell (f->file);
  lock_release (&file_lock);

  return status;
}

/* Close a file. */
static void
sys_close (int fd)
{
  struct user_file *f;

  f = file_by_fid (fd);

  if (f == NULL)
    sys_exit (-1);

  lock_acquire (&file_lock);
  list_remove (&f->thread_elem);
  file_close (f->file);
  free (f);
  lock_release (&file_lock);
}

/* Creates a memory mapped file from the given file. */
mapid_t
sys_mmap (int fd, void *addr)
{
  size_t size;
  struct file *file;

  size = sys_filesize(fd);
  lock_acquire (&file_lock);
  file = file_reopen ( file_by_fid (fd)->file );
  lock_release (&file_lock);

  if (size <= 0 || file == NULL)
    return -1;
  if (addr == NULL || addr == 0x0 || pg_ofs (addr) != 0)
    return -1;
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
    return -1;

  size_t ofs = 0;
  void *tmp_addr = addr;
  while (size > 0)
    {
      size_t read_bytes;
      size_t zero_bytes;

      if (size >= PGSIZE)
        {
          read_bytes = PGSIZE;
          zero_bytes = 0;
        }
      else
        {
          read_bytes = size;
          zero_bytes = PGSIZE - size;
        }

      /* Fail if there is already a mapped page at the same address. */
      if ( find_page (tmp_addr) != NULL)
          return -1;

      vm_new_file_page (tmp_addr, file, ofs, read_bytes, zero_bytes, true);
      ofs += PGSIZE;
      size -= read_bytes;
      tmp_addr += PGSIZE;
    }

  mapid_t mapid = allocate_mapid();
  vm_insert_mfile (mapid, fd, addr, tmp_addr);

  return mapid;
}

/* Unmaps a files from memory. */
void
sys_munmap (mapid_t mapid)
{
  struct vm_mfile *mf = vm_find_mfile (mapid);
  if (mf == NULL)
    sys_exit (-1);

  void *addr = mf->start_addr;
  for (;addr < mf->end_addr; addr += PGSIZE)
    {
      struct vm_page *page = NULL;

      page = find_page (addr);
      if (page == NULL)
        continue;

      if (page->loaded == true)
        {
          vm_pin_page (page);

          ASSERT (page->loaded && page->kpage != NULL);
          vm_unload_page (page, addr);
          vm_free_frame (page->kpage);
          /* We don't really need to unpin the page
          as the holding frame will be deleted when
          we dump the page. */
        }
      vm_delete_page (page);
    }
  vm_delete_mfile (mapid);
}


/* Allocate a new fid for a file */
static fid_t
allocate_fid (void)
{
  static fid_t next_fid = 2;
  return next_fid++;
}

/* Allocate a new mapid for a file */
static mapid_t
allocate_mapid (void)
{
  static mapid_t next_mapid = 0;
  return next_mapid++;
}

/* Returns the file with the given fid from the current thread's files */
static struct user_file *
file_by_fid (int fid)
{
  struct list_elem *e;
  struct thread *t;

  t = thread_current();
  for (e = list_begin (&t->files); e != list_end (&t->files);
       e = list_next (e))
    {
      struct user_file *f = list_entry (e, struct user_file, thread_elem);
      if (f->fid == fid)
        return f;
    }

  return NULL;
}

/* Extern function for sys_exit */
void
sys_t_exit (int status)
{
  sys_exit (status);
}

void
sys_t_filelock (int acquire)
{
  if (acquire)
    lock_acquire (&file_lock);
  else
    lock_release (&file_lock);
}
