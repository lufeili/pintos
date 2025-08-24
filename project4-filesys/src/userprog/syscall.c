#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

void sys_halt (struct intr_frame*);
void sys_exit (struct intr_frame*);
void sys_exec (struct intr_frame*);
void sys_wait (struct intr_frame*);
void sys_create (struct intr_frame*);
void sys_remove (struct intr_frame*);
void sys_open (struct intr_frame*);
void sys_filesize (struct intr_frame*);
void sys_read (struct intr_frame*);
void sys_write (struct intr_frame*);
void sys_seek (struct intr_frame*);
void sys_tell (struct intr_frame*);
void sys_close (struct intr_frame*);


// void sys_mmap (struct intr_frame*);
// void sys_munmap (struct intr_frame*);

void sys_chdir (struct intr_frame*);
void sys_mkdir (struct intr_frame*);
void sys_readdir (struct intr_frame*);
void sys_isdir (struct intr_frame*);
void sys_inumber (struct intr_frame*);

static void syscall_handler (struct intr_frame *);

void acquire_process_lock() {
  lock_acquire(&file_lock);
}

void release_process_lock() {
  lock_release(&file_lock);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
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

struct file_entry*
get_file_entry (int fd) {
  struct file_entry* file_entry = NULL;
  struct list* filelist = &thread_current()->filelist;
  struct list_elem* e = list_begin(filelist);
  while (e != list_end(filelist)) {
    file_entry = list_entry(e, struct file_entry, file_elem);
    if (fd == file_entry->fd) {
      return file_entry;
    }
    e = list_next(e);
  }
  return NULL;
}

/* Handle invalid cases */
void 
terminate (void) {
  thread_current()->exit_status = -1;
  thread_exit();
}

void
check_vaddr (const void *vaddr) {
  for (uint8_t i = 0; i < 4; i++) {
    if (!is_user_vaddr(vaddr) || get_user(vaddr + i) == -1) {
      terminate();
    }
  }

  if (!pagedir_get_page (thread_current()->pagedir, vaddr))
  {
    terminate();
  }

  /*if (vaddr == NULL)
      return false;

  for (uint8_t i = 0; i < 4; i++)
  {
      if (!is_user_vaddr(vaddr + i) || !pagedir_get_page(thread_current()->pagedir, vaddr + i))
          return false;
  }

  return true;*/
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int* esp = f->esp;
  check_vaddr(esp);
  check_vaddr(esp + 1);

  int syscall_type = * (int*)f->esp;
  
  switch (syscall_type)
  {
  case SYS_HALT:
    sys_halt(f);
    break;
  
  case SYS_EXIT:
    sys_exit(f);
    break;
  
  case SYS_EXEC:
    sys_exec(f);
    break;

  case SYS_WAIT:
    sys_wait(f);
    break;
  
  case SYS_CREATE:
    sys_create(f);
    break;
  
  case SYS_REMOVE:
    sys_remove(f);
    break;
  
  case SYS_OPEN:
    sys_open(f);
    break;
  
  case SYS_FILESIZE:
    sys_filesize(f);
    break;
  
  case SYS_READ:
    sys_read(f);
    break;
  
  case SYS_WRITE:
    sys_write(f);
    break;
  
  case SYS_SEEK:
    sys_seek(f);
    break;
  
  case SYS_TELL:
    sys_tell(f);
    break;
  
  case SYS_CLOSE:
    sys_close(f);
    break;
  
  case SYS_CHDIR:
    sys_chdir(f);
    break;

  case SYS_MKDIR:
    sys_mkdir(f);
    break;

  case SYS_READDIR:
    sys_readdir(f);
    break;

  case SYS_ISDIR:
    sys_isdir(f);
    break;

  case SYS_INUMBER:
    sys_inumber(f);
    break;
  
  default:
    terminate();
    break;
  }
}

void
sys_halt (struct intr_frame* f) {
  shutdown_power_off();
}

void
sys_exit (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  thread_current()->exit_status = *user_ptr;
  thread_exit();
}

void
sys_exec (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  char* cmd = *(char**)user_ptr;
  check_vaddr(cmd);
  f->eax = process_execute((char*)* user_ptr);
}

void
sys_wait (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;
  f->eax = process_wait(*user_ptr);
}

void
sys_create (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  //check_vaddr(user_ptr + 1);
  check_vaddr(user_ptr + 2);
  *user_ptr++;
  char* file = *(char**)user_ptr;
  check_vaddr(file);
  unsigned initial_size = *(user_ptr + 1);

  acquire_process_lock();
  f->eax = filesys_create((const char*)file, initial_size, false);
  release_process_lock();
}

void
sys_remove (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  //check_vaddr(user_ptr + 1);
  *user_ptr++;

  char* file = *(char**)user_ptr;
  check_vaddr(file);

  acquire_process_lock();
  f->eax = filesys_remove((const char*)file);
  release_process_lock();
}

void
sys_open (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  //check_vaddr(user_ptr + 1);
  *user_ptr++;

  char* file = *(char**)user_ptr;
  check_vaddr(file);

  acquire_process_lock();
  struct file* file_opened = filesys_open((const char*)file);
  release_process_lock();

  if (file_opened) {
    struct thread* current_thread = thread_current();
    struct file_entry* file_entry = malloc(sizeof(struct file_entry));
    file_entry->fd = current_thread->curr_file_fd++;
    file_entry->file = file_opened;
    struct inode * inode = file_get_inode(file_opened);
    if (inode && inode->data.is_dir) 
    {
      file_entry->dir = dir_open(inode_reopen(inode));
    }
    else
    {
      file_entry->dir = NULL;
    }
    list_push_back(&current_thread->filelist, &file_entry->file_elem);
    f->eax = file_entry->fd;
  } else {
    f->eax = -1;
  }
}

void
sys_filesize (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  struct file_entry* file_entry = get_file_entry(*user_ptr);
  if (file_entry) {
    acquire_process_lock();
    f->eax = file_length(file_entry->file);
    release_process_lock();
  } else {
    f->eax = -1;
  }
}

void
sys_read (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  check_vaddr(user_ptr + 2);
  check_vaddr(user_ptr + 3);
  *user_ptr++;

  int fd = *user_ptr;
  uint8_t* buffer = (uint8_t*)*(user_ptr + 1);
  off_t size = *(user_ptr + 2);
  check_vaddr(buffer);

  if (fd == 0) {
    for (off_t i = 0; i < size; i++) {
      buffer[i] = input_getc();
    }
    f->eax = size;
  } else if (fd == 1) {
    terminate();
  } else {
    struct file_entry* file_entry = get_file_entry(*user_ptr);
    if (file_entry) {
      acquire_process_lock();
      f->eax = file_read(file_entry->file, buffer, size);
      release_process_lock();
    } else {
      f->eax = -1;
    }
  }
}

void
sys_write (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  check_vaddr(user_ptr + 2);
  check_vaddr(user_ptr + 3);

  *user_ptr++;

  int fd = *user_ptr;
  const void* buffer = (const void*)*(user_ptr + 1);
  off_t size = *(user_ptr + 2);
  check_vaddr(buffer);

  if (fd == 0) {
    terminate();
  } else if (fd == 1) {
    putbuf(buffer, size);
    f->eax = size;
  } else {
    struct file_entry* file_entry = get_file_entry(*user_ptr);
    if (file_entry) {
      acquire_process_lock();
      if(file_entry->dir)
      {
        f->eax = -1;
        release_process_lock();
        return;
      }
      f->eax = file_write(file_entry->file, buffer, size);
      release_process_lock();
    } else {
      f->eax = -1;
    }
  }
}

void
sys_seek (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  check_vaddr(user_ptr + 2);
  *user_ptr++;

  struct file_entry* file_entry = get_file_entry(*user_ptr);
  if (file_entry) {
    acquire_process_lock();
    file_seek(file_entry->file, *(user_ptr+1));
    release_process_lock();
  }
}

void
sys_tell (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  struct file_entry* file_entry = get_file_entry(*user_ptr);
  if (file_entry) {
    acquire_process_lock();
    f->eax = file_tell(file_entry->file);
    release_process_lock();
  } else {
    f->eax = -1;
  }
}

void
sys_close (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  struct file_entry* file_entry = get_file_entry(*user_ptr);
  if (file_entry) {
    acquire_process_lock();
    file_close(file_entry->file);
    if(file_entry->dir)
      dir_close(file_entry->dir);
    release_process_lock();
    list_remove(&file_entry->file_elem);
    free(file_entry);
  }
}

void
sys_chdir (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  char* dir = *(char**)user_ptr;
  check_vaddr(dir);

  acquire_process_lock();
  f->eax = filesys_cd((const char*)dir);
  release_process_lock();
}

void
sys_mkdir (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  char* dir = *(char**)user_ptr;
  check_vaddr(dir);

  acquire_process_lock();
  f->eax = filesys_create((const char*)dir, 0, true);
  release_process_lock();
}

void
sys_readdir (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  int fd = *user_ptr;
  *user_ptr++;
  char* name = *(char**)user_ptr;
  check_vaddr(name);

  struct file_entry* file_entry = get_file_entry(fd);
  if (file_entry == NULL) {
    f->eax = -1;
    return;
  }

  acquire_process_lock();
  f->eax = dir_readdir(file_entry->dir, name);
  release_process_lock();
}

void
sys_isdir (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  int fd = *user_ptr;

  struct file_entry* file_entry = get_file_entry(fd);
  if (file_entry == NULL) {
    f->eax = -1;
    return;
  }

  acquire_process_lock();
  f->eax = file_get_inode(file_entry->file)->data.is_dir;
  release_process_lock();
}

void
sys_inumber (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  int fd = *user_ptr;

  struct file_entry* file_entry = get_file_entry(fd);
  if (file_entry == NULL) {
    f->eax = -1;
    return;
  }

  acquire_process_lock();
  f->eax = inode_get_inumber(file_get_inode(file_entry->file));
  release_process_lock();
}
