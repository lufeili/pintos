#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

#define CODE_SEGMENT (void*)0x08048000

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

// void sys_chdir (struct intr_frame*);
// void sys_mkdir (struct intr_frame*);
// void sys_readdir (struct intr_frame*);
// void sys_isdir (struct intr_frame*);
// void sys_inumber (struct intr_frame*);

static void syscall_handler (struct intr_frame *);

void acquire_process_lock() {
  if (!lock_held_by_current_thread(&file_lock)) {
    lock_acquire(&file_lock);
  }
}

void release_process_lock() {
  if (lock_held_by_current_thread(&file_lock)) {
    lock_release(&file_lock);
  }
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
}

/* Get the current thread's corresponding file to the given file descripter id. */
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
  release_process_lock();
  thread_current()->exit_status = -1;
  /* print the process's name and exit code */
  printf("%s: exit(%d)\n", thread_name(), thread_current()->exit_status);
  thread_exit();
}

/* Check whether the user pointer is valid. */
void check_pointer (const void* ptr) {
  if (ptr == NULL || !is_user_vaddr(ptr) 
      || pagedir_get_page(thread_current()->pagedir, ptr) == NULL
      || ptr < CODE_SEGMENT) {
    terminate();
  }
}

/* Check whether the buffer address is valid. */
void check_buffer (const void* buffer, off_t size) {
  void* ptr = (void*)buffer;
  for (size_t i = 0; i < size; i++) {
    check_pointer(ptr++);
  }
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int* esp = f->esp;
  check_pointer(esp);
  check_pointer(esp + 1);
  check_pointer(esp + 2);
  check_pointer(esp + 3);

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
  release_process_lock();
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  thread_current()->exit_status = *user_ptr;

  /* print the process's name and exit code */
  printf("%s: exit(%d)\n", thread_name(), thread_current()->exit_status);
  thread_exit();
}

void
sys_exec (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  char* cmd = *(char**)user_ptr;
  check_pointer(cmd);

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
  *user_ptr++;

  char* file = *(char**)user_ptr;
  check_pointer(file);

  unsigned initial_size = *(user_ptr + 1);

  acquire_process_lock();
  f->eax = filesys_create((const char*)file, initial_size);
  release_process_lock();
}

void
sys_remove (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  char* file = *(char**)user_ptr;
  check_pointer(file);

  acquire_process_lock();
  f->eax = filesys_remove((const char*)file);
  release_process_lock();
}

void
sys_open (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  char* file = *(char**)user_ptr;
  check_pointer(file);

  acquire_process_lock();
  struct file* file_opened = filesys_open((const char*)file);

  if (file_opened) {
    struct thread* current_thread = thread_current();
    struct file_entry* file_entry = malloc(sizeof(struct file_entry));
    if (file_entry == NULL) {
      f->eax = -1;
      release_process_lock();
      return;
    }
    file_entry->fd = current_thread->curr_file_fd++;
    file_entry->file = file_opened;
    list_push_back(&current_thread->filelist, &file_entry->file_elem);
    f->eax = file_entry->fd;
  } else {
    f->eax = -1;
  }
  release_process_lock();
}

void
sys_filesize (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  acquire_process_lock();
  struct file_entry* file_entry = get_file_entry(*user_ptr);
  if (file_entry) {
    f->eax = file_length(file_entry->file);
  } else {
    f->eax = -1;
  }
  release_process_lock();
}

void
sys_read (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  int fd = *user_ptr;
  uint8_t* buffer = (uint8_t*)*(user_ptr + 1);
  off_t size = *(user_ptr + 2);
  check_buffer(buffer, size);

  acquire_process_lock();

  /* Read from the keyboard using input_getc(). */
  if (fd == 0) {
    for (off_t i = 0; i < size; i++) {
      buffer[i] = input_getc();
    }
    f->eax = size;
  }
  /* Read from the output stream is invalid. */
  else if (fd == 1) {
    f->eax = -1;
  }
  /* Read from a regular file. */
  else {
    struct file_entry* file_entry = get_file_entry(*user_ptr);
    if (file_entry) {
      f->eax = file_read(file_entry->file, buffer, size);
    } else {
      f->eax = -1;
    }
  }

  release_process_lock();
}

void
sys_write (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  int fd = *user_ptr;
  const void* buffer = (const void*)*(user_ptr + 1);
  off_t size = *(user_ptr + 2);
  check_buffer(buffer, size);

  acquire_process_lock();

  /* Writing to the input stream is invalid. */
  if (fd == 0) {
    f->eax = -1;
  }
  /* Fd 1(STDOUT_FILENO) writes to the console. */
  else if (fd == 1) {
    putbuf(buffer, size);
    f->eax = size;
  }
  /* Write to a regular file. */
  else {
    struct file_entry* file_entry = get_file_entry(*user_ptr);
    if (file_entry) {
      f->eax = file_write(file_entry->file, buffer, size);
    } else {
      f->eax = -1;
    }
  }
  
  release_process_lock();
}

void
sys_seek (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  acquire_process_lock();
  struct file_entry* file_entry = get_file_entry(*user_ptr);
  if (file_entry) {
    file_seek(file_entry->file, *(user_ptr+1));
  }
  release_process_lock();
}

void
sys_tell (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  acquire_process_lock();
  struct file_entry* file_entry = get_file_entry(*user_ptr);
  if (file_entry) {
    f->eax = file_tell(file_entry->file);
  } else {
    f->eax = -1;
  }
  release_process_lock();
}

void
sys_close (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  acquire_process_lock();
  struct file_entry* file_entry = get_file_entry(*user_ptr);
  if (file_entry) {
    file_close(file_entry->file);
    list_remove(&file_entry->file_elem);
    free(file_entry);
  }
  release_process_lock();
}