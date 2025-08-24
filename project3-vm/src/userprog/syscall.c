#include "user/syscall.h"
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "vm/frame.h"
#include "vm/page.h"

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

void sys_mmap (struct intr_frame*);
void sys_munmap (struct intr_frame*);

// void sys_chdir (struct intr_frame*);
// void sys_mkdir (struct intr_frame*);
// void sys_readdir (struct intr_frame*);
// void sys_isdir (struct intr_frame*);
// void sys_inumber (struct intr_frame*);

static void syscall_handler (struct intr_frame *);

mapid_t file_mmap (struct file* file, void *addr);
void file_mummap (struct file_entry* file_entry);

void acquire_process_lock() {
  // printf("Acquire process lock!\n");
  if (!lock_held_by_current_thread(&file_lock)) {
    lock_acquire(&file_lock);
  }
}

void release_process_lock() {
  // printf("Release process lock!\n");
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

struct file_entry*
get_mapped_file_entry (mapid_t mapping) {
  struct file_entry* file_entry = NULL;
  struct list* filelist = &thread_current()->mapped_filelist;
  struct list_elem* e = list_begin(filelist);
  while (e != list_end(filelist)) {
    file_entry = list_entry(e, struct file_entry, file_elem);
    if (mapping == file_entry->fd) {
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

void check_pointer (const void* ptr) {
  if (ptr == NULL || !is_user_vaddr(ptr) 
      || get_page(pg_round_down(ptr)) == NULL
      || ptr < CODE_SEGMENT) {
    terminate();
  }
}

void check_buffer (const void* buffer, off_t size) {
  void* ptr = (void*)buffer;
  for (size_t i = 0; i < size; i++) {
    check_pointer(ptr++);
  }
}

void pin (const char* begin, const char* end) {
  while (begin < end) {
    struct page* page = get_page(pg_round_down(begin));
    if (page == NULL || page->writable == false) {
      terminate();
    }
    if (page->is_loaded == false) {
      handle_fault (page, NULL, NULL);
    }
    frame_pin(pg_round_down(begin));
    begin += PGSIZE;
  }
}

void unpin (const char* begin, const char* end) {
  while (begin < end) {
    frame_unpin(pg_round_down(begin));
    begin += PGSIZE;
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
  
  case SYS_MMAP:
    sys_mmap(f);
    break;
  
  case SYS_MUNMAP:
    sys_munmap(f);
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
  pin(buffer, buffer + size);
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
  unpin(buffer, buffer + size);
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
  if (fd == 0) {
    f->eax = -1;
  } else if (fd == 1) {
    putbuf(buffer, size);
    f->eax = size;
  } else {
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

void
sys_mmap (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  acquire_process_lock();
  int fd = *user_ptr;
  if (fd == 0 || fd == 1) {
    /* fd = 0 or fd = 1 are not mappable. */
    f->eax = -1;
  } else {
    struct file_entry* file_entry = get_file_entry(*user_ptr);
    if (file_entry) {
      f->eax = file_mmap(file_entry->file, *(user_ptr+1));
    } else {
      f->eax = -1;
    }
  }
  release_process_lock();
}

void
sys_munmap (struct intr_frame* f) {
  uint32_t* user_ptr = f->esp;
  *user_ptr++;

  acquire_process_lock();
  mapid_t mapping = *user_ptr;
  struct file_entry* file_entry = get_mapped_file_entry(mapping);
  file_mummap(file_entry);
  release_process_lock();
}


mapid_t file_mmap (struct file* file, void *addr) {
  /* - It must fail if addr is not page-aligned.
     - It must also fail if addr is 0. */
  if (((int)addr % PGSIZE) || (int)addr == 0) {
    return -1;
  }

  struct file* file_mapped = file_reopen(file);
  if (file_mapped == NULL) {
    return -1;
  }

  off_t length = file_length(file_mapped);
  /* Fail if the file open as fd has a length of zero bytes. */
  if (length == 0) {
    return -1;
  }

  /* It must fail if the range of pages mapped overlaps any existing set of mapped pages, 
       including the stack or pages mapped at executable load time. */
  for (off_t ofs = 0; ofs < length; ofs += PGSIZE) {
    if (get_page(addr + ofs) 
          || pagedir_get_page(thread_current()->pagedir, addr + ofs)) {
      return -1;
    }
  }

  struct file_entry* f = (struct file_entry*)malloc(sizeof(struct file_entry));
  if (f == NULL) {
    file_close(file_mapped);
    return -1;
  }

  struct thread* curr = thread_current();
  f->fd = curr->mapid++;
  f->file = file_mapped;
  f->upage = addr;
  list_push_back(&curr->mapped_filelist, &f->file_elem);

  off_t offset = 0;
  size_t read_bytes = 0;
  size_t zero_bytes = 0;
  int page_num = (length / PGSIZE) + ((length % PGSIZE > 0) ? 1 : 0);
  for (int i = 0; i < page_num; i++) {
    offset = i * PGSIZE;
    read_bytes = (i == page_num - 1) ? (length % PGSIZE) : PGSIZE;
    zero_bytes = PGSIZE - read_bytes;

    
    struct page* page = (struct page*)malloc(sizeof(struct page));
    if (page == NULL) {
      return -1;
    }

    page->vaddr = addr;
    page->page_type = PAGE_MAPPED;
    page->writable = true;
    page->is_loaded = false;
    page->swap_index = -1;

    page->file = file_mapped;
    page->offset = offset;
    page->read_bytes = read_bytes;
    page->zero_bytes = zero_bytes;
    
    if (!page_insert(curr->page_table, page)) {
      free(page);
      return -1;
    }
    
    addr += PGSIZE;

  }

  return f->fd;
}

void file_mummap (struct file_entry* file_entry) {
  void* addr = 0;
  void* upage = file_entry->upage;
  size_t length = file_length(file_entry->file);
  struct thread* cur = thread_current();

  off_t offset = 0;
  int page_num = (length / PGSIZE) + ((length % PGSIZE > 0) ? 1 : 0);
  for (int i = 0; i < page_num; i++) {
    offset = i * PGSIZE;
    addr = upage + offset;

    if (pg_ofs(pagedir_get_page(cur->pagedir, addr)) == 0 && 
            pagedir_is_dirty(cur->pagedir, addr)) {
      if (i == page_num - 1) {
        file_write_at(file_entry->file, addr, length % PGSIZE, offset);
      } else {
        file_write_at(file_entry->file, addr, PGSIZE, offset);
      }
    }
    pagedir_clear_page(cur->pagedir, addr);
  }

  list_remove(&file_entry->file_elem);
  file_close(file_entry->file);
  free(file_entry);
}
