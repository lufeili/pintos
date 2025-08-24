#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

/* Lock used when doing file operation. -> only allow one thread to operate.  */
static struct lock file_lock;

void acquire_process_lock();
void release_process_lock();

void syscall_init (void);

void terminate (void);

#endif /* userprog/syscall.h */