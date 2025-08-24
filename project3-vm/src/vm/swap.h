#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "bitmap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

/* The number of sectors per page. */
#define SWAP_SECTOR (PGSIZE / BLOCK_SECTOR_SIZE)

struct bitmap* swap_table;
struct block* swap_block;
struct lock swap_lock;

void acquire_swap_lock();
void release_swap_lock();

void swap_init (void);
void swap_in (void* kpage, size_t index);
size_t swap_out (void* kpage);

#endif VM_SWAP_H