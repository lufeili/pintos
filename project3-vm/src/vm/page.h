#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "filesys/off_t.h"
#include "threads/thread.h"

enum page_type {
    PAGE_DEFAULT,
    PAGE_FILE,
    PAGE_MAPPED
};

/* This is the structure of the supplemental page table. */
struct page {
    void* vaddr;                    /* The user virtual address. */
    enum page_type page_type;
    
    bool writable;
    bool is_loaded;                 /* Whether the page is loaded in memory. */
    int swap_index;                 /* Set it to -1 when unswapped. */

    struct file* file;              /* The corresponding file. */
    off_t offset;
    size_t read_bytes;
    size_t zero_bytes;
    
    struct hash_elem hash_elem;     /* struct thread `page_table' hash element. */
};

void page_init (struct hash* page_table);
bool page_insert (struct hash* page_table, struct page* page);
struct page* get_page (void* vaddr);
bool handle_fault (struct page* page, void* fault_addr, void* esp);

#endif VM_PAGE_H