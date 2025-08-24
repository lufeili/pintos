#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

/* Maximum stack size, 8MB. */
#define STACK_MAX 0x800000

unsigned page_hash_func (const struct hash_elem *e, void *aux);
bool page_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux);

struct hash_elem* get_page_elem (void* vaddr);

bool load_file (struct page* page, void* kpage);
bool stack_growth (void *upage);

void page_init (struct hash* page_table) {
    hash_init(page_table, page_hash_func, page_less_func, NULL);
}

/* Insert a page into the page table and check whether it succeeded. */
bool page_insert (struct hash* page_table, struct page* page) {
    struct hash_elem* temp = hash_insert(page_table, &page->hash_elem);
    return (temp == NULL);
}

struct hash_elem* get_page_elem (void* vaddr) {
    struct page page;
    page.vaddr = (void *)pg_round_down(vaddr);
    return hash_find(thread_current()->page_table, &page.hash_elem);
}

struct page* get_page (void* vaddr) {
    struct hash_elem* e = get_page_elem(vaddr);
    return e ? hash_entry(e, struct page, hash_elem) : NULL;
}

bool handle_fault (struct page* page, void* fault_addr, void* esp) {
    bool success = false;
    if (page) {
        void* kpage = frame_get_page(page, PAL_USER);
        if (kpage == NULL) {
            frame_free_page(kpage);
            return false;
        }

        switch (page->page_type)
        {
        case PAGE_FILE:
            success = load_file(page, kpage);
            break;
        case PAGE_MAPPED:
            success = load_file(page, kpage);
            break;
        case PAGE_DEFAULT:
            if (page->swap_index != -1) {
                swap_in(kpage, page->swap_index);
                page->swap_index = -1;
                success = true;
            }
            break;
        default:
            success = false;
            break;
        }

        if (!success) {
            frame_free_page(kpage);
            return false;
        }

        page->is_loaded = true;
        acquire_process_lock();
        if (!install_page(page->vaddr, kpage, page->writable)) {
            frame_free_page(kpage);
            release_process_lock();
            return false;
        }
        release_process_lock();

        return success;
    
    } else {
        /* We need to check whether the page fault occurrs in the stack.
            - The address should be in the stack space.
            - The address should be within 32 bytes of the stack pointer. */
        if (is_user_vaddr(fault_addr) && 
                (fault_addr >= PHYS_BASE - STACK_MAX) && 
                (fault_addr >= esp - 32)) {
            return stack_growth(fault_addr);
        }
    }
    return success;
}

bool load_file (struct page* page, void* kpage) {
    acquire_process_lock();
    size_t page_read_bytes = page->read_bytes > PGSIZE ? PGSIZE : page->read_bytes;
    if (file_read_at(page->file, kpage, page->read_bytes, page->offset) 
            != page_read_bytes) {
        release_process_lock();
        return false;
    } 
    release_process_lock();

    memset (kpage + page_read_bytes, 0, page->zero_bytes);

    return true;
}

/* Allocate one page for the stack and insert it into the page table. */
bool stack_growth (void *fault_addr) {
    struct page* page = (struct page*)malloc(sizeof(struct page));
    if (page == NULL) {
        return false;
    }

    void *upage = pg_round_down(fault_addr);
    page->vaddr = upage;
    page->page_type = PAGE_DEFAULT;
    page->writable = true;
    page->is_loaded = true;
    page->swap_index = -1;

    page->file = NULL;
    page->offset = 0;
    page->read_bytes = PGSIZE;
    page->zero_bytes = 0;

    if (!page_insert(thread_current()->page_table, page)) {
        free(page);
        return false;
    }

    void* kpage = frame_get_page(page->vaddr, PAL_USER | PAL_ZERO);
    if (kpage == NULL) {
        free(page);
        return false;
    }

    if (!install_page(page->vaddr, kpage, page->writable)) {
        free(page);
        frame_free_page(kpage);
        return false;
    }

    return true;
}

unsigned page_hash_func (const struct hash_elem *e, void *aux) {
    struct page* page = hash_entry(e, struct page, hash_elem);
    return hash_bytes(&page->vaddr, sizeof(page->vaddr));
}

bool page_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux) {
    struct page* page_a = hash_entry(a, struct page, hash_elem);
    struct page* page_b = hash_entry(b, struct page, hash_elem);
    return page_a->vaddr < page_b->vaddr;
}