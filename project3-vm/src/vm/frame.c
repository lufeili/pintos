#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/swap.h"

struct list_elem* lru;
struct list_elem* get_lru ();

void acquire_frame_lock();
void release_frame_lock();

void evict ();
struct frame* get_frame_evict ();

void frame_init () {
    list_init(&frame_table);
    lock_init(&frame_lock);
}

void* frame_get_page (struct page* page, enum palloc_flags flags) {
    void* kpage = palloc_get_page(flags);

    if (kpage == NULL) {
        evict();
        kpage = palloc_get_page(flags);
    }

    if (kpage == NULL) {
        PANIC("Fail to evict!\n");
    }

    struct frame* frame = (struct frame*)malloc(sizeof(struct frame));
    if (frame == NULL) {
        palloc_free_page(kpage);
        return NULL;
    }

	frame->kpage = kpage;
    frame->holder = thread_current();
    frame->page = page;
    frame->pinned = false;

    acquire_frame_lock();
    list_push_back(&frame_table, &frame->frame_elem);
    release_frame_lock();

    return kpage;
}

void frame_free_page (void* kpage) {
    acquire_frame_lock();

    struct list_elem* frame_elem = list_begin(&frame_table);
    while (frame_elem != list_end(&frame_table)) {
        struct frame* frame = list_entry(frame_elem, struct frame, frame_elem);
        if (kpage == frame->kpage) {
            palloc_free_page(kpage);
            list_remove(frame_elem);
            free(frame);
            break;
        }
        frame_elem = list_next(frame_elem);
    }

    release_frame_lock();
}

struct frame* get_frame (void* upage) {
    struct list_elem* frame_elem = list_begin(&frame_table);
    while (frame_elem != list_end(&frame_table)) {
        struct frame* frame = list_entry(frame_elem, struct frame, frame_elem);
        if (frame && frame->page->vaddr == upage) {
            return frame;
        }
        frame_elem = list_next(frame_elem);
    }
    return NULL;
}

void frame_pin (void* upage) {
    acquire_frame_lock();
    struct frame* frame = get_frame(upage);
    if (frame) {
        frame->pinned = true;
        list_remove(&frame->frame_elem);
        list_push_back(&frame_table, &frame->frame_elem);
    }
    release_frame_lock();
}

void frame_unpin (void* upage) {
    acquire_frame_lock();
    struct frame* frame = get_frame(upage);
    if (frame) {
        frame->pinned = false;
        list_remove(&frame->frame_elem);
        list_push_back(&frame_table, &frame->frame_elem);
    }
    release_frame_lock();
}

void acquire_frame_lock() {
    if (!lock_held_by_current_thread(&frame_lock)) {
        lock_acquire(&frame_lock);
    }
}
  
void release_frame_lock() {
    if (lock_held_by_current_thread(&frame_lock)) {
        lock_release(&frame_lock);
    }
}

void evict () {
	acquire_frame_lock();
    acquire_process_lock();

    struct frame* frame = get_frame_evict();
    struct page* page = frame->page;

    switch (page->page_type)
    {
    case PAGE_DEFAULT:
        page->swap_index = swap_out(frame->kpage);
        break;
    
    case PAGE_FILE:
        if (pagedir_is_dirty(frame->holder->pagedir, page->vaddr)) {
            page->swap_index = swap_out(frame->kpage);
            page->page_type = PAGE_DEFAULT;
        }
        break;
    
    case PAGE_MAPPED:
        if (pagedir_is_dirty(frame->holder->pagedir, page->vaddr)) {
            file_write_at(page->file, page->vaddr, page->read_bytes, 
                            page->zero_bytes, page->offset);
        }
        break;
    
    default:
        break;
    }

    pagedir_clear_page(frame->holder->pagedir, pg_round_down(page->vaddr));
    palloc_free_page(frame->kpage);
    list_remove(&frame->frame_elem);
    free(frame);

    release_process_lock();
    release_frame_lock();
}

struct frame* get_frame_evict () {
    struct list_elem* frame_elem = get_lru();
    struct frame* frame = list_entry(frame_elem, struct frame, frame_elem);
    while (frame->pinned 
                || pagedir_is_accessed(frame->holder->pagedir, frame->page->vaddr)) {
        pagedir_set_accessed(frame->holder->pagedir, frame->page->vaddr, false);
        frame_elem = get_lru();
        frame = list_entry(frame_elem, struct frame, frame_elem);
    }
    return frame;
}

struct list_elem* get_lru () {
    if (list_empty(&frame_table)) {
        return NULL;
    }

    if (lru == NULL || lru == list_end(&frame_table)) {
        lru = list_begin(&frame_table);
    } else {
        lru = list_next(lru);
    }

    if (lru == list_end(&frame_table)) {
        lru = get_lru();
    }

    return lru;
}
