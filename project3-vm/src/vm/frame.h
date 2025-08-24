#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/synch.h"
#include "threads/thread.h"
#include "vm/page.h"

struct lock frame_lock;
static struct list frame_table;

/* This is the structure of page frame. */
struct frame
{
    void* kpage;                    /* Kernel virtual address. */
    struct thread* holder;          /* The thread that holds the frame. */
    struct page* page;              /* The related page. */
    struct list_elem frame_elem;    /* List element to iterate over. */
    bool pinned;                    /* Record when a page contained in a frame 
                                        must not be evicted. */
};

void frame_init ();
void* frame_get_page (struct page* page, enum palloc_flags flags);
void frame_free_page (void* kpage);

struct frame* get_frame (void* upage);

void frame_pin (void* upage);
void frame_unpin (void* upage);

#endif VM_FRAME_H