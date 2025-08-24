#include "stdint.h"
#include "vm/swap.h"

void acquire_swap_lock() {
    if (!lock_held_by_current_thread(&swap_lock)) {
        lock_acquire(&swap_lock);
    }
}
  
void release_swap_lock() {
    if (lock_held_by_current_thread(&swap_lock)) {
        lock_release(&swap_lock);
    }
}

void swap_init (void) {
    swap_block = block_get_role(BLOCK_SWAP);
    if (swap_block == NULL) {
        PANIC("No swap block device found.");
    }

    swap_table = bitmap_create(block_size(swap_block) / SWAP_SECTOR);
    if (swap_table == NULL) {
        PANIC("Fail to create swap table.");
    }

    bitmap_set_all(swap_table, false);
    lock_init(&swap_lock);
}

void swap_in (void* kpage, size_t index) {
    acquire_process_lock();
    acquire_swap_lock();

    for (block_sector_t sector = 0; sector < SWAP_SECTOR; sector++) {
        block_read(swap_block, index * SWAP_SECTOR + sector, kpage + sector * BLOCK_SECTOR_SIZE);
    }
    bitmap_set_multiple(swap_table, index, 1, false);
    
    release_swap_lock();
    release_process_lock();
}

size_t swap_out (void* kpage) {
    acquire_process_lock();
    acquire_swap_lock();
    size_t index = bitmap_scan_and_flip(swap_table, 0, 1, false);
    for (block_sector_t sector = 0; sector < SWAP_SECTOR; sector++) {
        block_write(swap_block, index * SWAP_SECTOR + sector, kpage + sector * BLOCK_SECTOR_SIZE);
    }
    release_swap_lock();
    release_process_lock();
    return index;
}
