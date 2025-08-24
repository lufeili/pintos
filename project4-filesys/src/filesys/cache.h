#include "devices/block.h"
#include <stdbool.h>
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* Lock for synchronizing cache operations. */
struct lock cache_lock;

struct cache
{
    bool valid;                         /* Valid bit */
    bool dirty;                         /* Dirty bit */
    int64_t last_used;                  /* Last used time */
    block_sector_t sector;              /* Block sector */
    uint8_t buf[BLOCK_SECTOR_SIZE];     /* Buffer */
} cache_list[64];

void cache_init(void);
void cache_write_back(struct cache *c);
void cache_close(void);
void cache_read(block_sector_t sector, void *buffer);
void cache_write(block_sector_t sector, const void *buffer);
void cache_periodic_write(void);

struct cache* cache_find(block_sector_t sector);
struct cache* find_available(void);