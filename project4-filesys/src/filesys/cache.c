#include "filesys/cache.h"


void cache_init(void)
{
    lock_init(&cache_lock);
    for (int i = 0; i < 64; i++)
    {
        cache_list[i].valid = false;
        cache_list[i].dirty = false;
    }
}

void cache_write_back(struct cache *c)
{
    /* Write back if it is valid and modified. */
    if (c -> valid == true && c -> dirty == true)
    {
        block_write(fs_device, c -> sector, c -> buf);
        c -> dirty = false;
        c -> valid = false;
    }
}

void cache_close(void)
{
    /* Write back all the cache. */
    lock_acquire(&cache_lock);
    for (int i = 0; i < 64; i++)
    {
        cache_write_back(&cache_list[i]);
    }
    lock_release(&cache_lock);
}

 /* Find the cache according to sector. */
struct cache* cache_find(block_sector_t sector)
{
    for(int i = 0; i < 64; i++)
    {
        if (cache_list[i].sector == sector && cache_list[i].valid == true)
        {
            return &cache_list[i];
        }
    }
    return NULL;
}

struct cache* find_available(void)
{
    /* If there's free cache, use it. */
    for (int i = 0; i < 64; i++)
    {
        if (cache_list[i].valid == false)
        {
            return &cache_list[i];
        }
    }

    /* Otherwise, find the least recently used cache. */
    int64_t min = INT64_MAX;
    int min_idx = -1;
    for (int i = 0; i < 64; i++)
    {
        if (cache_list[i].last_used < min)
        {
            min = cache_list[i].last_used;
            min_idx = i;
        }
    }
    cache_write_back(&cache_list[min_idx]);
    return &cache_list[min_idx];
}

void cache_read(block_sector_t sector, void *buffer)
{
    lock_acquire(&cache_lock);

    /* Get cache. */
    struct cache *c = cache_find(sector);
    if (c == NULL)
    {
        c = find_available();
        c -> valid = true;
        c -> dirty = false;
        c -> sector = sector;
        block_read(fs_device, sector, c -> buf);
    }

    /* Set last used time. */
    c -> last_used = timer_ticks();

    /* Copy data from cache to buffer. */
    memcpy(buffer, c -> buf, BLOCK_SECTOR_SIZE);

    lock_release(&cache_lock);
}

void cache_write(block_sector_t sector, const void *buffer)
{
    lock_acquire(&cache_lock);

    /* Get cache. */
    struct cache *c = cache_find(sector);
    if (c == NULL)
    {
        c = find_available();
        c -> valid = true;
        c -> dirty = false;
        c -> sector = sector;
        block_read(fs_device, sector, c -> buf);
    }

    /* Set last used time. */
    c -> last_used = timer_ticks();

    /* Copy data from buffer to cache. */
    memcpy(c -> buf, buffer, BLOCK_SECTOR_SIZE);
    c -> dirty = true;

    lock_release(&cache_lock);
}

void cache_periodic_write(void)
{
    while(true)
    {
        lock_acquire(&cache_lock);
        for (int i = 0; i < 64; i++)
        {
            if(cache_list[i].valid == true && cache_list[i].dirty == true)
            {
                block_write(fs_device, cache_list[i].sector, cache_list[i].buf);
                cache_list[i].dirty = false;
            }
        }
        lock_release(&cache_lock);
        timer_sleep(100);
    }
}
