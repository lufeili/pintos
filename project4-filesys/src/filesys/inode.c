#include "filesys/inode.h"
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

static char zeros[BLOCK_SECTOR_SIZE];


/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}


/* Returns the block device sector accouding to index. */
static block_sector_t
index_to_sector (const struct inode_disk *inode_disk, off_t index)
{
  /* Check if the index falls within the range of direct blocks. */
  if(index < DIRECT_BLOCKS_COUNT)
  {
    return inode_disk->direct_blocks[index];
  }
  index -= DIRECT_BLOCKS_COUNT;

  /* Check if the index falls within the range of indirect blocks. */
  if (index < INDIRECT_BLOCKS_PER_SECTOR)
  {
    block_sector_t indirect_blocks[128];
    cache_read (inode_disk->indirect_block, indirect_blocks);
    block_sector_t sec = indirect_blocks[index];

    return sec;
  }
  index -= INDIRECT_BLOCKS_PER_SECTOR;

  /* Check if the index falls within the range of double-indirect blocks. */
  if (index < INDIRECT_BLOCKS_PER_SECTOR * INDIRECT_BLOCKS_PER_SECTOR)
  {
    off_t index_l1 = index / INDIRECT_BLOCKS_PER_SECTOR; 
    off_t index_l2 = index % INDIRECT_BLOCKS_PER_SECTOR; 

    block_sector_t indirect_blocks[128];
    cache_read (inode_disk->double_indirect_block, indirect_blocks);
    cache_read (indirect_blocks[index_l1], indirect_blocks);
    block_sector_t sec = indirect_blocks[index_l2];

    return sec;
  }

  return -1;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  if (pos < inode->data.length)
    return index_to_sector (&inode->data, pos / BLOCK_SECTOR_SIZE);
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

bool allocate_one_block(block_sector_t *sec)
{
  if(*sec == 0)
  {
    if(free_map_allocate(1, sec))
    {
      cache_write(*sec, zeros);
      return true;
    }
    else
      return false;
  }
  else
    return true;
}

bool allocate_indirect(block_sector_t *p_sec, size_t num_sectors) 
{
  block_sector_t indirect_blocks[128];
  
  /* Allocate indirect block. */
  bool success = allocate_one_block(p_sec);
  if (!success) 
      return false;
  cache_read(*p_sec, &indirect_blocks);

  /* Allocate data blocks. */
  for (size_t i = 0; i < num_sectors; ++i) 
  {
      if (!allocate_one_block(&indirect_blocks[i])) 
      {
          return false;
      }
  }
  cache_write(*p_sec, &indirect_blocks);
  return true;
}

bool allocate_double_indirect(block_sector_t *p_sec, size_t num_sectors) 
{
    block_sector_t indirect_block_2[128];

    /* Allocate double indirect block.*/
    bool success = allocate_one_block(p_sec);
    if (!success)
        return false;

    cache_read(*p_sec, &indirect_block_2);

    /* Allocate indirect blocks.*/
    size_t l1_num = DIV_ROUND_UP(num_sectors, 128);
    for (size_t i = 0; i < l1_num; ++i)
    {
        block_sector_t indirect_block_1[128];
        block_sector_t *p_sec_1 = &indirect_block_2[i];
        if(!allocate_one_block(p_sec_1))
          return false;
        cache_read(*p_sec_1, &indirect_block_1);

        /* Allocate data blocks.*/
        size_t l2_num = MIN(num_sectors, 128);
        for (size_t j = 0; j < l2_num; ++j) 
        {
            if (!allocate_one_block(&indirect_block_1[j])) 
                return false;
        }
        cache_write(*p_sec_1, &indirect_block_1);
        num_sectors -= l2_num;
    }
    cache_write(*p_sec, &indirect_block_2);
    return true;
}

bool allocate (struct inode_disk *inode, off_t len)
{
  size_t sector_num = bytes_to_sectors (len);

  /* Allocate direct. */
  if(sector_num <= DIRECT_BLOCKS_COUNT)
  {
    for(size_t i = 0; i < sector_num; i++)
    {
      if(allocate_one_block(&inode->direct_blocks[i]) == false)
        return false;
    }
    return true;
  }
  else
  {
    /* Allocate indirect. */
    for(size_t i = 0; i < DIRECT_BLOCKS_COUNT; i++)
    {
      if(allocate_one_block(&inode->direct_blocks[i]) == false)
        return false;
    }
    sector_num -= DIRECT_BLOCKS_COUNT;
    if(sector_num <= 128)
    {
      if(allocate_indirect(&inode->indirect_block, sector_num ) == false)
        return false;
      return true;
    }
    else
    {
      /* Allocate double indirect.*/
      if(allocate_indirect(&inode->indirect_block, 128) == false)
        return false;
      sector_num -= 128;
      if(allocate_double_indirect(&inode->double_indirect_block, sector_num) == false)
        return false;
      return true;
    }
  }
}


/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
  {
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    disk_inode->is_dir = is_dir;
    
    if (allocate (disk_inode, length)) 
    {
      cache_write (sector, disk_inode);
      success = true; 
    } 
    free (disk_inode);
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  cache_read (inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}


bool inode_release (struct inode *inode)
{
  if(inode->data.length < 0)
    return false;
  off_t num = bytes_to_sectors(inode->data.length);

  /* Release direct blocks. */
  if(num < DIRECT_BLOCKS_COUNT)
    for(size_t i = 0; i < num; i++)
      free_map_release(inode->data.direct_blocks[i], 1);
  else
  {
    /* Release direct blocks. */
    for(size_t i = 0; i < DIRECT_BLOCKS_COUNT; i++)
      free_map_release(inode->data.direct_blocks[i], 1);
    num -= DIRECT_BLOCKS_COUNT;
    /* Release indirect blocks. */
    if(num <= 128)
    {
      block_sector_t indirect_blocks[128];
      cache_read(inode->data.indirect_block, indirect_blocks);
      for(size_t i = 0; i < num; i++)
        free_map_release(indirect_blocks[i], 1);
      free_map_release(inode->data.indirect_block, 1);
    }
    else
    {
      /* Release indirect blocks. */
      block_sector_t indirect_blocks[128];
      cache_read(inode->data.indirect_block, indirect_blocks);
      for(size_t i = 0; i < 128; i++)
        free_map_release(indirect_blocks[i], 1);
      free_map_release(inode->data.indirect_block, 1);
      num -= 128;

      /* Release double indirect blocks.*/
      off_t num_l1 = num / 128;
      off_t num_l2 = num % 128;
      block_sector_t indirect_blocks_1[128];
      cache_read(inode->data.double_indirect_block, indirect_blocks_1);
      for(size_t i = 0; i < num_l1; i++)
      {
        block_sector_t indirect_blocks_2[128];
        cache_read(indirect_blocks_1[i], indirect_blocks_2);
        for(size_t j = 0; j < 128; j++)
          free_map_release(indirect_blocks_2[j], 1);
        free_map_release(indirect_blocks_1[i], 1);
      }
      if(num_l2 > 0)
      {
        block_sector_t indirect_blocks_2[128];
        cache_read(indirect_blocks_1[num_l1], indirect_blocks_2);
        for(size_t j = 0; j < num_l2; j++)
          free_map_release(indirect_blocks_2[j], 1);
        free_map_release(indirect_blocks_1[num_l1], 1);
      }
      free_map_release(inode->data.double_indirect_block, 1);
    }
  }
  return true;
  
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          inode_release(inode);
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          cache_read (sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          cache_read ( sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  /* If there isn't enough space, extend inode. */
  if(offset + size > inode->data.length)
  {
    if(!allocate(&inode->data, offset + size))
      return 0;

    /* Update inode */
    inode->data.length = offset + size;
    cache_write (inode->sector, & inode->data);
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          cache_write ( sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            cache_read (sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          cache_write (sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}
