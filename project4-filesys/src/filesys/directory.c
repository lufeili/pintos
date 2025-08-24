#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt)
{
  if(!inode_create(sector, entry_cnt * sizeof(struct dir_entry),true))
    return false;

  struct dir *dir = dir_open (inode_open(sector));
  if (dir == NULL)
    return false;
  
  /* Store parent directory. */
  struct dir_entry de;
  de.inode_sector = sector;
  if (inode_write_at (dir->inode, &de, sizeof(de), 0) != sizeof(de))
  {
    dir_close (dir);
    return false;
  }
  dir_close (dir);
  return true;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;

      /* Skip the first entry. */
      dir->pos = sizeof (struct dir_entry);

      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

struct dir *
dir_open_path (const char *path)
{
  int l = strlen(path);
  char *path_copy = (char*) malloc(sizeof(char) * (l + 1));
  memcpy (path_copy, path, sizeof(char) * (l + 1));

  struct dir *cwd;

  /* Absolute path? */
  if(path[0] == '/')
    cwd = dir_open_root();
  else
  {
    struct thread *t = thread_current();
    /*Main thread?*/
    if (t->cur_dir == NULL) 
      cwd = dir_open_root();
    else
      cwd = dir_reopen(t->cur_dir);
  }

  char *save_ptr;

  /* Split path and open the directoried in the path. */
  for (char *token = strtok_r(path_copy, "/", &save_ptr); token != NULL; token = strtok_r(NULL, "/", &save_ptr))
  {
    struct inode *inode = NULL;
    struct dir *next = NULL;

    if(strlen(token) == 0)
      continue;

    if(!dir_lookup(cwd, token, &inode))
    {
      dir_close(cwd);
      free(path_copy);
      return NULL;
    }
    next = dir_open(inode);
    /* Check whether next is opened. */
    if(!next)
    {
      dir_close(cwd);
      free(path_copy);
      return NULL;
    }

    dir_close(cwd); 
    cwd = next;
  }

  /* Deal with deleted directory. */
  if (dir_get_inode(cwd)->removed)
  {
    dir_close(cwd);
    free(path_copy);
    return NULL;
  }

  free(path_copy);
  return cwd;
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  struct dir_entry de;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /*If it is the current directory, reopen itself. */
  if (strcmp (name, ".") == 0)
  {
    *inode = inode_reopen (dir->inode);
    return *inode!= NULL;
  }

  /*If it is the parent directory, load the first entry. */
  if (strcmp (name, "..") == 0)
  {
    inode_read_at (dir->inode, &de, sizeof(de), 0);
    *inode = inode_open (de.inode_sector);
    return *inode!= NULL;
  }

  /*If it is not current or parent. */
  if (lookup (dir, name, &de, NULL))
  {
    *inode = inode_open (de.inode_sector);
  }
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Check every entry of the dir to see if it is empty. */
bool dir_is_empty (const struct dir *dir)
{
  struct dir_entry e;

  for (off_t ofs = sizeof(e); inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e) 
    if(e.in_use)
      return false;

  return true;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector, bool is_dir)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /*Add a child directory.*/
  if (is_dir)
  {
    struct dir *child_dir = dir_open(inode_open(inode_sector));
    if(child_dir == NULL)
      return false;
    
    e.inode_sector = dir->inode->sector;
    
    /* Store parent at the first entry. */
    if (inode_write_at(child_dir->inode, &e, sizeof(e), 0) != sizeof(e))
    {
      dir_close (child_dir);
      return false;
    }
    dir_close (child_dir);
  }

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;
  
  /*Deal with dir that is not empty.*/
  if (inode->data.is_dir)
  {
    struct dir *dir = dir_open (inode);
    if(!dir_is_empty(dir))
    {
      dir_close (dir);
      inode_close (inode);
      return false;
    }
  }

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}
