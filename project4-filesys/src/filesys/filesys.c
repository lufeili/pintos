#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "threads/thread.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Split name into dir path and file name. */
void name_split(const char *path, char *directory, char *filename)
{
  int l = strlen(path);
  if(l == 0)
  {
    *directory = '\0';
    *filename = '\0';
    return;
  }
  int pos = 0;
  int i = l - 1;
  for (; i >= 0; i--)
  {
    if (path[i] == '/')
    {
      pos = i;
      break;
    }
  }
  if(i < 0)
  {
    *directory = '\0';
    memcpy (filename, path, sizeof(char) * (l + 1));
  }
  else
  {
    memcpy (directory, path, sizeof(char) * (pos + 1));
    directory[pos + 1] = '\0';
    memcpy (filename, path + pos + 1, sizeof(char) * (l - pos));
    filename[l - pos - 1] = '\0';
  }
}

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();
  cache_init();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  cache_close();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool is_dir) 
{
  block_sector_t inode_sector = 0;

  char directory[512];
  char filename[512];
  name_split(name, directory, filename);
  struct dir *dir = dir_open_path (directory);
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, is_dir)
                  && dir_add (dir, filename, inode_sector, is_dir));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  /*struct dir *dir = dir_open_root ();
  struct inode *inode = NULL;

  if (dir != NULL)
    dir_lookup (dir, name, &inode);
  dir_close (dir);

  return file_open (inode);*/
  int l = strlen(name);
  if (l == 0)
    return NULL;

  char directory[512];
  char filename[512];
  name_split(name, directory, filename);
  struct dir *dir = dir_open_path (directory);

  if (dir == NULL)
    return NULL;

  struct inode *inode = NULL;

  /* Check whether the target is a file or directory. */
  if (strlen(filename) > 0)
  {
    dir_lookup (dir, filename, &inode);
    dir_close (dir);
  }
  else
    inode = dir_get_inode(dir);

  if (inode == NULL )
    return NULL;
  if(inode->removed == true)
    return NULL;
  
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  /*struct dir *dir = dir_open_root ();
  bool success = dir != NULL && dir_remove (dir, name);
  dir_close (dir); 

  return success;*/
  int l = strlen(name);
  char directory[512];
  char filename[512];
  name_split(name, directory, filename);
  struct dir *dir = dir_open_path (directory);

  bool success = (dir != NULL && dir_remove (dir, filename));
  dir_close (dir);

  
  return success;
}

bool
filesys_cd (const char *name)
{
  /* Open child directory. */
  struct dir *dir = dir_open_path (name);
  if(dir == NULL)
    return false;

  /* Close previous directory. */
  dir_close (thread_current()->cur_dir);
  
  /* Set new directory. */
  thread_current()->cur_dir = dir;
  return true;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
