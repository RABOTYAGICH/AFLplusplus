/*
   american fuzzy lop++ - shared memory related code
   -------------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#define AFL_MAIN

#ifdef __ANDROID__
  #include "android-ashmem.h"
#endif
#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"
#include "sharedmem.h"
#include "cmplog.h"
#include "list.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>

#ifndef USEMMAP
  #include <sys/ipc.h>
  #include <sys/shm.h>
#endif
#define SHM_ID 7
#define MAX_MEM 29572904
#define ARR_SIZE 16

static list_t shm_list = {.element_prealloc_count = 0};

/* Get rid of shared memory. */

void *_shmalloc(int id, size_t *size, void *shmptr, size_t shm_size,
                char *filename, int linenumber)
{

    Header *first, *curr, *best_fit;
    size_t free_size, best_block_size;

    // Verify pointers
    if (shmptr == NULL) {
        fprintf(stderr, "%s, line %d: Shared memory pointer cannot be null.\n",
                        filename, linenumber);
        return NULL;
    }
    if (size == NULL) {
        fprintf(stderr, "%s, line %d: Size pointer cannot be null.\n",
                        filename, linenumber);
        return NULL;
    }
    if (*size == 0) {
        // Like malloc(3), passing in a size of zero returns either NULL or
        // another pointer that can be successfully passed into shmfree()
        fprintf(stderr, "%s, line %d: Warning: allocating a pointer of size "
                        "zero returns NULL.\n", filename, linenumber);
        return NULL;
    }
    if (*size < 0) {
        fprintf(stderr, "%s, line %d: Cannot allocate a negative amount of "
                        "memory in shmalloc().\n", filename, linenumber);
        return NULL;
    }


    // Find the first header
    first = curr = (Header *) shmptr; best_fit = NULL;

    // First time calling shmalloc
    if(!first || first->bitseq != BITSEQ)
    {
        free_size = shm_size;

        initialize_header(first, free_size, id, 1);
        first->is_free = 0;
        first->refcount++;

        //Create the next header if we have enough room
        
        curr = (Header *)((char *)shmptr + sizeof(Header) + *size);
        initialize_header(curr, free_size - (*size), -1, 0);
        first->next = ptr2offset(curr, shmptr);
        curr->prev = ptr2offset(first, shmptr);
    
        int qq = first + 1;
        return (first + 1);
    }
    else
    {

        //Lock shared memory
        pthread_mutex_lock(&(first->mutex));

        best_block_size = -1;

        //Loop through all headers to see if id already exists
        //Also record best spot to put this new item if it does not exist
        while(curr != NULL)
        {

            if(curr->id == id && !curr->is_free)
            {

                //Already have item with this id
                curr->refcount++;
                *size = curr->size;

                //Can unlock mutex and return here
                pthread_mutex_unlock(&(first->mutex));
                return (curr + 1);
            }

            //Get size of this block
            if((curr->size < best_block_size || best_block_size == -1) && curr->size >= *size && curr->is_free == 1)
            {
                best_block_size = curr->size;
                best_fit = curr;
            }

            curr = (Header *) offset2ptr(curr->next, shmptr);
        }

        //Did not find existing entry

        if(best_fit == NULL)
        {
            //Did not find a viable chunk, failure
            fprintf(stderr, "%s, line %d: shmalloc() ran out of available space"
                            " to satisfy the request.\n", filename, linenumber);
            pthread_mutex_unlock(&(first->mutex));
            return NULL;
        }

        //Found a viable chunk - use it
        free_size = best_fit->size; //Total size of chunk before next header
        best_fit->size = *size;
        best_fit->refcount = 1;
        best_fit->id = id;
        best_fit->is_free = 0;

        //Check if there is enough room to make another header
        if((free_size - best_fit->size) > sizeof(Header))
        {
            curr = (Header *) ((char *) best_fit + best_fit->size + sizeof(Header));
            initialize_header(curr, (size_t)((char *)free_size - best_fit->size - sizeof(Header)), -1, 0);

            //Adjust pointers
            curr->prev = ptr2offset(best_fit, shmptr);
            curr->next = best_fit->next;
            if(best_fit->next != -1)
            {
                ((Header *)offset2ptr(best_fit->next, shmptr))->prev = ptr2offset(curr, shmptr);
            }

            best_fit->next = ptr2offset(curr, shmptr);
        }
        else {
            best_fit->size = free_size;
        }

        pthread_mutex_unlock(&(first->mutex));

        return (best_fit + 1);
    }
}

/*
 * Frees an object in shared memory
 */
void _shmfree(void *shmptr, size_t shm_size, void *shm_ptr, char *filename, int linenumber)
{
    Header *h, *first;
    if (shmptr == NULL) {
        // Like free(3), shmfree() of a NULL pointer has no effect
        fprintf(stderr, "%s, line %d: free() on a NULL pointer does nothing.\n",
                        filename, linenumber);
        return;
    }

    //Get the associated header
    h = ((Header *) shmptr) - 1;

    // More verification checks
    if(h->bitseq != BITSEQ) {
        fprintf(stderr, "%s, line %d: Attempted to free a pointer not allocated"
                        " by shmalloc() or corruption of internal memory has "
                        "occurred. Check your memory accesses.\n",
                        filename, linenumber);
        return;
    }
    if (h->is_free) {
        fprintf(stderr, "%s, line %d: Attempt to shmfree() a pointer that has "
                        "already been freed.\n", filename, linenumber);
        return;
    }

    //LOCK EVERYTHING
    first = (Header *) shm_ptr;
    pthread_mutex_lock(&(first->mutex));

    //If we are the last reference
    if(--(h->refcount) <= 0)
    {
        //Adjust our size
        if(h->next != -1)
        {
            h->size = (char *)offset2ptr(h->next, shm_ptr) - (char *)h - sizeof(Header);
        }
        else
        {
            h->size = (char *) shm_size - (char *)h - sizeof(Header);
        }

        /*Check if we can delete our next to free up space*/
        if(h->next != -1 && ((Header *) offset2ptr(h->next, shm_ptr))->is_free)
        {
            h->size += (size_t) ((char *)((Header *) offset2ptr(h->next, shm_ptr))->size + sizeof(Header));
            destroy_header((Header *)offset2ptr(h->next, shm_ptr), shm_ptr);
        }

        //Don't delete the first entry
        if(h != first) {

            if(h->prev != -1 && ((Header *) offset2ptr(h->prev, shm_ptr))->is_free)
            {
                ((Header *) offset2ptr(h->prev, shm_ptr))->size += (size_t) ((char *)h->size + sizeof(Header));
                destroy_header(h, shm_ptr);
                h = NULL;
            }
        }

        //Need to set h to freed
        if(h != NULL || h == first)
        {
            h->is_free = 1;
        }
    }

    pthread_mutex_unlock(&(first->mutex));
}

void initialize_header(Header *h, size_t size, int id, unsigned char is_first)
{
    //Sanity check
    if(h == NULL)
        return;

    h->prev = -1;
    h->next = -1;
    h->size = size;
    h->refcount = 0;
    h->id = id;
    h->is_free = 1;
    h->bitseq = BITSEQ;

    if(is_first) {
        h->has_mutex = 1;
        pthread_mutexattr_init(&(h->attr));
        pthread_mutexattr_setpshared(&(h->attr), PTHREAD_PROCESS_SHARED);
        pthread_mutex_init(&(h->mutex), &(h->attr));
    }
    else
    {
        h->has_mutex = 0;
    }
}

/*
 * Destroys a header struct
 * Assumes that if a mutex exists, it is locked
 */
void destroy_header(Header *h, void *shm_ptr)
{
    //Sanity check
    if(h == NULL)
        return;

    //Adjust previous and next accordingly
    if(h->prev != -1)
    {
        ((Header *)offset2ptr(h->prev, shm_ptr))->next = h->next;
        printf("prev next is %p\n", ((Header *)offset2ptr(h->prev, shm_ptr)));
    }
    if(h->next != -1)
    {
        ((Header *)offset2ptr(h->next, shm_ptr))->prev = h->prev;
    }

    //Now the list is good, corrupt bitseq to be safe
    h->bitseq += 1;
    h->next = -1;
    h->prev = -1;

    //Screw up ptrs
    h->next = -1;
    h->prev = -1;

    //Unlock and destroy mutex
/*    if(h->has_mutex)
    {
        pthread_mutex_unlock(&(h->mutex));
        pthread_mutex_destroy(&(h->mutex));
    }*/

}

long ptr2offset(void *ptr, void *shm_ptr)
{
    if(ptr == NULL) return -1;
    return ptr - shm_ptr;
}

void *offset2ptr(long offset, void *shm_ptr)
{
    if(offset == -1) return NULL;
    return (char *)shm_ptr + offset;
}



void addEntry(ht_entry *entry)
{
    size_t dbl_sizeHt = sizeof(ht_original);
    size_t dbl_sizeDl = sizeof(unsigned long long)*20;

    ht_original *tmp = (ht_original*) shmalloc(id_sh, &dbl_sizeHt, shm_ptr, MAX_MEM);
    id_sh++;
    tmp->addrs = (unsigned long long*) shmalloc(id_sh, &dbl_sizeDl, shm_ptr, MAX_MEM);
    id_sh++;
    tmp->addrs[0] = id_sh;
    tmp->next = entry->head;
    tmp->count=1;

    entry->head = tmp;
    entry->original = *tmp; 

}

void afl_shm_deinit(sharedmem_t *shm) {

  if (shm == NULL) { return; }
  list_remove(&shm_list, shm);
  if (shm->shmemfuzz_mode) {

    unsetenv(SHM_FUZZ_ENV_VAR);

  } else {
    
    unsetenv(SHM_ENV_VAR);
    unsetenv(SHM_ENV_VAR2);
    OKF("UNSET!\n");


  }

#ifdef USEMMAP
  if (shm->map != NULL) {

    munmap(shm->map, shm->map_size);
    shm->map = NULL;

  }

  if (shm->g_shm_fd != -1) {

    close(shm->g_shm_fd);
    shm->g_shm_fd = -1;

  }

  if (shm->g_shm_file_path[0]) {

    shm_unlink(shm->g_shm_file_path);
    shm->g_shm_file_path[0] = 0;

  }

  if (shm->cmplog_mode) {

    unsetenv(CMPLOG_SHM_ENV_VAR);

    if (shm->cmp_map != NULL) {

      munmap(shm->cmp_map, shm->map_size);
      shm->map = NULL;

    }

    if (shm->cmplog_g_shm_fd != -1) {

      close(shm->cmplog_g_shm_fd);
      shm->cmplog_g_shm_fd = -1;

    }

    if (shm->cmplog_g_shm_file_path[0]) {

      shm_unlink(shm->cmplog_g_shm_file_path);
      shm->cmplog_g_shm_file_path[0] = 0;

    }

  }

#else
  shmctl(shm->shm_id, IPC_RMID, NULL);
  shmctl(shm->id_shm, IPC_RMID, NULL);

  if (shm->cmplog_mode) { shmctl(shm->cmplog_shm_id, IPC_RMID, NULL); }
#endif

  shm->map = NULL;

}

/* Configure shared memory.
   Returns a pointer to shm->map for ease of use.
*/

u8 *afl_shm_init(sharedmem_t *shm, size_t map_size,
                 unsigned char non_instrumented_mode) {

  shm->map_size = 0;

  shm->map = NULL;
  shm->cmp_map = NULL;

#ifdef USEMMAP

  shm->g_shm_fd = -1;
  shm->cmplog_g_shm_fd = -1;

  /* ======
  generate random file name for multi instance

  thanks to f*cking glibc we can not use tmpnam securely, it generates a
  security warning that cannot be suppressed
  so we do this worse workaround */
  snprintf(shm->g_shm_file_path, L_tmpnam, "/afl_%d_%ld", getpid(), random());

  /* create the shared memory segment as if it was a file */
  shm->g_shm_fd = shm_open(shm->g_shm_file_path, O_CREAT | O_RDWR | O_EXCL,
                           DEFAULT_PERMISSION);
  if (shm->g_shm_fd == -1) { PFATAL("shm_open() failed"); }

  /* configure the size of the shared memory segment */
  if (ftruncate(shm->g_shm_fd, map_size)) {

    PFATAL("setup_shm(): ftruncate() failed");

  }

  /* map the shared memory segment to the address space of the process */
  shm->map =
      mmap(0, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm->g_shm_fd, 0);
  if (shm->map == MAP_FAILED) {

    close(shm->g_shm_fd);
    shm->g_shm_fd = -1;
    shm_unlink(shm->g_shm_file_path);
    shm->g_shm_file_path[0] = 0;
    PFATAL("mmap() failed");

  }

  /* If somebody is asking us to fuzz instrumented binaries in non-instrumented
     mode, we don't want them to detect instrumentation, since we won't be
     sending fork server commands. This should be replaced with better
     auto-detection later on, perhaps? */

  if (!non_instrumented_mode) setenv(SHM_ENV_VAR, shm->g_shm_file_path, 1);

  if (shm->map == (void *)-1 || !shm->map) PFATAL("mmap() failed");

  if (shm->cmplog_mode) {

    snprintf(shm->cmplog_g_shm_file_path, L_tmpnam, "/afl_cmplog_%d_%ld",
             getpid(), random());

    /* create the shared memory segment as if it was a file */
    shm->cmplog_g_shm_fd =
        shm_open(shm->cmplog_g_shm_file_path, O_CREAT | O_RDWR | O_EXCL,
                 DEFAULT_PERMISSION);
    if (shm->cmplog_g_shm_fd == -1) { PFATAL("shm_open() failed"); }

    /* configure the size of the shared memory segment */
    if (ftruncate(shm->cmplog_g_shm_fd, map_size)) {

      PFATAL("setup_shm(): cmplog ftruncate() failed");

    }

    /* map the shared memory segment to the address space of the process */
    shm->cmp_map = mmap(0, map_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                        shm->cmplog_g_shm_fd, 0);
    if (shm->cmp_map == MAP_FAILED) {

      close(shm->cmplog_g_shm_fd);
      shm->cmplog_g_shm_fd = -1;
      shm_unlink(shm->cmplog_g_shm_file_path);
      shm->cmplog_g_shm_file_path[0] = 0;
      PFATAL("mmap() failed");

    }

    /* If somebody is asking us to fuzz instrumented binaries in
       non-instrumented mode, we don't want them to detect instrumentation,
       since we won't be sending fork server commands. This should be replaced
       with better auto-detection later on, perhaps? */

    if (!non_instrumented_mode)
      setenv(CMPLOG_SHM_ENV_VAR, shm->cmplog_g_shm_file_path, 1);

    if (shm->cmp_map == (void *)-1 || !shm->cmp_map)
      PFATAL("cmplog mmap() failed");

  }

#else
  u8 *shm_str;
  int shm_id;
  char shm_id_ptr[15];
  shm->shm_id =
      shmget(IPC_PRIVATE, map_size, IPC_CREAT | IPC_EXCL | DEFAULT_PERMISSION);
  if (shm->shm_id < 0) {

    PFATAL("shmget() failed, try running afl-system-config");

  }

  if (shm->cmplog_mode) {

    shm->cmplog_shm_id = shmget(IPC_PRIVATE, sizeof(struct cmp_map),
                                IPC_CREAT | IPC_EXCL | DEFAULT_PERMISSION);

    if (shm->cmplog_shm_id < 0) {

      shmctl(shm->shm_id, IPC_RMID, NULL);  // do not leak shmem
      PFATAL("shmget() failed, try running afl-system-config");

    }

  }

  if (!non_instrumented_mode) {

    shm_str = alloc_printf("%d", shm->shm_id);

    /* If somebody is asking us to fuzz instrumented binaries in
       non-instrumented mode, we don't want them to detect instrumentation,
       since we won't be sending fork server commands. This should be replaced
       with better auto-detection later on, perhaps? */
    
    setenv(SHM_ENV_VAR, shm_str, 1);


    char *cov_r = getenv("AFL_COVERAGE");
    bool r_cov = atoi(cov_r);
    
    if (r_cov == 1)
    {
    
    
      if ((shm->id_shm = shmget(IPC_PRIVATE, MAX_MEM, 0777 | IPC_CREAT | IPC_EXCL)) == -1) {
          printf("errno %d\n",errno );

          fprintf(stderr, "Failed to get a shared memory segment.\n");
          exit(EXIT_FAILURE);
      }


      if ((shm_ptr = shmat(shm->id_shm, NULL, 0)) == (void *) -1) {
          printf("errno %d\n",errno );

          fprintf(stderr, "Failed to attach to our shared memory segment.\n");
          exit(EXIT_FAILURE);
      }
      sprintf(shm_id_ptr, "%d", shm->id_shm);
      int check = setenv(SHM_ENV_VAR2,shm_id_ptr,1);
    }
    
    ck_free(shm_str);

  }

  if (shm->cmplog_mode && !non_instrumented_mode) {

    shm_str = alloc_printf("%d", shm->cmplog_shm_id);

    setenv(CMPLOG_SHM_ENV_VAR, shm_str, 1);

    ck_free(shm_str);

  }

  shm->map = shmat(shm->shm_id, NULL, 0);

  if (shm->map == (void *)-1 || !shm->map) {

    shmctl(shm->shm_id, IPC_RMID, NULL);  // do not leak shmem

    if (shm->cmplog_mode) {

      shmctl(shm->cmplog_shm_id, IPC_RMID, NULL);  // do not leak shmem

    }

    PFATAL("shmat() failed");

  }

  if (shm->cmplog_mode) {

    shm->cmp_map = shmat(shm->cmplog_shm_id, NULL, 0);

    if (shm->cmp_map == (void *)-1 || !shm->cmp_map) {

      shmctl(shm->shm_id, IPC_RMID, NULL);  // do not leak shmem

      shmctl(shm->cmplog_shm_id, IPC_RMID, NULL);  // do not leak shmem

      PFATAL("shmat() failed");

    }

  }

#endif

  shm->map_size = map_size;
  list_append(&shm_list, shm);

  return shm->map;

}

