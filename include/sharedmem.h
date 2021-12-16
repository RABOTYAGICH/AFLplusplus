/*
   american fuzzy lop++ - shared memory related header
   ---------------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#ifndef __AFL_SHAREDMEM_H
#define __AFL_SHAREDMEM_H
#include <pthread.h>

#include "types.h"
#define SHM_ENV_VAR2 "__AFL_SHM_ID2"
typedef struct ht_original
{
    unsigned long long *addrs;
    struct ht_original *next;
    int count;
} ht_original;


void *shm_ptr;
static int id_sh = 0;

typedef struct ht_entry {
    ht_original original;
    ht_original *head;
} ht_entry;
#define INITIAL_CAPACITY 65537  // must not be zero

// Hash table structure: create with ht_create, free with ht_destroy.
typedef struct ht {
    ht_entry entries[65547];  // hash slots
    unsigned int length;      // number of items in hash table
    int id;
    
} ht;

struct Header {
    int bitseq;
    int id;
    int refcount;
    size_t size;
    long prev, next; // offsets
    unsigned char has_mutex;
    unsigned char is_free;
    pthread_mutex_t mutex;
    pthread_mutexattr_t attr;
};
#define BITSEQ 536870911
#define shmalloc(i, s, p, sz) _shmalloc(i, s, p, sz, __FILE__, __LINE__)
#define shmfree(ptr, sz, s) _shmfree(ptr, sz, s,  __FILE__, __LINE__)

typedef struct Header Header;

/**
 * Initializes values in header
 */
void initialize_header(Header *h, size_t size, int id, unsigned char is_first);

/**
 * Destroys the given header structure.
 */
void destroy_header(Header *, void *);

/**
 * Allocate shared .memory that's already been attached via shmat(3).
 * Returns a pointer to the newly allocated memory.
 */
void *_shmalloc(int id, size_t *size, void *shmptr, size_t shm_size,
                char *filename, int linenumber);

/**
 * Frees a block of shared memory previously allocated with shmalloc().
 */
void _shmfree(void *ptr, size_t shm_size, void *shm_ptr, char *filename, int linenumber);

long ptr2offset(void *ptr, void *shm_ptr);

void *offset2ptr(long offset, void *shm_ptr);


typedef struct sharedmem {

  // extern unsigned char *trace_bits;

#ifdef USEMMAP
  /* ================ Proteas ================ */
  int  g_shm_fd;
  char g_shm_file_path[L_tmpnam];
  int  cmplog_g_shm_fd;
  char cmplog_g_shm_file_path[L_tmpnam];
/* ========================================= */
#else
  s32 shm_id;                          /* ID of the SHM region              */
  s32 id_shm;                          /* ID of the SHM region              */

  s32 cmplog_shm_id;
#endif

  u8 *map;                                          /* shared memory region */
  ht *shared_memory;                                          /* shared memory region */


  size_t map_size;                                 /* actual allocated size */

  int             cmplog_mode;
  int             shmemfuzz_mode;
  struct cmp_map *cmp_map;

} sharedmem_t;

u8 * afl_shm_init(sharedmem_t *, size_t, unsigned char non_instrumented_mode);
void afl_shm_deinit(sharedmem_t *);
#define MAX_MEM 29572904



#endif

