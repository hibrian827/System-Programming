/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/* single word (4) or double word (8) alignment */
#define ALIGNMENT         8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size)       (((size) + (ALIGNMENT-1)) & ~0x7)


#define SIZE_T_SIZE       (ALIGN(sizeof(size_t)))


// define
#define WSIZE             4
#define DSIZE             8
#define CHUNKSIZE         (1<<12)

#define MAX(x, y)         ((x) > (y) ? (x) : (y))

#define PACK(size, alloc) ((size) | (alloc))

#define GET(p)            (*(unsigned int *) (p))
#define PUT(p, val)       (*(unsigned int *) (p) = (val))

#define GET_SIZE(p)       (GET(p) & ~0x7)
#define GET_ALLOC(p)      (GET(p) & 0x1)

#define HDRP(bp)          ((char *)(bp) - WSIZE)
#define FTRP(bp)          ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

#define NEXT_BLKP(bp)     ((char *)(bp) + GET_SIZE((char *)(bp) - WSIZE))
#define PREV_BLKP(bp)     ((char *)(bp) - GET_SIZE((char *)(bp) - DSIZE))

// static variable
static char *heap_listp;

// static method
static void* coalesce(char * bp)
{
  size_t size = GET_SIZE(bp);
  char *next = NEXT_BLKP(bp);
  char *prev = PREV_BLKP(bp);
  if(GET_ALLOC(next) == 0 && GET_ALLOC(prev) == 0)
  {
    size += GET_SIZE(prev) + GET_SIZE(next);
    PUT(HDRP(prev), PACK(size, 0));
    PUT(FTRP(next), PACK(size, 0));
    bp = prev;
  }
  else if(GET_ALLOC(next) == 0)
  {
    size += GET_SIZE(next);
    PUT(HDRP(bp), PACK(size, 0));
    PUT(FTRP(next), PACK(size, 0));
  }
  else if(GET_ALLOC(prev) == 0)
  {
    size += GET_SIZE(prev);
    PUT(HDRP(prev), PACK(size, 0));
    PUT(FTRP(bp), PACK(size, 0));
    bp = prev;
  }
  return bp;
}

static void* extend_heap(size_t words)
{
  char * bp;
  size_t size;

  size = (words % 2) ? (words + 1) * WSIZE : words * WSIZE;
  if((long)(bp = mem_sbrk(size) == -1)) return NULL;
  PUT(HDRP(bp), PACK(size, 0));
  PUT(FTRP(bp), PACK(size, 0));
  PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1));

  return coalesce(bp);
}

/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
  if(heap_listp = mem_sbrk(4 * WSIZE) == (void *) -1) return -1;
  PUT(heap_listp, 0);
  PUT(heap_listp + WSIZE, PACK(DSIZE, 1));
  PUT(heap_listp + DSIZE, PACK(DSIZE, 1));
  PUT(heap_listp + 3 * WSIZE, PACK(0, 1));
  heap_listp += 2 * WSIZE;
  if(extend_heap(CHUNKSIZE / WSIZE) == NULL) return -1;
  return 0;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
  char* bp;
  size_t asize = ALIGN(size);
  size_t extend_size = MAX(asize, CHUNKSIZE);
  
  if(size == 0) return NULL;
  
  bp = find_fit(asize); // TODO
  if(bp != NULL)
  {
    place(bp, asize); // TODO
    return bp;
  }

  bp = extend_heap(extend_size); 
  if(bp == NULL) return NULL;
  place(bp, asize);
  return bp;
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
  size_t size = GET_SIZE(HDRP(ptr));
  PUT(HDRP(ptr), PACK(size, 0));
  PUT(FTRP(ptr), PACK(size, 0));
  return coalesce(ptr);
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    void *oldptr = ptr;
    void *newptr;
    size_t copySize;
    
    newptr = mm_malloc(size);
    if (newptr == NULL)
      return NULL;
    copySize = *(size_t *)((char *)oldptr - SIZE_T_SIZE);
    if (size < copySize)
      copySize = size;
    memcpy(newptr, oldptr, copySize);
    mm_free(oldptr);
    return newptr;
}