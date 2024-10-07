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
#define ALIGNMENT             8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size)           (((size) + (ALIGNMENT-1)) & ~0x7)


#define SIZE_T_SIZE           (ALIGN(sizeof(size_t)))


// define
#define WSIZE                 4
#define DSIZE                 8
#define CHUNKSIZE             (1 << 12)

#define MAX(x, y)             ((x) > (y) ? (x) : (y))

#define PACK(size, alloc)     ((size) | (alloc))

#define GET(p)                (*(unsigned int *) (p))
#define PUT(p, val)           (*(unsigned int *) (p) = (val))

#define GET_SIZE(p)           (GET(p) & ~0x7)
#define GET_ALLOC(p)          (GET(p) & 0x1)

#define HDRP(bp)              ((char *)(bp) - WSIZE)
#define FTRP(bp)              ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

#define NEXT_BLKP(bp)         ((char *)(bp) + GET_SIZE((char *)(bp) - WSIZE))
#define PREV_BLKP(bp)         ((char *)(bp) - GET_SIZE((char *)(bp) - DSIZE))

#define GET_PREV_FREE(bp)     (*(unsigned long *) (bp))
#define GET_NEXT_FREE(bp)     (*(unsigned long *) (bp + DSIZE))
#define SET_PREV_FREE(bp, p)  (*(unsigned long *) (bp) = (p))
#define SET_NEXT_FREE(bp, p)  (*(unsigned long *) (bp + DSIZE) = (p))

#define SIZE_NUM 4

// static variable
static char *heap_listp;

static int size_class[SIZE_NUM] = {1 << 4, 1 << 8, 1 << 12, 1 << 16};
static void* free_list[SIZE_NUM + 1];

// static method
static int mm_check()
{
  printf("\n************** starting heap check **************\n\n");
  void * start_p = mem_heap_lo();
  printf("heap starts in %p\n", start_p);
  void* bp;
  int wasFree = 0;
  for(bp = heap_listp; GET_SIZE(HDRP(bp)) > 0; bp = NEXT_BLKP(bp))
  {
    // print each blk
    printf("%p ---- header : size=%6d ----\n", HDRP(bp), GET_SIZE(HDRP(bp)));
    if(GET_ALLOC(HDRP(bp))) printf("%p |          allocate          |\n", bp);
    else printf("%p |            free            |\n", bp);
    printf("%p ---- footer : size=%6d ----\n", FTRP(bp), GET_SIZE(FTRP(bp)));
    // check alignment
    if((long)bp % ALIGNMENT != 0) {
      printf("!!! not aligned !!!!\n");
      return -1;
    }
    // check header and footer
    if(GET_SIZE(HDRP(bp)) != GET_SIZE(FTRP(bp)) || GET_ALLOC(HDRP(bp)) != GET_ALLOC(FTRP(bp))) {
      printf("!!! header and footer not same !!!!\n");
      return -1;
    }
    // check coalescing
    if(wasFree && GET_ALLOC(HDRP(bp)) == 0) {
      printf("!!! coalesce failed !!!!\n");
      return -1;
    }
    wasFree = !GET_ALLOC(HDRP(bp));
  }
  void * end_p = mem_heap_hi();
  printf("heap ends in %p\n\n", end_p);
  printf("free list:\n");
  for(int i = 0; i < SIZE_NUM; i++) {
    printf("%5d : %p\n", size_class[i], free_list[i]);
  }
  printf("large : %p\n\n", free_list[SIZE_NUM]);
  printf("\n\n*************** ending heap check ***************\n\n");
  return 0;
}

static void add_free(void *bp) {
  size_t size = GET_SIZE(HDRP(bp));
  for(int i = 0; i < SIZE_NUM; i++) {
    if(size <= size_class[i]) {
      void *ptr = free_list[i];
      // TODO: need fixing
      while(ptr) ptr = GET_NEXT_FREE(ptr);
      free_list[i] = bp;
      return;
    }
  }
}

// TODO
static void* coalesce(void * bp)
{
  size_t size = GET_SIZE(HDRP(bp));
  void *next = NEXT_BLKP(bp);
  void *prev = PREV_BLKP(bp);
  if(GET_ALLOC(HDRP(next)) == 0 && GET_ALLOC(HDRP(prev)) == 0)
  {
    size += GET_SIZE(HDRP(prev)) + GET_SIZE(HDRP(next));
    PUT(HDRP(prev), PACK(size, 0));
    PUT(FTRP(next), PACK(size, 0));
    bp = prev;
  }
  else if(GET_ALLOC(HDRP(next)) == 0)
  {
    size += GET_SIZE(HDRP(next));
    PUT(HDRP(bp), PACK(size, 0));
    PUT(FTRP(next), PACK(size, 0));
  }
  else if(GET_ALLOC(HDRP(prev)) == 0)
  {
    size += GET_SIZE(HDRP(prev));
    PUT(HDRP(prev), PACK(size, 0));
    PUT(FTRP(bp), PACK(size, 0));
    bp = prev;
  }
  add_free(bp);
  return bp;
}

static void* extend_heap(size_t words)
{
  char * bp;
  size_t size;

  size = (words % 2 == 1) ? (words + 1) * WSIZE : words * WSIZE;
  bp = mem_sbrk(size);
  if((long)(bp) == -1) return NULL;
  PUT(HDRP(bp), PACK(size, 0));
  PUT(FTRP(bp), PACK(size, 0));
  PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1));

  return coalesce(bp);
}

// TODO
static void* find_fit(size_t asize)
{
  void* bp;
  for(bp = heap_listp; GET_SIZE(HDRP(bp)) > 0; bp = NEXT_BLKP(bp))
  {
    if(GET_ALLOC(HDRP(bp)) == 0 && GET_SIZE(HDRP(bp)) >= asize) return bp;
  }
  return NULL;
}

static void place(void *bp, size_t asize)
{
  // --------------------- DEBUG ---------------------
  // printf("[ACTION] allocated %d to %p\n", asize, bp);
  // -------------------------------------------------
  size_t csize = GET_SIZE(HDRP(bp));
  if((csize - asize) >= 2 * DSIZE)
  {
    PUT(HDRP(bp), PACK(asize, 1));
    PUT(FTRP(bp), PACK(asize, 1));
    bp = NEXT_BLKP(bp);
    PUT(HDRP(bp), PACK(csize-asize, 0));
    PUT(FTRP(bp), PACK(csize-asize, 0));
  }
  else{
    PUT(HDRP(bp), PACK(csize, 1));
    PUT(FTRP(bp), PACK(csize, 1));
  }
  // --------------------- DEBUG ---------------------
  // mm_check();
  // -------------------------------------------------
}

/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
  // --------------------- DEBUG ---------------------
  // printf("----------------------------- starting initialization -----------------------------\n\n");
  // -------------------------------------------------
  heap_listp = mem_sbrk(4 * WSIZE);
  if(heap_listp == (void *) -1) return -1;
  PUT(heap_listp, 0);
  PUT(heap_listp + WSIZE, PACK(DSIZE, 1));
  PUT(heap_listp + DSIZE, PACK(DSIZE, 1));
  PUT(heap_listp + 3 * WSIZE, PACK(0, 1));
  heap_listp += 2 * WSIZE;
  if(extend_heap(CHUNKSIZE / WSIZE) == NULL) return -1;
  for(int i = 0; i <= SIZE_NUM; i++) free_list[i] = 0;
  // --------------------- DEBUG ---------------------
  // mm_check();
  // -------------------------------------------------
  return 0;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
  char* bp;
  size_t asize = ALIGN(MAX(size, 16) + DSIZE);
  // size_t extend_size = MAX(asize, CHUNKSIZE);
  size_t extend_size = asize;
  
  if(size == 0) return NULL;
  
  bp = find_fit(asize);
  if(bp != NULL)
  {
    place(bp, asize);
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
  // --------------------- DEBUG ---------------------
  // printf("[ACTION] freeing %p\n", ptr);
  // -------------------------------------------------
  if(ptr == NULL) return;
  size_t size = GET_SIZE(HDRP(ptr));
  PUT(HDRP(ptr), PACK(size, 0));
  PUT(FTRP(ptr), PACK(size, 0));
  SET_PREV_FREE(ptr, 0);
  SET_NEXT_FREE(ptr, 0);
  coalesce(ptr);
  // --------------------- DEBUG ---------------------
  // printf("[ACTION] freed %p\n", ptr);
  // mm_check();
  // -------------------------------------------------
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
  // --------------------- DEBUG ---------------------
  // printf("[ACTION] reallocating %p to %d\n", ptr, size);
  // -------------------------------------------------
  void *oldptr = ptr;
  void *newptr;
  size_t copySize;
  
  if(size == 0){
    mm_free(oldptr);
    return NULL;
  }

  newptr = mm_malloc(size);
  if(newptr == NULL) return NULL;
  if(oldptr == NULL) return newptr;
  
  copySize = GET_SIZE(oldptr);
  if (size < copySize) copySize = size;
  memcpy(newptr, oldptr, copySize);
  mm_free(oldptr);
  return newptr;
}