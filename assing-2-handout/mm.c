/*
 * mm.c - malloc implemented with Segregated Free List
 * 
 * This file implemented my own malloc with functions
 * mm_malloc() for allocating new memory to heap
 * mm_free() for freeing allocated memory
 * mm_realloc() for reallocating an allocated memory
 * 
 * For memory utilization, segregated Free List has been used
 * with the method of segregated fit to be more specific.
 * More details of the implementation is described below
 * in each header of the functions or macros. Some macros
 * or function names have been implemented based on the implicit
 * implementation from the textbook.
 * 
  */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*
 * Constants and Macros
 * 
 * Useful, or commonly used constants and macros are defined.
 */

// single word (4) or double word (8) alignment 
#define ALIGNMENT             8
// rounds up to the nearest multiple of ALIGNMENT
#define ALIGN(size)           (((size) + (ALIGNMENT-1)) & ~0x7)

// size of size_t aligned with heap alignment
#define SIZE_T_SIZE           (ALIGN(sizeof(size_t)))
// word size
#define WSIZE                 4
// double-word size
#define DSIZE                 8
// chunk size for heap's first initialization
#define CHUNKSIZE             (1 << 12)
// the number of size classes
#define SIZE_NUM 10

// max value between 2 values
#define MAX(x, y)             ((x) > (y) ? (x) : (y))
// pack size and allocation bit for a block's header/footer
#define PACK(size, alloc)     ((size) | (alloc))

// dereferencing 4B value of pointer p
#define GET(p)                (*(unsigned int *) (p))
// setting the referenced value of pointer p to val
#define PUT(p, val)           (*(unsigned int *) (p) = (val))
// get the size info in header/footer of a block
#define GET_SIZE(p)           (GET(p) & ~0x7)
// get the allocation info in header/footer of a block
#define GET_ALLOC(p)          (GET(p) & 0x1)
// get the pointer of the header of a block
#define HDRP(bp)              ((char *)(bp) - WSIZE)
// get the pointer of the footer of a block
#define FTRP(bp)              ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

// get the pointer of the previous block of a block
#define PREV_BLKP(bp)         ((char *)(bp) - GET_SIZE((char *)(bp) - DSIZE))
// get the pointer of the next block of a block
#define NEXT_BLKP(bp)         ((char *)(bp) + GET_SIZE((char *)(bp) - WSIZE))
// get the pointer of the previous free block of a free block
#define GET_PREV_FREE(bp)     ((void *)(GET(bp)))
// get the pointer of the next free block of a free block
#define GET_NEXT_FREE(bp)     ((void *)(GET(bp + WSIZE)))
// set the pointer of the previous free block of a free block as p
#define SET_PREV_FREE(bp, p)  (*(unsigned int *) (bp) = (long)(p))
// set the pointer of the next free block of a free block as p
#define SET_NEXT_FREE(bp, p)  (*(unsigned int *) (bp + WSIZE) = (long)(p))

/*
 * Static variable and methods
 *
 * Variables and methods defined as static
 * so that is only used within mm.c
 */

// pointer of the starting point of heap
static char *heap_listp;
// array of size classes
static int size_class[SIZE_NUM] = {1 << 5, 1 << 6, 1 << 7, 1 << 8, 1 << 9, 1 << 10, 1 << 11, 1 << 12, 1 << 13, 1 << 14};
/* 
 * free list - array of pointers of the first free block for each size class
 * 
 * The free blocks are saved as linked list for each size
 * class. Each free block has its info of the previous and
 * next free block in the first 8B (4B for prev, 4B for next)
 * of the payload area. The very first free block for each
 * linked list is saved in the free_list array. The index
 * corresponds to the index of the size class in size_class
 * array. The last index in free_list is for the free blocks
 * that are larger than the last size in size_class.
 * 
 */
static void* free_list[SIZE_NUM + 1];

/*
 * mm_check - function for heap check
 * 
 * no parameter
 * return : 0 if there is no problem / -1 if there is a problem
 * 
 * Prints the whole heap in block units including the header, 
 * footer, allocation with the correspoding addresses.
 * Also prints the whole free list for each size class.
 * While printing, if there is problem with the heap, or free class,
 * like no coalescing, no alignment, different header and footer,
 * the function stops printing and returns -1.
 * 
 */
static int mm_check() {
  printf("\n************** starting heap check **************\n\n");
  void * start_p = mem_heap_lo();
  printf("heap starts in %p\n", start_p);
  void* bp;
  int wasFree = 0;
  for(bp = heap_listp; GET_SIZE(HDRP(bp)) > 0; bp = NEXT_BLKP(bp)) {
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
  // print free list
  printf("free list:\n");
  for(int i = 0; i < SIZE_NUM; i++) {
    void * temp = free_list[i];
    printf("%5d :", size_class[i]);
    while(temp) {
      printf(" %p", temp);
      temp = GET_NEXT_FREE(temp);
    }
    printf("\n");
  }
  void * temp = free_list[SIZE_NUM];
  printf("large :");
  while(temp) {
    printf(" %p", temp);
    temp = GET_NEXT_FREE(temp);
  }
  printf("\n");
  printf("\n\n*************** ending heap check ***************\n\n");
  return 0;
}

/*
 * get_class - function that gives the appropriate size class index for a given size
 * 
 * parameter:
 * int asize = the aligned size of which the corresponding size class is in interest
 * 
 * return: the correspoding size class's index
 * 
 * For a given aligned size, this function traverses the
 * array of size classes and returns the index of the first
 * size class that is big enough for asize to fit in.
 *
 */
static int get_class(int asize) {
  int size = asize - DSIZE;
  for(int i = 0; i < SIZE_NUM; i++) if(size <= size_class[i]) return i;
  return SIZE_NUM;
}

/* 
 * add_free - function that adds a pointer to the free list
 * 
 * parameter :
 * void* bp = the pointer of the free block that is being added to the free list
 * 
 * no return
 * 
 * Using the given pointer of the free block, the function
 * traverses the appropriate free list according to the size
 * of the free block. Regardless of whether there is a pointer
 * or not in the free list, the given free block is placed 
 * at the very first of the free list for LIFO method in 
 * allocating new blocks.
 * 
 */
static void add_free(void* bp) {
  // --------------------- DEBUG ---------------------
  // printf("adding %p with %d to free list\n", bp, GET_SIZE(HDRP(bp)));
  // -------------------------------------------------
  size_t size = GET_SIZE(HDRP(bp));
  int class = get_class(size);
  void *ptr = free_list[class];
  if(ptr) {
    SET_NEXT_FREE(bp, ptr);
    SET_PREV_FREE(bp, 0);
    SET_PREV_FREE(ptr, bp);
    free_list[class] = bp;
  }
  else {
    free_list[class] = bp;
    SET_NEXT_FREE(bp, 0);
    SET_PREV_FREE(bp, 0);
  }
  // --------------------- DEBUG ---------------------
  // printf("added %p to free list\n", bp);
  // -------------------------------------------------
  return;
}

/* 
 * remove_free - function that removes a pointer from the free list
 * 
 * parameter :
 * void* bp = the pointer of the free block that is being removed from the free list
 * 
 * no return
 * 
 * Using the given pointer of the free block, the function
 * traverses the appropriate free list according to the size
 * of the free block. If the pointer is found, after it is 
 * removed from the free list, the previous free block and 
 * the next free block is linked to each other.
 * 
 */
static void remove_free(void *bp) {
  // --------------------- DEBUG ---------------------
  // printf("removing %p from free list\n", bp);
  // -------------------------------------------------
  size_t size = GET_SIZE(HDRP(bp));
  int class = get_class(size);
  void *ptr = free_list[class];
  void *prev = NULL;
  void *next = GET_NEXT_FREE(ptr);
  while(ptr != bp) {
    prev = ptr;
    ptr = GET_NEXT_FREE(ptr);
    next = GET_NEXT_FREE(ptr);
  }
  // alone
  if(prev == NULL && next == NULL) {
    free_list[class] = NULL;
  }
  // first
  else if(prev == NULL) {
    SET_PREV_FREE(next, 0);
    free_list[class] = next;
  }
  // last
  else if(next == NULL) {
    SET_NEXT_FREE(prev, 0);
  }
  // middle
  else {
    SET_PREV_FREE(next, prev);
    SET_NEXT_FREE(prev, next);
  }
  // --------------------- DEBUG ---------------------
  // printf("removed %p from free list\n", bp);
  // -------------------------------------------------
  return;
}

/* 
 * coalesce - function that coalesces the free block with nearby free blocks
 * 
 * parameter :
 * void* bp = the pointer of the free block that is being coalesced
 * 
 * return: the pointer of the coalesced free block.
 * 
 * Using the given pointer of the free block, the function
 * checks if the very previous block or the very next block
 * is also free. If so, the function changes the headers and
 * footers of the free blocks so that they make up a one large
 * free block. The smaller free blocks are removed from the
 * free list and the new large free block is added to the free
 * list. Afterwise, the pointer of the large single free block
 * is returned.
 * 
 */
static void* coalesce(void * bp) {
  size_t size = GET_SIZE(HDRP(bp));
  void *next = NEXT_BLKP(bp);
  void *prev = PREV_BLKP(bp);
  if(GET_ALLOC(HDRP(next)) == 0 && GET_ALLOC(HDRP(prev)) == 0)
  {
    size += GET_SIZE(HDRP(prev)) + GET_SIZE(HDRP(next));
    remove_free(prev);
    remove_free(next);
    PUT(HDRP(prev), PACK(size, 0));
    PUT(FTRP(next), PACK(size, 0));
    bp = prev;
  }
  else if(GET_ALLOC(HDRP(next)) == 0)
  {
    size += GET_SIZE(HDRP(next));
    remove_free(next);
    PUT(HDRP(bp), PACK(size, 0));
    PUT(FTRP(next), PACK(size, 0));
  }
  else if(GET_ALLOC(HDRP(prev)) == 0)
  {
    size += GET_SIZE(HDRP(prev));
    remove_free(prev);
    PUT(HDRP(prev), PACK(size, 0));
    PUT(FTRP(bp), PACK(size, 0));
    bp = prev;
  }
  add_free(bp);
  return bp;
}

/* 
 * extend_heap - extends the heap according to the given size
 * 
 * parameter :
 * size_t words = the number of words for the heap to be extended
 * 
 * return: the pointer of the free block made by extending the heap / NULL if heap extension failed
 * 
 * The heap is extended as much as the given number of words.
 * This new area of heap is classified as a new free block,
 * so it is sent to coalesce() function in case the heap
 * already had a free block at the very end. The result of
 * coalescing is returned, but in case the extension of heap
 * had failed, NULL is returned.
 * 
 */
static void* extend_heap(size_t words) {
  char * bp;
  size_t size;
  size = (words % 2 == 1) ? (words + 1) * WSIZE : words * WSIZE;
  bp = mem_sbrk(size);
  if((long)(bp) == -1) return NULL;
  PUT(HDRP(bp), PACK(size, 0));
  PUT(FTRP(bp), PACK(size, 0));
  PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1));
  // --------------------- DEBUG ---------------------
  // printf("extended heap\n");
  // -------------------------------------------------
  return coalesce(bp);
}

/* 
 * find_fit - function that finds the appropriate free block for allocation
 * 
 * parameter :
 * size_t size = the size of the block for allocation
 * 
 * return : the pointer of the block appropriate for allocation / NULL if there is no fit
 * 
 * Using the given size, the function traverses the free list for
 * a free block large enough for allocation. Uses the strategy of
 * first-fit, so starting with the appropriate size class, the
 * function traverses until the first free block larger than the
 * given size appears. If there is no appropriate free block, than
 * the next size class's free list is traversed. If there is no fit
 * until the very end, NULL is returned.
 * 
 */
static void* find_fit(size_t asize) {
  int class = get_class(asize);
  for(int i = class; i <= SIZE_NUM; i++) {
    void* bp = free_list[i];
    while(bp && asize > GET_SIZE(HDRP(bp))) bp = GET_NEXT_FREE(bp);
    if(bp) return bp;
  }
  return NULL;
}

/* 
 * place - function that makes the given block as allocated
 * 
 * parameter :
 * void* bp = the pointer of the block that is being allocated
 * size_t asize = size of the block being allocated
 * 
 * no return
 * 
 * First removes bp from free list. Then adds a header and 
 * footer to bp with asize as the size and state as allocated.
 * If there is enough space for a new free block after
 * allocating, the free block is splitted into 2, the first
 * being allocated and the other being freed, thus being
 * added to the free list. 
 * 
 */
static void place(void *bp, size_t asize) {
  // -------------------- DEBUG ---------------------
  // printf("[ACTION] allocated %d to %p\n", asize, bp);
  // -------------------------------------------------
  size_t csize = GET_SIZE(HDRP(bp));
  if((csize - asize) >= 2 * DSIZE) {
    remove_free(bp);
    PUT(HDRP(bp), PACK(asize, 1));
    PUT(FTRP(bp), PACK(asize, 1));
    bp = NEXT_BLKP(bp);
    PUT(HDRP(bp), PACK(csize-asize, 0));
    PUT(FTRP(bp), PACK(csize-asize, 0));
    add_free(bp);
  }
  else {
    remove_free(bp);
    PUT(HDRP(bp), PACK(csize, 1));
    PUT(FTRP(bp), PACK(csize, 1));
  }
  // --------------------- DEBUG ---------------------
  // mm_check();
  // -------------------------------------------------
}

/* 
 * Functions
 * 
 * The implemented functions that are directly used 
 * from other files for allocation, free, and 
 * reallocation of memory.
 * 
 */

/* 
 * mm_init - initialize the malloc package.
 * 
 * no parameter
 * 
 * return : 0 if no problem / -1 if there is a problem
 * 
 * Initializes the heap and static variables. First each
 * pointer of the free_list is initialized as NULL. Then
 * the heap is extended for the first two 8B sized blocks
 * that indicates the start and the last 0B sized block.
 * Heap is additionally extended as much as the CHUNKSIZE
 * for initial space and 8B more for header and footer.
 * If there is any problem in the heap extension, -1 is
 * returned, and 0 is returned if else.
 * 
 */
int mm_init(void) {
  // --------------------- DEBUG ---------------------
  // printf("----------------------------- starting initialization -----------------------------\n\n");
  // -------------------------------------------------
  for(int i = 0; i <= SIZE_NUM; i++) free_list[i] = 0;
  heap_listp = mem_sbrk(4 * WSIZE);
  if(heap_listp == (void *) -1) return -1;
  PUT(heap_listp, 0);
  PUT(heap_listp + WSIZE, PACK(DSIZE, 1));
  PUT(heap_listp + DSIZE, PACK(DSIZE, 1));
  PUT(heap_listp + 3 * WSIZE, PACK(0, 1));
  heap_listp += 2 * WSIZE;
  if(extend_heap(DSIZE) == NULL) return -1;
  if(extend_heap(CHUNKSIZE / WSIZE) == NULL) return -1;
  // --------------------- DEBUG ---------------------
  // mm_check();
  // -------------------------------------------------
  return 0;
}

/* 
 * mm_malloc - allocate a new block
 * 
 * paramter :
 * size_t size = the size of the block to be allocated
 * 
 * return : the pointer of the allocated block / NULL if allocation failed
 * 
 * Blocks are allocated so that the size is a multiple of the 
 * alignment. For this, the size is changed as asize so that
 * it aligns with the heap. After alignment, using find_fit()
 * and place(), a new block is allocated, and the pointer is
 * returned. NULL is returned if there is any problem allocating.
 * 
 */
void *mm_malloc(size_t size) {
  // --------------------- DEBUG ---------------------
  // printf("[ACTION] allocating %d\n", size);
  // -------------------------------------------------
  char* bp;
  size_t asize = ALIGN(MAX(size + DSIZE, 16));
  size_t extend_size = MAX(asize, CHUNKSIZE);
  
  if(size == 0) return NULL;
  
  bp = find_fit(asize);
  if(bp != NULL)
  {
    place(bp, asize);
    return bp;
  }
  bp = extend_heap(extend_size / WSIZE); 
  if(bp == NULL) return NULL;
  place(bp, asize);
  return bp;
}

/*
 * mm_free - free an allocated block
 *
 * paramter :
 * void* ptr = the pointer of the allocated block that is to be freed
 * 
 * no return
 * 
 * Set the allocation state of header and footer of the given block 
 * as free and after initializing the next and previous free block,
 * it is sent to coalesce() for both coalescing and addition to the 
 * free list. If ptr is NULL, it does nothing.
 * 
 */
void mm_free(void *ptr) {
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
 * mm_realloc - reallocates a block to a given size
 *
 * paramter :
 * void* ptr = the pointer of the block to be reallocated
 * size_t size = size of the reallocated block
 * 
 * return : the pointer of the reallocated block / NULL if reallocation failed or wasn't needed
 * 
 * Reallocates a block so that its size is changed to the given size.
 * If the reallocation is for getting smaller, a new block is not allocated,
 * rather, the size of the block is simply changed, with the rest being
 * freed. If the reallocation is for getting bigger, a new block is
 * allocated, and the payload is copied to the new block. If ptr is NULL, 
 * it just allocates a new block, and if size is 0, it just frees the block.
 * 
 */
void *mm_realloc(void *ptr, size_t size) {
  // --------------------- DEBUG ---------------------
  // printf("[ACTION] reallocating %p to %d\n", ptr, size);
  // -------------------------------------------------
  void *newptr;
  if(ptr == NULL) {
    newptr = mm_malloc(size);
    return newptr;
  }
  if(size == 0) {
    mm_free(ptr);
    return NULL;
  }
  
  size_t asize = ALIGN(MAX(size + DSIZE, 16));
  size_t oldSize = GET_SIZE(HDRP(ptr));
  size_t copySize = oldSize - DSIZE;
  if(oldSize > asize && (oldSize - asize) >= 2 * DSIZE) {
    PUT(HDRP(ptr), PACK(asize, 1));
    PUT(FTRP(ptr), PACK(asize, 1));
    newptr = ptr;
    ptr = NEXT_BLKP(ptr);
    PUT(HDRP(ptr), PACK(oldSize-asize, 0));
    PUT(FTRP(ptr), PACK(oldSize-asize, 0));
    SET_PREV_FREE(ptr, 0);
    SET_NEXT_FREE(ptr, 0);
    coalesce(ptr);
  }
  else {
    newptr = mm_malloc(size);
    if(newptr == NULL) return NULL;
    if(size < copySize) copySize = size;
    memcpy(newptr, ptr, copySize);
    mm_free(ptr);
  }
  // --------------------- DEBUG ---------------------
  // printf("[ACTION] reallocated %p to %d\n", ptr, size);
  // mm_check();
  // -------------------------------------------------
  return newptr;
}