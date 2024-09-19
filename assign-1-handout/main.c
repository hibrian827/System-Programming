// The base C code is genereated using ChatGPT!

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>

#define MAX_RAND 100
#define COUNT 10

// Define the node structure
struct Node {
    int data;
    struct Node* left;
    struct Node* right;
};

extern int sort_tree(struct Node* root, int i, int sorted_nums[]);

// Function to create a new node
struct Node* createNode(int data) {
    struct Node* newNode = (struct Node*)malloc(sizeof(struct Node));
    if (!newNode) {
        printf("Memory allocation error\n");
        exit(1);
    }
    newNode->data = data;
    newNode->left = NULL;
    newNode->right = NULL;
    return newNode;
}

// Function to insert a new node in the binary tree
struct Node* insert(struct Node* node, int data) {
    if (node == NULL) {
        return createNode(data);
    }

    if (data < node->data) {
        node->left = insert(node->left, data);
    } else if (data > node->data) {
        node->right = insert(node->right, data);
    }

    return node;
}


bool check_if_sorted(int nums[], int sorted_nums[]){
    bool is_found;

#ifdef DEBUG
    printf("nums: ");
    for (int i=0; i<COUNT; i++) {
        printf("%d ", nums[i]);
    }
    printf("\n");
    
    printf("sorted_nums: ");
    for (int i=0; i<COUNT; i++) {
        printf("%d ", sorted_nums[i]);
    }
    printf("\n");
#endif

    for (int i=0; i<COUNT-1; i++) {
        is_found = false;
        for (int j=0; j<COUNT; j++)
            if (sorted_nums[i] == nums[j])
                is_found = true;

        if (!is_found) {
            printf("[-] FAIL\n");
            return false;
        }

        if (sorted_nums[i] > sorted_nums[i+1]) {
            printf("[-] FAIL\n");
            return false;
        }
    }
    printf("[+] PASS\n");
    return true;
}

// Generate unique, random numbers
bool gen_rand_nums(int nums[]) {
    for (int i=0; i<COUNT; i++) {
        nums[i] = rand() % MAX_RAND;        
        for (int j=0; j<i; j++) {
            if (nums[j] == nums[i])
                return false;
        }
    }
    return true;
}

struct Node *make_tree(int nums[]) {
    struct Node* root = NULL;
    
    for (int i=0; i<COUNT; i++) {
        if (i == 0)
            root = insert(root, nums[i]);
        else
            insert(root, nums[i]);
    }
    return root;
}

// Main function
int main() {
    int nums[COUNT];
    int sorted_nums[COUNT];
    
    srand(time(NULL));

    while (1) {
        if (gen_rand_nums(nums))
            break;
    }

    struct Node* root = NULL;
    root = make_tree(nums);

    sort_tree(root, 0, sorted_nums);

    check_if_sorted(nums, sorted_nums);

    return 0;
}
