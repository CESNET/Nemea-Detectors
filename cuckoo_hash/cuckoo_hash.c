#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HASH_SIZE 50

typedef struct ht_item {
    char key[3];
    int data;
} item_t;

unsigned int RSHash(char* key, unsigned int size)
{
    unsigned int a = 63689;
    unsigned int b = 378551;
    unsigned int hash = 0;

    for (unsigned int i = 0; i < size; key++, i++) {
        hash = hash * a  + (*key);
        a = a * b;
    }
    return hash % HASH_SIZE;
}

unsigned int JSHash(char* key, unsigned int size)
{
   unsigned int hash = 1315423911;
   unsigned int i    = 0;

   for(i = 0; i < size; key++, i++)
   {
      hash ^= ((hash << 5) + (*key) + (hash >> 2));
   }

   return hash % HASH_SIZE;
}

int ht_insert(item_t* ht, char* key, int data)
{
    int t;
    unsigned int pos, swap1, swap2;
    item_t prev;
    pos = RSHash(key, strlen(key));

    for (t = 0; t < 10; t++) {
        if (ht[pos].data == 0) { // try empty
            strcpy(ht[pos].key, key);
            ht[pos].data = data;
            return 0;
        }
        printf("Position occupied. Will try to swap.\n");

        prev = ht[pos]; // store previous item
        
        //copy new item
        strcpy(ht[pos].key, key);
        ht[pos].data = data;

        // compute both hashses
        swap1 = RSHash(prev.key, strlen(prev.key));
        swap2 = JSHash(prev.key, strlen(prev.key));

        // test which one was used
        if (swap2 == pos) {
            pos = swap1;
        } else {
            pos = swap2;
        }
        
        strcpy(key, prev.key);
        data = prev.data;
    }

    printf("Final insertion: %d\n", pos);
    return -1;
}

void ht_remove(item_t* ht, char* key)
{
    unsigned int pos;
    pos = RSHash(key, strlen(key));

    printf("Testing position (%d)\n", pos);
    
    if (ht[pos].data != 0 && (strcmp(key, ht[pos].key) == 0)) {
        ht[pos].data = 0;
        memset(ht[pos].key, 0x0, 3);
        return;
    }

    pos = JSHash(key, strlen(key));
    printf("Testing position (%d)\n", pos);
    if (ht[pos].data != 0 && (strcmp(key, ht[pos].key) == 0)) {
        ht[pos].data = 0;
        memset(ht[pos].key, 0x0, 3);
        return;
    }

    printf("Nothing to remove.\n");
}

int main()
{

    item_t ht[HASH_SIZE];
    char key[3];
    int d = 1;
    int ret;
    int i,j;
    
    for (int i = 0; i < HASH_SIZE; i++) {
        ht[i].data = 0;
    }

    for (i = 'a', j = 'Z'; i <= 'z', j >= 'A';d++, i++, j--) {
        key[0] = (char) i;
        key[1] = (char) j;
        key[2] = '\0';

        ret = ht_insert(ht, key, d);
        if (ret == 0) {
            printf("Item inserted.\n");
        } else {
            printf("Item discared. HT full or item cycled.\n");
        }
    }

    unsigned int pos;

    for (int i = 0; i < HASH_SIZE; i++) {
        printf("RSHash: %lu\nJSHash: %lu\n", RSHash("aZ", 2), JSHash("aZ", 2));
    }
    
    pos = RSHash("aZ", 2);
    printf("Test output: %d\n", ht[pos].data);

    pos = JSHash("aZ", 2);
    printf("Test output: %d\n", ht[pos].data);

    for (int i = 0;i < HASH_SIZE; i++) {
        if (ht[i].data != 0)
            printf("Item stored at %s (%d): %d\n", ht[i].key, i, ht[i].data);
    }

    printf("//////////////////////////////////////////////\n");

    ht_remove(ht, "aZ");
    for (int i = 0;i < HASH_SIZE; i++) {
        if (ht[i].data != 0)
            printf("Item stored at %s (%d): %d\n", ht[i].key, i, ht[i].data);
    }
    
    for (i = 'a', j = 'Z'; i <= 'z', j >= 'A';d++, i++, j--) {
        key[0] = (char) i;
        key[1] = (char) j;
        key[2] = '\0';

        ht_remove(ht, key);
    }

    int i_count = 0;

    for (int i = 0;i < HASH_SIZE; i++) {
        if (ht[i].data != 0)
            i_count++;
    }

    if (i_count == 0)
        printf("All data erased.\n");

    int a = 5;
    int *p_a;
    p_a = &a;

    return 0;
}
