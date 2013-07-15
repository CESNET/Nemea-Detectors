#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HASH_SIZE 50

typedef struct {
    char *key;
    void *data;
} cc_item_t;

//typedef cc_item_t *cc_hash_table_t[HASH_SIZE];
typedef cc_item_t **cc_hash_table_t;

int ht_init(cc_hash_table_t* new_table, unsigned int table_size)
{
    *new_table = (cc_hash_table_t) calloc(table_size, sizeof(cc_item_t*));
    
    if (new_table == NULL) {
        fprintf(stderr, "ERROR: Hash table couldn't be initialized.");
        return -1;
    }
/*
    for (int i = 0; i < HASH_SIZE; i++) {
        (*new_table)[i] = NULL;
    }
*/
    return 0;
}

unsigned int RSHash(char* key, unsigned int key_length)
{
    unsigned int a = 63689;
    unsigned int b = 378551;
    unsigned int hash = 0;

    for (unsigned int i = 0; i < key_length; key++, i++) {
        hash = hash * a  + (*key);
        a = a * b;
    }
    return hash % HASH_SIZE;
}

unsigned int JSHash(char* key, unsigned int key_length)
{
    unsigned int hash = 1315423911;
    unsigned int i    = 0;

    for(i = 0; i < key_length; key++, i++) {
        hash ^= ((hash << 5) + (*key) + (hash >> 2));
    }

    return hash % HASH_SIZE;
}

int ht_insert(cc_hash_table_t ht, cc_item_t *new_data)
{
    int t;
    unsigned int pos, swap1, swap2;
    cc_item_t *curr, *prev;
    pos = RSHash(new_data->key, strlen(new_data->key));

    curr = new_data;
    for (t = 0; t < 10; t++) {
        if (ht[pos] == NULL) { // try empty
            ht[pos] = curr;
            return 0;
        }

//        memcpy(&prev.key, ht[pos]->key, strlen(ht[pos]->key));
        memcpy(prev, ht[pos], sizeof(cc_item_t));

        
        //copy new item
        ht[pos] = new_data;

        // compute both hashses
        swap1 = RSHash(prev->key, strlen(prev->key));
        swap2 = JSHash(prev->key, strlen(prev->key));

        // test which one was used
        if (swap2 == pos) {
            pos = swap1;
        } else {
            pos = swap2;
        }       
        curr = prev;
    }
    return -1;
}

/*void *ht_get(cc_hash_table_t ht, char* key)
{
*/  

void ht_remove(cc_hash_table_t ht, char* key)
{
    unsigned int pos;
    pos = RSHash(key, strlen(key));
 
    if (ht[pos] != NULL && (strcmp(key, ht[pos]->key) == 0)) {
        ht[pos] = NULL;
        return;
    }

    pos = JSHash(key, strlen(key));
    if (ht[pos] != NULL && (strcmp(key, ht[pos]->key) == 0)) {
        ht[pos] = NULL;
        return;
    }
}

int main()
{

    int d = 1;
    int ret;
    int i,j;

    cc_hash_table_t ht;

    ht_init(&ht, HASH_SIZE);
    
    cc_item_t *new_item;
    for (i = 'a', j = 'Z'; i <= 'z', j >= 'A';d++, i++, j--) {
        char key[3];
        
        key[0] = (char) i;
        key[1] = (char) j;
        key[2] = '\0';
        cc_item_t *new_item = (cc_item_t *) malloc(sizeof(cc_item_t));
        new_item->key = (char *) malloc(strlen(key) * sizeof(char));
        strcpy(new_item->key, key);
        new_item->data = (int *)malloc(sizeof(int));
        *((int *) new_item->data) = d;

        ret = ht_insert(ht, new_item);
        if (ret != 0) {
            printf("Item discared. HT full or item cycled.\n");
        }
    }

    unsigned int pos;
   
    for (int i = 0;i < HASH_SIZE; i++) {
        if (ht[i] != NULL)
            printf("Item stored at %s (%d): %d\n", ht[i]->key, i, *((int *)ht[i]->data));
    }

    printf("//////////////////////////////////////////////\n");

    ht_remove(ht, "aZ");
    for (int i = 0;i < HASH_SIZE; i++) {
        if (ht[i] != NULL)
            printf("Item stored at %s (%d): %d\n", ht[i]->key, i, *((int *)ht[i]->data));
    }
    
    for (i = 'a', j = 'Z'; i <= 'z', j >= 'A';d++, i++, j--) {
        char key[3];
        key[0] = (char) i;
        key[1] = (char) j;
        key[2] = '\0';

        ht_remove(ht, key);
    }

    int i_count = 0;

    for (int i = 0;i < HASH_SIZE; i++) {
        if (ht[i] != NULL)
            i_count++;
    }

    if (i_count == 0)
        printf("All data erased.\n");


    return 0;
}
