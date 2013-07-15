#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HASH_SIZE 50
#define COPY_KEY_BUFFER 101

typedef struct {
    char *key;
    void *data;
} cc_item_t;

//typedef cc_item_t *cc_hash_table_t[HASH_SIZE];
typedef struct {
    cc_item_t *table;
    unsigned int data_size;
} cc_hash_table_t;

int ht_init(cc_hash_table_t* new_table, unsigned int table_size, unsigned int data_size)
{
    new_table->table = (cc_item_t*) malloc(table_size * sizeof(cc_item_t*));
    
    if (new_table == NULL) {
        fprintf(stderr, "ERROR: Hash table couldn't be initialized.");
        return -1;
    }

    new_table->data_size = data_size;

    for (int i = 0; i < HASH_SIZE; i++) {
        new_table->table[i].data = NULL;
    }

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

int ht_insert(cc_hash_table_t* ht, cc_item_t *new_data)
{
    int t;
    unsigned int pos, swap1, swap2;
    pos = RSHash(new_data->key, strlen(new_data->key));

    cc_item_t prev, curr;

    prev.key = malloc(COPY_KEY_BUFFER);
    prev.data = malloc(ht->data_size);
    
    curr.key = malloc(COPY_KEY_BUFFER);
    curr.data = malloc(ht->data_size);

    strcpy(curr.key, new_data->key);
    memcpy(curr.data, new_data->data, ht->data_size);

    for (t = 0; t < 10; t++) {
        if (ht->table[pos].data == NULL) { // try empty
            ht->table[pos].key = curr.key;
            ht->table[pos].data = curr.data;
            free(prev.data);
            free(prev.key);
            return 0;
        }

        strcpy(prev.key, ht->table[pos].key);
        memcpy(prev.data, ht->table[pos].data, ht->data_size);
        
        //copy new item
        strcpy(ht->table[pos].key, curr.key);
        memcpy(ht->table[pos].data, curr.data, ht->data_size);

        // compute both hashses
        swap1 = RSHash(prev.key, strlen(prev.key));
        swap2 = JSHash(prev.key, strlen(prev.key));

        // test which one was used
        if (swap2 == pos) {
            pos = swap1;
        } else {
            pos = swap2;
        }       
        strcpy(curr.key, prev.key);
        memcpy(curr.data, prev.data, ht->data_size);
    }

    free(prev.data);
    free(prev.key);
    free(curr.data);
    free(curr.key);
    return -1;
}

void *ht_get(cc_hash_table_t* ht, char* key)
{
    unsigned int pos1, pos2;
    
    pos1 = RSHash(key, strlen(key));
    pos2 = JSHash(key, strlen(key));

    if (ht->table[pos1].data != NULL && strcmp(key, ht->table[pos1].key) == 0) {
        return ht->table[pos1].data;
    }
    if (ht->table[pos2].data != NULL && strcmp(key, ht->table[pos2].key) == 0) {
        return ht->table[pos2].data;
    }
    return NULL;
}

unsigned int ht_get_index(cc_hash_table_t* ht, char* key)
{
    unsigned int pos1, pos2;
    
    pos1 = RSHash(key, strlen(key));
    pos2 = JSHash(key, strlen(key));

    if (ht->table[pos1].data != NULL && strcmp(key, ht->table[pos1].key) == 0) {
        return pos1;
    }
    if (ht->table[pos2].data != NULL && strcmp(key, ht->table[pos2].key) == 0) {
        return pos2;
    }
    return -1;
}

void ht_remove_by_key(cc_hash_table_t* ht, char* key)
{
    unsigned int pos1, pos2;
    pos1 = RSHash(key, strlen(key));
    pos2 = JSHash(key, strlen(key));
 
    if (ht->table[pos1].data != NULL && (strcmp(key, ht->table[pos1].key) == 0)) {
        free(ht->table[pos1].data);      
        free(ht->table[pos1].key);
        ht->table[pos1].data = NULL;
        ht->table[pos1].key = NULL;
        return;
    }

    if (ht->table[pos2].data != NULL && (strcmp(key, ht->table[pos2].key) == 0)) {
        free(ht->table[pos2].data);      
        free(ht->table[pos2].key);
        ht->table[pos2].data = NULL;
        ht->table[pos2].key = NULL;
        return;
    }
}

void ht_remove_by_index(cc_hash_table_t* ht, unsigned int index)
{
}

int main()
{

    int d = 1;
    int ret;
    int i,j;

    cc_hash_table_t ht;

    ht_init(&ht, HASH_SIZE, sizeof(int));
    
    cc_item_t *new_item;
    for (i = 'a', j = 'Z'; i <= 'z', j >= 'A';d++, i++, j--) {
        char key[3];
        
        key[0] = (char) i;
        key[1] = (char) j;
        key[2] = '\0';
        cc_item_t *new_item = NULL;
        new_item  = (cc_item_t *) malloc(sizeof(cc_item_t));
        new_item->key = (char *) malloc(strlen(key) * sizeof(char));
        strcpy(new_item->key, key);
        new_item->data = (int *)malloc(sizeof(int));
        *((int *) new_item->data) = d;

        ret = ht_insert(&ht, new_item);
        if (ret != 0) {
            printf("Item discared. HT full or item cycled.\n");
        }
    }

    unsigned int pos;
   
    for (int i = 0;i < HASH_SIZE; i++) {
        if (ht.table[i].data != NULL)
            printf("Item stored at %s (%d): %d\n", ht.table[i].key, i, *((int *)ht.table[i].data));
    }

    printf("//////////////////////////////////////////////\n");

    for (int i = 0;i < HASH_SIZE; i++) {
        if (ht.table[i].data != NULL)
            printf("Item stored at %s (%d): %d\n", ht.table[i].key, i, *((int *)ht.table[i].data));
    }

    printf("Item at cX (%d): %d\n", ht_get_index(&ht, "cX"), *((int*)ht_get(&ht, "cX")));

    ht_remove_by_key(&ht,"dW");

    if (ht_get(&ht,"dW") == NULL)
        printf("Item with \"dW\" key not in table\n");
    
    printf("//////////////////////////////////////////////\n");

    for (int i = 0;i < HASH_SIZE; i++) {
        if (ht.table[i].data != NULL)
            printf("Item stored at %s (%d): %d\n", ht.table[i].key, i, *((int *)ht.table[i].data));
    }
/*    for (i = 'a', j = 'Z'; i <= 'z', j >= 'A';d++, i++, j--) {
        char key[3];
        key[0] = (char) i;
        key[1] = (char) j;
        key[2] = '\0';

        ht_remove(&ht, key);
    }

    int i_count = 0;

    for (int i = 0;i < HASH_SIZE; i++) {
        if (ht.table[i] != NULL)
            i_count++;
    }

    if (i_count == 0)
        printf("All data erased.\n");

*/
    return 0;
}
