#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cuckoo_hash.h"

unsigned int RSHash(char* key, unsigned int key_length, unsigned int t_size)
{
    unsigned int a = 63689;
    unsigned int b = 378551;
    unsigned int hash = 0;

    for (unsigned int i = 0; i < key_length; key++, i++) {
        hash = hash * a  + (*key);
        a = a * b;
    }
    return hash % t_size;
}

unsigned int JSHash(char* key, unsigned int key_length, unsigned int t_size)
{
    unsigned int hash = 1315423911;
    unsigned int i    = 0;

    for(i = 0; i < key_length; key++, i++) {
        hash ^= ((hash << 5) + (*key) + (hash >> 2));
    }

    return hash % t_size;
}
/**
 * Initialization function for the hash table.
 * Function gets the pointer to the structure with the table and creates a new 
 * one according to table_size parameter. The data_size parameter serves in 
 * table operations for data manipulation.
 *
 * @param new_table Pointer to a table structure.
 * @param table_size Size of the newly created table.
 * @param data_size Size of the data being stored in the table.
 * @return -1 if the table wasn't created, 0 otherwise.
 */
int ht_init(cc_hash_table_t* new_table, unsigned int table_size, unsigned int data_size)
{
    // allocate the table itself
    new_table->table = (cc_item_t*) calloc(table_size, sizeof(cc_item_t));
    
    // test if the memory was allocated
    if (new_table == NULL) {
        fprintf(stderr, "ERROR: Hash table couldn't be initialized.\n");
        return -1;
    }

    // set data size and current table size
    new_table->data_size = data_size;
    new_table->table_size = table_size;

    return 0;
}

int rehash(cc_hash_table_t* ht, cc_item_t* rest)
{
    cc_item_t *old_table, *new_table;
    cc_hash_table_t dummy;
    new_table = (cc_item_t*) calloc((ht->table_size * 2), sizeof(cc_item_t));

    if (new_table == NULL) {
        fprintf(stderr, "ERROR: Hash table cannot be extended. Unable to continue.\n");
        return -1;
    }

    unsigned int old_size = ht->table_size;

    old_table = ht->table;
    ht->table = new_table;
    ht->table_size *= 2;

    for (int i = 0; i < old_size; i++) {
        if (old_table[i].key != NULL && old_table[i].data != NULL) {
            ht_insert(ht, &old_table[i]);
        }
    }

    ht_insert(ht, rest);

    for(int i = 0; i < old_size; i++) {
        if (old_table[i].key != NULL) {
            free(old_table[i].key);
            old_table[i].key = NULL;
        }
        if (old_table[i].data != NULL) {
            free(old_table[i].data);
            old_table[i].data = NULL;
        }
    }
    free(old_table);

    return 0;
}

int ht_insert(cc_hash_table_t* ht, cc_item_t *new_data)
{
    int t, ret;
    unsigned int pos, swap1, swap2;
    pos = RSHash(new_data->key, strlen(new_data->key), ht->table_size);

    cc_item_t prev, curr;

    prev.key = malloc(COPY_KEY_BUFFER);
    prev.data = malloc(ht->data_size);
    
    curr.key = malloc(COPY_KEY_BUFFER);
    curr.data = malloc(ht->data_size);

    strcpy(curr.key, new_data->key);
    memcpy(curr.data, new_data->data, ht->data_size);

    for (t = 1; t <= 10; t++) {
        if (ht->table[pos].data == NULL && ht->table[pos].key == NULL) { // try empty

            printf("Insert %d\n",t);

            ht->table[pos].key = malloc((strlen(curr.key) + 1) * sizeof(char));
            strcpy(ht->table[pos].key, curr.key);
            ht->table[pos].data = curr.data;
            free(curr.key);
            free(prev.data);
            free(prev.key);
            return 0;
        }

        printf("Insert SWAP %d\n", t);
        
        strcpy(prev.key, ht->table[pos].key);
        memcpy(prev.data, ht->table[pos].data, ht->data_size);
        
        //copy new item
        strcpy(ht->table[pos].key, curr.key);
        memcpy(ht->table[pos].data, curr.data, ht->data_size);

        // compute both hashses
        swap1 = RSHash(prev.key, strlen(prev.key), ht->table_size);
        swap2 = JSHash(prev.key, strlen(prev.key), ht->table_size);

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
    ret = rehash(ht, &curr); 
    free(curr.data);
    free(curr.key);
    return ret;
    
}

void *ht_get(cc_hash_table_t* ht, char* key)
{
    unsigned int pos1, pos2;
    
    pos1 = RSHash(key, strlen(key), ht->table_size);
    pos2 = JSHash(key, strlen(key), ht->table_size);

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
    
    pos1 = RSHash(key, strlen(key), ht->table_size);
    pos2 = JSHash(key, strlen(key), ht->table_size);

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
    pos1 = RSHash(key, strlen(key), ht->table_size);
    pos2 = JSHash(key, strlen(key), ht->table_size);
 
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

void ht_destroy(cc_hash_table_t *ht)
{
    for(int i = 0; i < ht->table_size; i++) {
        if (ht->table[i].key != NULL) {
            free(ht->table[i].key);
            ht->table[i].key = NULL;
        }
        if (ht->table[i].data != NULL) {
            free(ht->table[i].data);
            ht->table[i].data = NULL;
        }
    }
    free(ht->table);
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

        new_item->key = (char *) malloc((strlen(key) + 1)  * sizeof(char));

        strcpy(new_item->key, key);

        new_item->data = (int *)malloc(sizeof(int));

        *((int *) new_item->data) = d;

        ret = ht_insert(&ht, new_item);
        if (ret != 0) {
            fprintf(stderr, "Insertion failed due the maxed out capacity.\n" );
            ht_destroy(&ht);
            free(new_item->key);
            free(new_item->data);
            free(new_item);
            return EXIT_FAILURE;
        }

        free(new_item->key);
        free(new_item->data);
        free(new_item);

    }

    unsigned int pos;
   
    for (int i = 0;i < ht.table_size; i++) {
        if (ht.table[i].data != NULL)
            printf("Item stored at %s (%d): %d\n", ht.table[i].key, i, *((int *)ht.table[i].data));
    }

    printf("//////////////////////////////////////////////\n");

    for (int i = 0;i < ht.table_size; i++) {
        if (ht.table[i].data != NULL)
            printf("Item stored at %s (%d): %d\n", ht.table[i].key, i, *((int *)ht.table[i].data));
    }

    printf("Item at cX (%d): %d\n", ht_get_index(&ht, "cX"), *((int*)ht_get(&ht, "cX")));

    ht_remove_by_key(&ht,"dW");

    if (ht_get(&ht,"dW") == NULL)
        printf("Item with \"dW\" key not in table\n");
    
    printf("//////////////////////////////////////////////\n");

    for (int i = 0;i < ht.table_size; i++) {
        if (ht.table[i].data != NULL)
            printf("Item stored at %s (%d): %d\n", ht.table[i].key, i, *((int *)ht.table[i].data));
    }

    ht_destroy(&ht);
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
