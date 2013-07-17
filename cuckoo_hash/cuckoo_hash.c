/**
 * \file cuckoo_hash.c
 * \brief Generic hash table with Cuckoo hashing support.
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \date 2013
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cuckoo_hash.h"

/*
 * Hash function used for the table. Can be changed.
 */

static unsigned int hash_1(char* key, unsigned int key_length, unsigned int t_size)
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

static unsigned int hash_2(char* key, unsigned int key_length, unsigned int t_size)
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
int ht_init(cc_hash_table_t* new_table, unsigned int table_size, unsigned int data_size, unsigned int key_length)
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
    new_table->key_length = key_length; 

    return 0;
}

/**
 * Function for resizing/rehashing the table.
 * This function is called only when the table is unable to hold anymore.
 * items. It resizes the old table using double the capacity and rehashes 
 * all items that were stored in the old table so far. Then it inserts the 
 * item that would be discarded. If this function fails the table cannot be 
 * used anymore and the program cannot continue due the lack of memory.
 *
 * @param ht Table to be resized and rehashed.
 * @param Item to be inserted after rehashing.
 * @return 0 on succes otherwise REHASH_FAILURE.
 */
int rehash(cc_hash_table_t* ht, cc_item_t* rest)
{
    cc_item_t *old_table, *new_table;

    // allocate new table
    new_table = (cc_item_t*) calloc((ht->table_size * 2), sizeof(cc_item_t));

    if (new_table == NULL) {
        fprintf(stderr, "ERROR: Hash table cannot be extended. Unable to continue.\n");
        return -1;
    }

    unsigned int old_size = ht->table_size;

    old_table = ht->table;
    ht->table = new_table;
    ht->table_size *= 2;

    // rehash and copy items from old table to new one
    for (int i = 0; i < old_size; i++) {
        if (old_table[i].key != NULL && old_table[i].data != NULL) {
            ht_insert(ht, old_table[i].key, old_table[i].data);
        }
    }

    // insert the remaining item
    ht_insert(ht, rest->key, rest->data);

    // destroy old table
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

/**
 * Function for inserting the item into the table.
 * This function perform the insertion operation using the "Cuckoo hashing" 
 * algorithm. It computes the one hash for the item and tries to insert it 
 * on the retrieved position. If the positio is empty the item is inserted 
 * without any other necessary operations. However if the position is already 
 * occupied the residing item is kicked out and replaced with the currently 
 * inserted item. Then the funstion computes both hashes for the kicked out 
 * item and determines which one to use alternatively. Then it tries to insert 
 * this item using the same method. For preventing infinite loop the "TTL" value 
 * is implemented. If this is exceeded the table is resized and rehashed using 
 * the rehash() function.
 *
 * @param ht Table in which we want to insert the item.
 * @param new_data Pointer to new data to be inserted.
 * @return 0 on succes otherwise REHASH_FAILURE when the rehashing function fails.
 */
int ht_insert(cc_hash_table_t* ht, char *key, const void *new_data)
{
    int t, ret;
    unsigned int pos, swap1, swap2;
    pos = hash_1(key, ht->key_length, ht->table_size);

    cc_item_t prev, curr;

    // prepare memory for storing "kicked" values
    prev.key = malloc(ht->key_length);
    prev.data = malloc(ht->data_size);
    
    // prepare memory for data
    curr.key = malloc(ht->key_length);
    curr.data = malloc(ht->data_size);

    // make a working copy of inserted data
    memcpy(curr.key, key, ht->key_length);
    memcpy(curr.data, new_data, ht->data_size);

    for (t = 1; t <= 10; t++) {
        if (ht->table[pos].data == NULL && ht->table[pos].key == NULL) { // try empty
            // we insert a new value into the table

            // assign data and key pointers
            ht->table[pos].key = curr.key; 
            ht->table[pos].data = curr.data;

            // free the rest of the memory
            free(prev.data);
            free(prev.key);

            return 0;
        }

        // computed position is occupied --> we kick the residing item out
        
        memcpy(prev.key, ht->table[pos].key, ht->key_length);
        memcpy(prev.data, ht->table[pos].data, ht->data_size);
        
        //copy new item
        memcpy(ht->table[pos].key, curr.key, ht->key_length);
        memcpy(ht->table[pos].data, curr.data, ht->data_size);

        // compute both hashses for kicked item
        swap1 = hash_1(prev.key, ht->key_length, ht->table_size);
        swap2 = hash_2(prev.key, ht->key_length, ht->table_size);

        // test which one was used
        if (swap2 == pos) {
            pos = swap1;
        } else {
            pos = swap2;
        }
        
        // prepare the item for insertion
        memcpy(curr.key, prev.key, ht->key_length);
        memcpy(curr.data, prev.data, ht->data_size);
    }
   
    // TTL for insertion exceeded, rehash is needed 
    free(prev.data);
    free(prev.key);

    // rehash the table and return the appropriate value is succesful
    ret = rehash(ht, &curr); 
    free(curr.data);
    free(curr.key);
    return ret;
    
}

/**
 * Function for getting the data from table.
 * Function computes both hashes for the given key and checks the positions
 * for the desired data. Pointer to the data is returned when found.
 *
 * @param ht Hash table to be searched for data.
 * @param key Key of the desired item.
 * @return Pointer to the data when found otherwise NULL.
 */
void *ht_get(cc_hash_table_t* ht, char* key)
{
    unsigned int pos1, pos2;
    
    pos1 = hash_1(key, ht->key_length, ht->table_size);
    pos2 = hash_2(key, ht->key_length, ht->table_size);

    if (ht->table[pos1].data != NULL && memcmp(key, ht->table[pos1].key, ht->key_length) == 0) {
        return ht->table[pos1].data;
    }
    if (ht->table[pos2].data != NULL && memcmp(key, ht->table[pos2].key, ht->key_length) == 0) {
        return ht->table[pos2].data;
    }
    return NULL;
}

/**
 * Function for getting the index of the item in table.
 * Function computes both hashes for the given key and checks the positions
 * for the desired item. Index is returned when found.
 *
 * @param ht Hash table to be searched for data.
 * @param key Key of the desired item.
 * @return Index of the item in table otherwise -1.
 */
unsigned int ht_get_index(cc_hash_table_t* ht, char* key)
{
    unsigned int pos1, pos2;
    
    pos1 = hash_1(key, ht->key_length, ht->table_size);
    pos2 = hash_2(key, ht->key_length, ht->table_size);

    if (ht->table[pos1].data != NULL && memcmp(key, ht->table[pos1].key, ht->key_length) == 0) {
        return pos1;
    }
    if (ht->table[pos2].data != NULL && memcmp(key, ht->table[pos2].key, ht->key_length) == 0) {
        return pos2;
    }
    return -1;
}

/**
 * Procedure for removing the item from table.
 * Procedure searches for the data using the given key and frees any 
 * used by the item. If the item is already empty the procedure does nothing.
 *
 * @param ht Hash table to be searched for data.
 * @param key Key of the desired item.
 */
void ht_remove_by_key(cc_hash_table_t* ht, char* key)
{
    unsigned int pos1, pos2;
    pos1 = hash_1(key, ht->key_length, ht->table_size);
    pos2 = hash_2(key, ht->key_length, ht->table_size);
 
    if (ht->table[pos1].data != NULL && (memcmp(key, ht->table[pos1].key, ht->key_length) == 0)) {
        free(ht->table[pos1].data);      
        free(ht->table[pos1].key);
        ht->table[pos1].data = NULL;
        ht->table[pos1].key = NULL;
        return;
    }

    if (ht->table[pos2].data != NULL && (memcmp(key, ht->table[pos2].key, ht->key_length) == 0)) {
        free(ht->table[pos2].data);      
        free(ht->table[pos2].key);
        ht->table[pos2].data = NULL;
        ht->table[pos2].key = NULL;
        return;
    }
}

/**
 * Procedure for removing the item from table (index version).
 * Procedure removes the item pointed by the index from the table.
 * If the item is already empty the procedure does nothing.
 *
 * @param ht Hash table to be searched for data.
 * @param key Key of the desired item.
 */
void ht_remove_by_index(cc_hash_table_t* ht, unsigned int index)
{
    if (ht->table[index].data != NULL && ht->table[index].key != NULL) {
        free(ht->table[index].data);
        free(ht->table[index].key);
        ht->table[index].data = NULL;
        ht->table[index].key = NULL;
    }
}


/**
 * Clean-up procedure.
 * Procedure goes frees all the memory used by the table.
 *
 * @param ht Hash table to be searched for data.
 */
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
