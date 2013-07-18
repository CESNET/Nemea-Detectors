/**
 * \file cuckoo_hash.h
 * \brief Generic hash table with Cuckoo hashing support -- header file.
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \date 2013
 */

#ifndef CUCKOO_HASH_H
#define CUCKOO_HASH_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Error constant returned by rehashing function when failing.
 */
#define REHASH_FAILURE -1

/**
 * Constant return by index getter when an item is not found.
 */
#define NOT_FOUND -1

/**
 * Structure of the item of the table.
 */
typedef struct {
    /*@{*/
    char *key; /**< Key of the item (as bytes) */
    void *data; /**< Pointer to data (void for use with any data possible) */
    /*@}*/
} cc_item_t;

/**
 * Structure of the hash table.
 */
typedef struct {
    /*@{*/
    cc_item_t *table; /**< Array of the item representing the storage */
    unsigned int data_size; /**< Size of the data stored in every item (content of the data pointer) */
    unsigned int table_size; /**< Current size/capacity of the table */
    unsigned int key_length; /**< Length of the key used for items */
    /*@}*/
} cc_hash_table_t;
/*
 * Initialization function for the table.
 */
int ht_init(cc_hash_table_t* new_table, unsigned int table_size, unsigned int data_size, unsigned int key_length);

/*
 * Function for resizing and rehashing the table.
 */
int rehash(cc_hash_table_t* ht, cc_item_t* rest);

/*
 * Function for inserting an element.
 */
int ht_insert(cc_hash_table_t* ht, char *key, const void *new_data);

/*
 * Getters for data/index to item in table.
 */
void *ht_get(cc_hash_table_t* ht, char* key);
int ht_get_index(cc_hash_table_t* ht, char* key);

/*
 * Procedures for removing single item from table.
 */
void ht_remove_by_key(cc_hash_table_t* ht, char* key);
void ht_remove_by_index(cc_hash_table_t* ht, unsigned int index);

/*
 * Destructor of the table.
 */
void ht_destroy(cc_hash_table_t *ht);

#ifdef __cplusplus
}
#endif

#endif
