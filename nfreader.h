/* NADEX framework - nfreader library header file
   Author: Vaclav Bartos (ibartosv@fit.vutbr.cz), 2012
   
   This library is derived from original source codes of nfdump written by
   Peter Haag. See copyright notices and other notes in nfreader.c file.
*/

#ifndef _NFREADER_H
#define _NFREADER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

///////////////////////////////////////////////////////////////////////////////
// Sturcture definitions

typedef struct nf_ip_addr_s {
	union {
		struct {
			uint32_t	fill1[2];
			uint32_t	_v4;
			uint32_t	fill2;
		};
		uint64_t		_v6[2];
	} ip_union;
} nf_ip_addr_t;

/*typedef struct extension_map_s {
 	// record head
 	uint16_t	type;	// is ExtensionMapType
 	uint16_t	size;	// size of full map incl. header

	// map data
	uint16_t	map_id;			// identifies this map
 	uint16_t	extension_size; // size of all extensions
	uint16_t	ex_id[1];		// extension id array
} extension_map_t;*/

/* the master record contains all possible record fields unpacked */
typedef struct master_record_s {
    // common information from all netflow versions

    uint16_t    type;           // index 0  0xffff 0000 0000 0000
    uint16_t    size;           // index 0  0x0000'ffff'0000 0000
    uint8_t     flags;          // index 0  0x0000'0000'ff00'0000
    uint8_t     exporter_ref;   // index 0  0x0000'0000'00ff'0000
    uint16_t    ext_map;        // index 0  0x0000'0000'0000'ffff

    uint16_t    msec_first;     // index 1  0xffff'0000'0000'0000
    uint16_t    msec_last;      // index 1  0x0000'ffff'0000'0000

    uint32_t    first;          // index 1  0x0000'0000'ffff'ffff

    uint32_t    last;           // index 2  0xffff'ffff'0000'0000
    uint8_t     fwd_status;     // index 2  0x0000'0000'ff00'0000
    uint8_t     tcp_flags;      // index 2  0x0000'0000'00ff'0000
    uint8_t     prot;           // index 2  0x0000'0000'0000'ff00
    uint8_t     tos;            // index 2  0x0000'0000'0000'00ff

    // extension 8
    uint16_t    srcport;        // index 3  0xffff'0000'0000'0000
    uint16_t    dstport;        // index 3  0x0000'ffff'0000'0000
    union {
        struct {
            uint8_t dst_tos;    // index 3  0x0000'0000'ff00'0000
            uint8_t dir;        // index 3  0x0000'0000'00ff'0000
            uint8_t src_mask;   // index 3  0x0000'0000'0000'ff00
            uint8_t dst_mask;   // index 3  0x0000'0000'0000'00ff
        };
        uint32_t    any;
    };

    // extension 4 / 5
    uint32_t    input;          // index 4  0xffff'ffff'0000'0000
    uint32_t    output;         // index 4  0x0000'0000'ffff'ffff

    // extension 6 / 7
    uint32_t    srcas;          // index 5  0xffff'ffff'0000'0000
    uint32_t    dstas;          // index 5  0x0000'0000'ffff'ffff

    // IP address block 
    union {                     
        struct _ipv4_s {
            uint32_t    fill1[2];   // <empty>      index 6 0xffff'ffff'ffff'ffff
            uint32_t    srcaddr;    // srcaddr      index 7 0xffff'ffff'0000'0000
            uint32_t    fill2;      // <empty>      index 7 0x0000'0000'ffff'ffff
            uint32_t    fill3[2];   // <empty>      index 8 0xffff'ffff'ffff'ffff
            uint32_t    dstaddr;    // dstaddr      index 9 0xffff'ffff'0000'0000
            uint32_t    fill4;      // <empty>      index 9 0xffff'ffff'0000'0000
        } _v4;  
        struct _ipv6_s {
            uint64_t    srcaddr[2]; // srcaddr[0-1] index 6 0xffff'ffff'ffff'ffff
                                    // srcaddr[2-3] index 7 0xffff'ffff'ffff'ffff
            uint64_t    dstaddr[2]; // dstaddr[0-1] index 8 0xffff'ffff'ffff'ffff
                                    // dstaddr[2-3] index 9 0xffff'ffff'ffff'ffff
        } _v6;
    } ip_union;

    // counter block - expanded to 8 bytes
    uint64_t    dPkts;          // index 10 0xffff'ffff'ffff'ffff
    uint64_t    dOctets;        // index 11 0xffff'ffff'ffff'ffff

    // extension 9 / 10
    nf_ip_addr_t ip_nexthop;     // ipv4   index 13 0x0000'0000'ffff'ffff
                                // ipv6   index 12 0xffff'ffff'ffff'ffff
                                // ipv6   index 13 0xffff'ffff'ffff'ffff

    // extension 11 / 12
    nf_ip_addr_t bgp_nexthop;    // ipv4   index 15 0x0000'0000'ffff'ffff
                                // ipv6   index 14 0xffff'ffff'ffff'ffff
                                // ipv6   index 15 0xffff'ffff'ffff'ffff

    // extension 13
    uint16_t    src_vlan;       // index 16 0xffff'0000'0000'0000
    uint16_t    dst_vlan;       // index 16 0x0000'ffff'0000'0000
    uint32_t    fill1;          // align 64bit word

    // extension 14 / 15
    uint64_t    out_pkts;       // index 17 0xffff'ffff'ffff'ffff

    // extension 16 / 17
    uint64_t    out_bytes;      // index 18 0xffff'ffff'ffff'ffff

    // extension 18 / 19
    uint64_t    aggr_flows;     // index 19 0xffff'ffff'ffff'ffff

    // extension 20
    uint64_t    in_src_mac;     // index 20 0xffff'ffff'ffff'ffff

    // extension 20
    uint64_t    out_dst_mac;    // index 21 0xffff'ffff'ffff'ffff

    // extension 21
    uint64_t    in_dst_mac;     // index 22 0xffff'ffff'ffff'ffff

    // extension 21
    uint64_t    out_src_mac;    // index 23 0xffff'ffff'ffff'ffff

    // extension 22
    uint32_t    mpls_label[10];

    // extension 23 / 24
    nf_ip_addr_t ip_router;      // ipv4   index 30 0x0000'0000'ffff'ffff
                                // ipv6   index 29 0xffff'ffff'ffff'ffff
                                // ipv6   index 30 0xffff'ffff'ffff'ffff

    // extension 25
    uint16_t    fill;           // fill index 31 0xffff'0000'0000'0000
    uint8_t     engine_type;    // type index 31 0x0000'ff00'0000'0000
    uint8_t     engine_id;      // ID   index 31 0x0000'00ff'0000'0000

    // last entry in master record 
    void/*extension_map_t*/ *map_ref;
} master_record_t;

/* flags in master_record are defined as:
 * bit  0:  0: IPv4              1: IPv6
 * bit  1:  0: 32bit dPkts       1: 64bit dPkts
 * bit  2:  0: 32bit dOctets     1: 64bit dOctets 
 * bit  3:  0: IPv4 next hop     1: IPv6 next hop
 * bit  4:  0: IPv4 BGP next hop 1: BGP IPv6 next hop
 * bit  5:  0:                   1:
 * bit  6:  0:                   1:
 * bit  7:  0:                   1:
 * bit  8:  0: unsampled         1: sampled flow - sampling applied 
*/

/* structure containing basic statistics read from file header */ 
typedef struct stat_record_s {
	// overall stat
	uint64_t	numflows;
	uint64_t	numbytes;
	uint64_t	numpackets;
	// flow stat
	uint64_t	numflows_tcp;
	uint64_t	numflows_udp;
	uint64_t	numflows_icmp;
	uint64_t	numflows_other;
	// bytes stat
	uint64_t	numbytes_tcp;
	uint64_t	numbytes_udp;
	uint64_t	numbytes_icmp;
	uint64_t	numbytes_other;
	// packet stat
	uint64_t	numpackets_tcp;
	uint64_t	numpackets_udp;
	uint64_t	numpackets_icmp;
	uint64_t	numpackets_other;
	// time window
	uint32_t	first_seen;
	uint32_t	last_seen;
	uint16_t	msec_first;
	uint16_t	msec_last;
	// other
	uint32_t	sequence_failure;
} stat_record_t; 


// Data needed to store for each opened file (simulating class attributes).
// Pointer to it must be passed to every function working with the file.
typedef struct {
   void/*extension_map_list_t*/ *extension_map_list;
   void/*common_record_t*/ *in_buff;
   void/*common_record_t*/ *rec_ptr;
   char *filename;
   int   rfd;
   int   opened;
   int   remaining_records;
} nf_file_t;

///////////////////////////////////////////////////////////////////////////////
// Function prototypes

/* Open given nfdump file and prepare to read flows. If filename is NULL, read 
   from stdin.
   Data needed to store context of opened file will be stored to 'file'.
*/
int nf_open(nf_file_t *file, char *filename);

/* Read next flow record in opened file and save it into master_record.
   If master_record is NULL, just skip the record.
   If there are no more records, E_NO_MORE_RECORDS is returned (and 
   master_record is not changed).
*/
int nf_next_record(nf_file_t *file, master_record_t *master_record);

/* Close opened file and clear buffers.
   This function should be called when reading is done.
*/
void nf_close(nf_file_t *file);


/* Get statistics form a header of given file and save it to stats structure. */
int nf_get_stats(char *filename, stat_record_t *stats);



// Error codes (returned by functions above)
#define E_OK                  0  // No error
#define E_NO_MORE_RECORDS     1  // No more records to read
#define E_OPEN_FILE          -1  // Error when opening file
#define E_NOT_OPENED         -2  // Returned by next_record() when no file is opened
#define E_CORRUPTED          -3  // File is probably corrupted
#define E_READ_ERROR         -4  // Error when reading file
#define E_MEMORY            -10  // Can't allocate enough memory


#ifdef __cplusplus
} //extern "C"
#endif

#endif
