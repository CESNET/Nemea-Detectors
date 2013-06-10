#ifndef _UNIREC_H_
#define _UNIREC_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Structures and functions to handle generic IP addresses (IPv4 or IPv6).
 * IP addresses are stored on 128 bits. IPv6 addresses are stored directly.
 * IPv4 addresses are converted to 128 bit is this way:
 * 0000:0000:0000:0000:<ipv4_addr>:ffff:ffff
 * No valid IPv6 address should look like this so it's possible to determine
 * IP address version without explicitly storing any flag. 
 *
 * Addresses are stored in big endian (network byte order).
 * 
 * This implementation assumes the platform uses little-endian (true for x86
 * architectures).
 * 
 * Layout of ip_addr_t union: 
 *  MSB                                 LSB
 *  xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
 * |      i64[0]       |       i64[1]      |
 * | i32[0]  | i32[1]  | i32[2]  | i32[3]  |
 * |bytes[0] ...              ... bytes[15]|   
 */

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>


typedef union ip_addr_u {
   uint8_t  bytes[16];
   uint8_t  i8[16];
   uint32_t i32[4];
   uint64_t i64[2];
} ip_addr_t;


// Return 1 if the address is IPv4, 0 otherwise.
extern inline int ip_is4(ip_addr_t *addr)
{
   return (addr->i64[0] == 0 && addr->i32[3] == 0xffffffff);
}

// Return 1 if the address is IPv4, 0 otherwise.
extern inline int ip_is6(ip_addr_t *addr)
{
   return !ip_is4(addr);
}

// Return integer value of an IPv4 address
extern inline uint32_t ip_get_v4_as_int(ip_addr_t *addr)
{
   return ntohl(addr->i32[2]);
}

// Return a pointer to bytes of IPv4 address in big endian (network order)
extern inline char* ip_get_v4_as_bytes(ip_addr_t *addr)
{
   return &addr->bytes[8];
}


// Create ip_addr_t from an IPv4 address stored as a 32bit integer (in machine's native endianness)
extern inline ip_addr_t ip_from_int(uint32_t i)
{
   ip_addr_t a;
   a.i64[0] = 0;
   a.i32[2] = htonl(i);
   a.i32[3] = 0xffffffff;
   return a;
}

// Create ip_addr_t from an IPv4 address stored as 4 bytes in big endian
extern inline ip_addr_t ip_from_4_bytes_be(char b[4])
{
   ip_addr_t a;
   a.i64[0] = 0;
   a.bytes[8] = b[0];
   a.bytes[9] = b[1];
   a.bytes[10] = b[2];
   a.bytes[11] = b[3];
   a.i32[3] = 0xffffffff;
   return a;
}

// Create ip_addr_t from an IPv4 address stored as 4 bytes in little endian
extern inline ip_addr_t ip_from_4_bytes_le(char b[4])
{
   ip_addr_t a;
   a.i64[0] = 0;
   a.bytes[8]  = b[3];
   a.bytes[9]  = b[2];
   a.bytes[10] = b[1];
   a.bytes[11] = b[0];
   a.i32[3] = 0xffffffff;
   return a;
}


// Create ip_addr_t from an IPv6 address stored as 16 bytes in big endian
extern inline ip_addr_t ip_from_16_bytes_be(char b[16])
{
   ip_addr_t a;
   memcpy(&a, b, 16);
   return a;
}

// Create ip_addr_t from an IPv6 address stored as 16 bytes in little endian
extern inline ip_addr_t ip_from_16_bytes_le(char b[16])
{
   ip_addr_t a;
   int i;
   for (i = 0; i < 16; i++)
      a.bytes[i] = b[15-i];
   return a;
}


// Convert IP address in a string into ip_addr_t. Return 1 on success,
// 0 on error (i.e. string doesn't contain a valid IP address).
extern inline int ip_from_str(const char *str, ip_addr_t *addr)
{
   if (strchr(str, ':') == NULL) { // IPv4
      char tmp[4];
      if (inet_pton(AF_INET, str, &tmp) != 1)
         return 0; // err
      *addr = ip_from_4_bytes_be(tmp);
      return 1;
   }
   else { // IPv6
      char tmp[16];
      if (inet_pton(AF_INET6, str, tmp) != 1)
         return 0; // err
      *addr = ip_from_16_bytes_be(tmp);
      return 1;
   }
}



// Convert ip_addr_t to a string representing the address in common notation.
// str must be allocated to at least INET6_ADDRSTRLEN (usually 46) bytes!
extern inline void ip_to_str(ip_addr_t *addr, char *str)
{
   if (ip_is4(addr)) { // IPv4
      inet_ntop(AF_INET, ip_get_v4_as_bytes(addr), str, INET6_ADDRSTRLEN);
   }
   else { // IPv6
      inet_ntop(AF_INET6, addr, str, INET6_ADDRSTRLEN);
   }
}


#ifdef __cplusplus
}
#endif

#endif
