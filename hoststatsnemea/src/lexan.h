#ifndef LEXAN_H
#define LEXAN_H

#include <string>

/*
start
c()                  -> start
c(+, -, *, /, (, ), [, ], =, EOF)
                     -> return
c(,)                 -> return
c(a, A, _)           -> alnum
c(#)                 -> num
c(>)                 -> bigger
c(<)                 -> smaller
c(!)                 -> excl
c(else)              -> error

alnum
c()                  -> return
c(+, -, *, /, >, <, =, !, (, ), [, ], ,, EOF)
                     -> return
c(,)                 -> return
c(a, A, _, #)        -> alnum
c(else)              -> error

num
c()                  -> return
c(+, -, *, /, >, <, =, !, ), EOF)
                     -> return
c(.)                 -> only_num
c(e)                 -> e_state
c(#)                 -> num
c(else)              -> error

only_num
c(#)                 -> num_end
c(else)              -> error

num_end
c()                 -> return
c(+, -, *, /, >, <, =, !, EOF)
                     -> return
c(,)                 -> return
c(#)                 -> only_num_end
c(else)              -> error

e_state
c(+,-,#)             -> only_num
c(else)               -> error

bigger
c(=)                 -> return >=
c(else)              -> return >

smaller
c(=)                 -> return <=
c(else)              -> return <

excl
c(=)                 -> return !=
c(else)              -> error
*/

// If you change this, change also op_priority array in synan.h
enum lexan_ret {
   TOKEN_ERROR,      // 0
   TOKEN_EOF,        // 1
   TOKEN_NUMBER,     // 2
   // Operators
   TOKEN_PLUS,       // 3
   TOKEN_MINUS,      // 4
   TOKEN_STAR,       // 5
   TOKEN_SLASH,      // 6
   TOKEN_LBRACKET,   // 7
   TOKEN_RBRACKET,   // 8
   TOKEN_LSBRACKET,  // 9
   TOKEN_RSBRACKET,  // 10
   TOKEN_EQUAL,      // 11
   TOKEN_UNEQUAL,    // 12
   TOKEN_BIGGER,     // 13
   TOKEN_SMALLER,    // 14
   TOKEN_SMEQUAL,    // 15
   TOKEN_BEQUAL,     // 16
   TOKEN_COMMA,      // 17
   TOKEN_AND,        // 18
   TOKEN_OR,         // 19
   TOKEN_NOT,        // 20
   // Keywords
   TOKEN_SRC,        // 21
   TOKEN_DST,        // 22
   TOKEN_IN,         // 23
   TOKEN_OUT,        // 24
   TOKEN_BYTES,      // 25
   TOKEN_PACKETS,    // 26
   TOKEN_FLOWS,      // 27
   TOKEN_SYN,        // 28
   TOKEN_FIN,        // 29
   TOKEN_RST,        // 30
   TOKEN_PSH,        // 31
   TOKEN_URG,        // 32
   TOKEN_ACK,        // 33
   TOKEN_LINKS,      // 34
   TOKEN_MIN,        // 35
   TOKEN_MAX         // 36
};

using namespace std;

class Lexan
{
   string read_str;
   int len;
   int index;

   bool is_bin_op(int c);  // Is binary operator

public:
   int last_rc;
   string last_token;

   Lexan(string str)
   {
      read_str = str;
      len = read_str.length();
      index = 0;
   };

   int get_token();

protected:
   int keyword();
};

#endif
