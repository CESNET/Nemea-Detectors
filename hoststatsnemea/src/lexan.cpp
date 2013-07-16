#include <cstring>
#include <cctype>
#include <cstdio>
#include <cstdlib>

#include <string>
#include <iostream>

#include "lexan.h"

using namespace std;

enum lexan_states {
   lexan_start,
   lexan_alnum,
   lexan_num,
   lexan_only_num,
   lexan_num_end,
   lexan_e_state,
   lexan_bigger,
   lexan_smaller,
   lexan_excl,
};

bool Lexan::is_bin_op(int c)
{
   if ( (c == '+') || (c == '-') || (c == '*') || (c == '/') || (c == '>')
       || (c == '<') || (c == '=') || (c == '!') )
   {
      return true;
   }
   else
      return false;
}

int Lexan::get_token()
{
   last_token.erase();
   int state = lexan_start;

   int c = 0;

   while ( 1 ) {
      if ( index == len )
         c = EOF;
      else
         c = read_str[index];

      switch ( state ) {
      // start ----------------------------------------------------------------
      case lexan_start:
         if ( isspace(c) ) {
            index++;
            continue;
         }

         else if ( (c == '+') || (c == '-') || (c == '*') || (c == '/') || (c == '(')
         || (c == ')') || (c == '[') || (c == ']') || (c == ',') )
         {
            switch ( c ) {
               case '+': last_rc = TOKEN_PLUS; break;
               case '-': last_rc = TOKEN_MINUS; break;
               case '*': last_rc = TOKEN_STAR; break;
               case '/': last_rc = TOKEN_SLASH; break;
               case '(': last_rc = TOKEN_LBRACKET; break;
               case ')': last_rc = TOKEN_RBRACKET; break;
               case '[': last_rc = TOKEN_LSBRACKET; break;
               case ']': last_rc = TOKEN_RSBRACKET; break;
               case ',': last_rc = TOKEN_COMMA; break;
               default: last_rc = TOKEN_ERROR; break;
            }
            last_token.push_back(c);
            index++;
            return last_rc;
         }

         else if ( c == EOF ) {
            last_rc = TOKEN_EOF;
            return last_rc;
         }

         else if ( isalpha(c) || c == '_' ) {
            last_token.push_back(c);
            state = lexan_alnum;
            index++;
            continue;
         }

         else if ( isdigit(c) ) {
            last_token.push_back(c);
            state = lexan_num;
            index++;
            continue;
         }

         else if ( c == '>' ) {
            last_token.push_back(c);
            state = lexan_bigger;
            index++;
            continue;
         }

         else if ( c == '<' ) {
            last_token.push_back(c);
            state = lexan_smaller;
            index++;
            continue;
         }

         else if ( c == '!' ) {
            last_token.push_back(c);
            state = lexan_excl;
            index++;
            continue;
         }

         else {
            last_rc = TOKEN_ERROR;
            return last_rc;
         }
      break;

      // alnum ----------------------------------------------------------------
      case lexan_alnum:
         if ( isspace(c) || is_bin_op(c) || (c == '(') || (c == ')') || (c == '[')
         || (c == ']') || (c == ',') || (c == EOF) )
         {
            return keyword();
         }

         else if ( isalnum(c) || (c =='_') ) {
            last_token.push_back(c);
            index++;
            continue;
         }

         else {
            last_rc = TOKEN_ERROR;
            return last_rc;
         }
      break;

      // num ----------------------------------------------------------------
      case lexan_num:
         if ( isspace(c) || is_bin_op(c) || (c == ')') || (c == EOF) ) {
            last_rc = TOKEN_NUMBER;
            return last_rc;
         }

         else if ( c == '.' ) {
            last_token.push_back(c);
            state = lexan_only_num;
            index++;
            continue;
         }

         else if ( c == 'e' ) {
            last_token.push_back(c);
            state = lexan_e_state;
            index++;
            continue;
         }

         else if ( isdigit(c) ) {
            last_token.push_back(c);
            index++;
            continue;
         }

         else {
            last_rc = TOKEN_ERROR;
            return last_rc;
         }
      break;

      // only_num ----------------------------------------------------------------
      case lexan_only_num:
         if ( isdigit(c) ) {
            last_token.push_back(c);
            state = lexan_num_end;
            index++;
            continue;
         }

         else {
            last_rc = TOKEN_ERROR;
            return last_rc;
         }
      break;

      // num_end ----------------------------------------------------------------
      case lexan_num_end:
         if ( isspace(c) || is_bin_op(c) || (c == ')') || (c == EOF) ) {
            last_rc = TOKEN_NUMBER;
            return last_rc;
         }

         else if ( isdigit(c) ) {
            last_token.push_back(c);
            index++;
            continue;
         }

         else {
            last_rc = TOKEN_ERROR;
            return last_rc;
         }
      break;

      // e_state ----------------------------------------------------------------
      case lexan_e_state:
         if ( (c == '+') || (c == '-') || isdigit(c) ) {
            last_token.push_back(c);
            state = lexan_only_num;
            index++;
            continue;
         }

         else {
            last_rc = TOKEN_ERROR;
            return last_rc;
         }
      break;

      // bigger ----------------------------------------------------------------
      case lexan_bigger:
         if ( c == '=' ) {
            last_token.push_back(c);
            index++;
            last_rc = TOKEN_BEQUAL;
            return last_rc;
         }

         else {
            last_rc = TOKEN_BIGGER;
            return last_rc;
         }
      break;

      // smaller ----------------------------------------------------------------
      case lexan_smaller:
         if ( c == '=' ) {
            last_token.push_back(c);
            index++;
            last_rc = TOKEN_SMEQUAL;
            return last_rc;
         }

         else {
            last_rc = TOKEN_SMALLER;
            return last_rc;
         }
      break;

      // excl ----------------------------------------------------------------
      case lexan_excl:
         if ( c == '=' ) {
            last_token.push_back(c);
            index++;
            last_rc = TOKEN_UNEQUAL;
            return last_rc;
         }

         else {
            last_rc = TOKEN_ERROR;
            return last_rc;
         }
      break;

      default:
         last_rc = TOKEN_ERROR;
         return last_rc;
      }
   }

   last_rc = TOKEN_ERROR;
   return last_rc;
}

int Lexan::keyword()
{
   if ( last_token.compare("src") == 0 || last_token.compare("SRC") == 0 )
      last_rc = TOKEN_SRC;
   else if ( last_token.compare("dst") == 0 || last_token.compare("DST") == 0 )
      last_rc = TOKEN_DST;
   else if ( last_token.compare("in") == 0 || last_token.compare("IN") == 0 )
      last_rc = TOKEN_IN;
   else if ( last_token.compare("out") == 0 || last_token.compare("OUT") == 0 )
      last_rc = TOKEN_OUT;
   else if ( last_token.compare("bytes") == 0 || last_token.compare("BYTES") == 0 )
      last_rc = TOKEN_BYTES;
   else if ( last_token.compare("packets") == 0 || last_token.compare("PACKETS") == 0 )
      last_rc = TOKEN_PACKETS;
   else if ( last_token.compare("flows") == 0 || last_token.compare("FLOWS") == 0 )
      last_rc = TOKEN_FLOWS;
   else if ( last_token.compare("syn") == 0 || last_token.compare("SYN") == 0 )
      last_rc = TOKEN_SYN;
   else if ( last_token.compare("fin") == 0 || last_token.compare("FIN") == 0 )
      last_rc = TOKEN_FIN;
   else if ( last_token.compare("rst") == 0 || last_token.compare("RST") == 0 )
      last_rc = TOKEN_RST;
   else if ( last_token.compare("psh") == 0 || last_token.compare("PSH") == 0 )
      last_rc = TOKEN_PSH;
   else if ( last_token.compare("urg") == 0 || last_token.compare("URG") == 0 )
      last_rc = TOKEN_URG;
   else if ( last_token.compare("ack") == 0 || last_token.compare("ACK") == 0 )
      last_rc = TOKEN_ACK;
   else if ( last_token.compare("links") == 0 || last_token.compare("LINKS") == 0 )
      last_rc = TOKEN_LINKS;
   else if ( last_token.compare("min") == 0 || last_token.compare("MIN") == 0 )
      last_rc = TOKEN_MIN;
   else if ( last_token.compare("max") == 0 || last_token.compare("MAX") == 0 )
      last_rc = TOKEN_MAX;
   else if ( last_token.compare("and") == 0 || last_token.compare("AND") == 0 )
      last_rc = TOKEN_AND;
   else if ( last_token.compare("or") == 0 || last_token.compare("OR") == 0 )
      last_rc = TOKEN_OR;
   else if ( last_token.compare("not") == 0 || last_token.compare("NOT") == 0 )
      last_rc = TOKEN_NOT;
   else
      last_rc = TOKEN_ERROR;
   return last_rc;
}

/* Test main
int main()
{
   Lexan lex("out syn * 2 > in ack");
   int lex_rc = lex.get_token();

   while (lex_rc != TOKEN_EOF) {
      cout << lex_rc << " " << lex.last_token << endl;
      lex_rc = lex.get_token();
   }
   return EXIT_SUCCESS;
}
*/
