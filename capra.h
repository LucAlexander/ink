#ifndef CAPRA_H
#define CAPRA_H

#include <inttypes.h>
#include "kickstart.h"

#define ARENA_SIZE 0x1000000
#define TOKEN_ARENA_SIZE 0x10000

#define DEBUG

typedef enum TOKEN { // TODO comments, imports
	PAREN_OPEN_TOKEN='(',
	PAREN_CLOSE_TOKEN=')',
	BRACK_OPEN_TOKEN='[',
	BRACK_CLOSE_TOKEN=']',
	BRACE_OPEN_TOKEN='{',
	BRACE_CLOSE_TOKEN='}',
	AT_TOKEN='@',
	COMMA_TOKEN=',',
	SEMI_TOKEN=';',
	COLON_TOKEN=':',
	PIPE_TOKEN='|',
	LAMBDA_TOKEN='\\',
	EQUAL_TOKEN='=',
	BACKTICK_TOKEN='`',
	COMPOSE_TOKEN='.',
	SHIFT_TOKEN='$',
	ASTERISK_TOKEN='*',
	AMPERSAND_TOKEN='&',
	HOLE_TOKEN='_',
	IDENTIFIER_TOKEN=1000,
	SYMBOL_TOKEN,
	STRING_TOKEN,
	CHAR_TOKEN,
	INTEGER_TOKEN,
	ARROW_TOKEN,
	IF_TOKEN,
	ELSE_TOKEN,
	MATCH_TOKEN,
	WHILE_TOKEN,
	FOR_TOKEN,
	VAR_TOKEN,
	ALIAS_TOKEN,
	TYPE_TOKEN,
	STRUCT_TOKEN,
	ENUM_TOKEN,
	UNION_TOKEN,
	DOUBLE_ARROW_TOKEN,
	TYPECLASS_TOKEN,
	IMPLEMENTS_TOKEN,
	RETURN_TOKEN,
	SIZEOF_TOKEN,
	TOKEN_COUNT
} TOKEN;

MAP_DECL(TOKEN);

typedef struct token {
	string name; // TODO unionize
	uint64_t pos;
	int64_t neg;
	uint64_t index;
	TOKEN tag;
} token;

void show_tokens(token* tokens, uint64_t token_count);

typedef struct parser {
	pool* mem;
	pool* token_mem;
	TOKEN_map* keymap;
	token* tokens;
	string text;
	uint64_t text_index;
	uint64_t token_count;
	string err;
} parser;

typedef struct compiler {
	pool* mem;
} compiler;

void keymap_fill(TOKEN_map* const map);
void compile_file(const char* input, const char* output);
compiler compile_str(string input);
uint8_t issymbol(char c);
void lex_string(parser* const parse);
void parse_string(parser* const parse);

#endif
