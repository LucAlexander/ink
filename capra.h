#ifndef CAPRA_H
#define CAPRA_H

#include <inttypes.h>
#include "kickstart.h"

#define ARENA_SIZE 0x100000000
#define TOKEN_ARENA_SIZE 0x10000
#define ERROR_STRING_MAX 0x100

#define DEBUG

typedef enum TOKEN {
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
	CARROT_TOKEN='^',
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
	U8_TOKEN,
	U16_TOKEN,
	U32_TOKEN,
	U64_TOKEN,
	I8_TOKEN,
	I16_TOKEN,
	I32_TOKEN,
	I64_TOKEN,
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
	IMPORT_TOKEN,
	SIZEOF_TOKEN,
	TOKEN_COUNT
} TOKEN;

MAP_DECL(TOKEN);

typedef struct token {
	enum {
		STRING_TOKEN_TYPE,
		UINT_TOKEN_TYPE,
		INT_TOKEN_TYPE
	} content_tag;
	union{
		string name;
		uint64_t pos;
		int64_t neg;
	} data;
	uint64_t index;
	TOKEN tag;
} token;

void show_tokens(token* tokens, uint64_t token_count);

typedef struct type_ast type_ast;
typedef struct alias_ast alias_ast;
typedef struct typedef_ast typedef_ast;
typedef struct typeclass_ast typeclass_ast;
typedef struct implementation_ast implementation_ast;
typedef struct structure_ast structure_ast;
typedef struct literal_ast literal_ast;
typedef struct pattern_ast pattern_ast;
typedef struct expr_ast expr_ast;
typedef struct term_ast term_ast;
typedef struct parser parser;

void keymap_fill(TOKEN_map* const map);
void compile_file(char* input, const char* output);
void compile_str(string input);
uint8_t issymbol(char c);
void lex_string(parser* const parse);
void parse_program(parser* const parse);
type_ast* parse_type(parser* const parse, uint8_t named, TOKEN end);
type_ast* parse_type_worker(parser* const parse, uint8_t named, TOKEN end);
structure_ast* parse_struct_type(parser* const parse);
void show_type(type_ast* const type);
void show_structure(structure_ast* const s);
alias_ast* parse_alias(parser* const parse);
typedef_ast* parse_typedef(parser* const parse);
void show_alias(alias_ast* const alias);
void show_typedef(typedef_ast* const type);
typeclass_ast* parse_typeclass(parser* const parse);
implementation_ast* parse_implementation(parser* const parse);
void show_typeclass(typeclass_ast* const class);
void show_implementation(implementation_ast* const impl);
pattern_ast* parse_pattern(parser* const parse);
void show_pattern(pattern_ast* pat);
void show_literal(literal_ast* const lit);
void parse_block_expression(parser* const parse, TOKEN end, expr_ast* const expr);
expr_ast* parse_expr(parser* const parse, TOKEN end);
term_ast* parse_term(parser* const parse);
void show_term(term_ast* term);
void show_expression(expr_ast* expr);
type_ast* parse_type_dependency(parser* const parse);
void parse_import(parser* const parse);
void show_error(parser* const parse);
void lex_err(parser* const parse, uint64_t index, string filename);

typedef struct alias_ast {
	token name;
	type_ast* type;
} alias_ast;

typedef struct typedef_ast {
	token name;
	token* params;
	uint64_t param_count;
	type_ast* type;
} typedef_ast;

typedef struct typeclass_ast {
	token name;
	token param;
	term_ast* members;
	uint64_t member_count;
} typeclass_ast;

typedef struct implementation_ast {
	token type;
	token typeclass;
	term_ast* members;
	uint64_t member_count;
} implementation_ast;

typedef struct structure_ast {
	token name;
	token* params;
	uint64_t param_count;
	union {
		struct {
			token* names;
			type_ast* members;
			uint64_t count;
		} structure, union_structure;
		struct {
			token* names;
			uint64_t* values;
			uint64_t count;
		} enumeration;
	} data;
	enum {
		STRUCT_STRUCT,
		UNION_STRUCT,
		ENUM_STRUCT
	} tag;
} structure_ast;

typedef struct literal_ast {
	union {
		uint64_t u;
		int64_t i;
	} data;
	enum {
		INT_LITERAL,
		UINT_LITERAL
	} tag;
} literal_ast;

typedef struct pattern_ast {
	union {
		struct {
			token name;
			pattern_ast* inner;
		} named;
		struct {
			pattern_ast* members;
			uint64_t count;
		} structure;
		struct {
			pattern_ast* ptr;
			pattern_ast* len;
		} fat_ptr;
		token binding;
		token str;
		struct {
			pattern_ast* nest;
			token member;
		} union_selector;
		literal_ast literal;
	} data;
	enum {
		NAMED_PATTERN,
		STRUCT_PATTERN,
		FAT_PTR_PATTERN,
		HOLE_PATTERN,
		BINDING_PATTERN,
		LITERAL_PATTERN,
		STRING_PATTERN,
		UNION_SELECTOR_PATTERN
	} tag;
} pattern_ast;

typedef struct type_ast {
	union {
		struct {
			token * typeclass_dependencies;
			token * dependency_typenames;
			uint64_t dependency_count;
			type_ast* type;
		} dependency;
		struct {
			type_ast* left;
			type_ast* right;
		} function;
		enum {
			U8_TYPE,
			U16_TYPE,
			U32_TYPE,
			U64_TYPE,
			I8_TYPE,
			I16_TYPE,
			I32_TYPE,
			I64_TYPE
		} lit;
		type_ast* ptr;
		struct {
			type_ast* ptr;
			uint64_t len;
		} fat_ptr;
		structure_ast* structure;
		struct {
			token name;
			type_ast* args;
			uint64_t arg_count;
		} named;
	} data;
	uint8_t variable;
	enum {
		DEPENDENCY_TYPE,
		FUNCTION_TYPE,
		LIT_TYPE,
		PTR_TYPE,
		FAT_PTR_TYPE,
		STRUCT_TYPE,
		NAMED_TYPE
	} tag;
} type_ast;

typedef struct expr_ast {
	type_ast* type;
	union {
		struct {
			expr_ast* left;
			expr_ast* right;
		} appl, mutation;
		struct {
			pattern_ast* args;
			expr_ast* expression;
			expr_ast* alt;
			uint64_t arg_count;
		} lambda;
		struct {
			expr_ast* lines;
			uint64_t line_count;
		} block, list;
		literal_ast literal;
		token str;
		token binding;
		term_ast* term;
		struct {
			expr_ast* members;
			token * names;
			uint64_t member_count;
		} constructor;
		struct {
			expr_ast* pred;
			expr_ast* cons;
			expr_ast* alt;
		} if_statement;
		struct {
			token binding;
			expr_ast* initial;
			expr_ast* limit;
			expr_ast* cons;
		} for_statement;
		struct {
			expr_ast* pred;
			expr_ast* cons;
		} while_statement;
		struct {
			expr_ast* pred;
			pattern_ast* patterns;
			expr_ast* cases;
			uint64_t count;
		} match;
		expr_ast* ret;
	} data;
	enum {
		APPL_EXPR,
		LAMBDA_EXPR,
		BLOCK_EXPR,
		LIT_EXPR,
		TERM_EXPR,
		STRING_EXPR,
		LIST_EXPR,
		STRUCT_EXPR,
		BINDING_EXPR,
		MUTATION_EXPR,
		RETURN_EXPR,
		REF_EXPR,
		DEREF_EXPR,
		IF_EXPR,
		FOR_EXPR,
		WHILE_EXPR,
		MATCH_EXPR,
		NOP_EXPR,
	} tag;
} expr_ast;

typedef struct term_ast {
	type_ast* type;
	token name;
	expr_ast* expression;
} term_ast;

MAP_DECL(typedef_ast);
MAP_DECL(alias_ast);
MAP_DECL(typeclass_ast);
MAP_DECL(implementation_ast);
MAP_DECL(implementation_ast_map);
MAP_DECL(term_ast);
MAP_DECL(uint64_t);

typedef struct parser {
	pool* mem;
	pool* token_mem;
	TOKEN_map* keymap;
	token* tokens;
	string text;
	uint64_t text_index;
	uint64_t token_count;
	uint64_t token_index;
	string err;
	uint64_t err_token;
	typedef_ast_map* types;
	alias_ast_map* aliases;
	typeclass_ast_map* typeclasses;
	implementation_ast_map_map* implementations;
	term_ast_map* terms;
	term_ast* term_list;
	uint64_t term_count;
	uint64_t term_capacity;
	uint64_t_map* imported;
	string* file_offsets;
	uint64_t file_offset_count;
	uint64_t file_offset_capacity;
	string mainfile;
} parser;

typedef struct binding {
	token* name;
	type_ast* type;
} binding;

typedef struct scope {
	pool* mem;
	binding* bindings;
	uint64_t binding_capacity;
	uint64_t binding_count;
} scope;

uint64_t push_binding(scope* const s, token* const t, type_ast* const type);
void pop_binding(scope* const s, uint64_t pos);

token* reduce_alias(parser* const parse, token* const t);

typedef struct walker {
	scope* local_scope;
} walker;

void walk_expr(walker* const walk, expr_ast* const expr);
void walk_term(walker* const walk, term_ast* const term);

#endif
