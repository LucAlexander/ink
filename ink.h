#ifndef INK_H
#define INK_H

#include <inttypes.h>
#include "kickstart.h"

#define ARENA_SIZE 0x50000000
#define TOKEN_ARENA_SIZE 0x10000
#define TEMP_ARENA_SIZE 0x50000000
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
	CONSTANT_TOKEN,
	BREAK_TOKEN,
	CONTINUE_TOKEN,
	AS_TOKEN,
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
	CLOSURE_COPY_TOKEN,
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
typedef struct const_ast const_ast;
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
const_ast* parse_constant(parser* const parse);
void show_constant(const_ast* constant);

typedef struct const_ast {
	token name;
	expr_ast* value;
} const_ast;

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
	type_ast* type;
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
			token* typeclass_dependencies;
			token* dependency_typenames;
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
			I64_TYPE,
			INT_ANY
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
	uint8_t dot;
	union {
		struct {
			expr_ast* left;
			expr_ast* right;
		} appl, mutation, access;
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
			token* names;
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
		expr_ast* ref;
		expr_ast* deref;
		expr_ast* closure;
		type_ast* size_type;
		struct {
			type_ast* target;
			expr_ast* source;
		} cast;
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
		SIZEOF_EXPR,
		REF_EXPR,
		DEREF_EXPR,
		IF_EXPR,
		FOR_EXPR,
		WHILE_EXPR,
		MATCH_EXPR,
		CAST_EXPR,
		BREAK_EXPR,
		CONTINUE_EXPR,
		CLOSURE_COPY_EXPR,
		NOP_EXPR,
		//for use after walk
		STRUCT_ACCESS_EXPR,
		ARRAY_ACCESS_EXPR
	} tag;
} expr_ast;

typedef struct term_ast {
	type_ast* type;
	token name;
	expr_ast* expression;
} term_ast;

typedef typedef_ast* typedef_ptr;
typedef alias_ast* alias_ptr;
typedef const_ast* const_ptr;
typedef typeclass_ast* typeclass_ptr;
typedef implementation_ast* implementation_ptr;
typedef term_ast* term_ptr;

MAP_DECL(typedef_ptr);
MAP_DECL(alias_ptr);
MAP_DECL(const_ptr);
MAP_DECL(typeclass_ptr);
MAP_DECL(implementation_ptr);
MAP_DECL(implementation_ptr_map);
MAP_DECL(term_ptr);
MAP_DECL(type_ast);
MAP_DECL(uint64_t);
MAP_DECL(token);

#define GROWABLE_BUFFER_DECL(type)\
	typedef struct type##_buffer {\
		pool* mem;\
		type* buffer;\
		uint64_t capacity;\
		uint64_t count;\
	} type##_buffer;\
\
	type##_buffer type##_buffer_init(pool* const mem);\
\
	void type##_buffer_insert(type##_buffer* const buffer, type elem);\
\
	type* type##_buffer_top(type##_buffer* const buffer);\
\
	void type##_buffer_clear(type##_buffer* const buffer);

#define GROWABLE_BUFFER_IMPL(type)\
	type##_buffer type##_buffer_init(pool* const mem){\
		type##_buffer buffer = {\
			.mem = mem,\
			.buffer = pool_request(mem, sizeof(type)*2),\
			.capacity = 2,\
			.count = 0\
		};\
		return buffer;\
	}\
\
	void type##_buffer_insert(type##_buffer* const buffer, type elem){\
		if (buffer->capacity == buffer->count){\
			buffer->capacity *= 2;\
			type* data = pool_request(buffer->mem, sizeof(type)*buffer->capacity);\
			for (uint64_t i = 0;i<buffer->count;++i){\
				data[i] = buffer->buffer[i];\
			}\
			buffer->buffer = data;\
		}\
		buffer->buffer[buffer->count] = elem;\
		buffer->count += 1;\
	}\
\
	type* type##_buffer_top(type##_buffer* const buffer){\
		return &buffer->buffer[buffer->count-1];\
	}\
\
	void type##_buffer_clear(type##_buffer* const buffer){\
		buffer->count = 0;\
	}

GROWABLE_BUFFER_DECL(typedef_ast);
GROWABLE_BUFFER_DECL(alias_ast);
GROWABLE_BUFFER_DECL(const_ast);
GROWABLE_BUFFER_DECL(typeclass_ast);
GROWABLE_BUFFER_DECL(implementation_ast);
GROWABLE_BUFFER_DECL(term_ast);
GROWABLE_BUFFER_DECL(term_ptr);
GROWABLE_BUFFER_DECL(expr_ast);

MAP_DECL(term_ptr_buffer);

typedef struct parser {
	pool* mem;
	pool* temp_mem;
	pool* token_mem;
	TOKEN_map* keymap;
	token* tokens;
	string text;
	uint64_t text_index;
	uint64_t token_count;
	uint64_t token_index;
	string err;
	uint64_t err_token;
	typedef_ptr_map* types;
	alias_ptr_map* aliases;
	const_ptr_map* constants;
	typeclass_ptr_map* typeclasses;
	implementation_ptr_map_map* implementations;
	term_ptr_map* terms;
	alias_ast_buffer alias_list;
	const_ast_buffer const_list;
	typedef_ast_buffer type_list;
	typeclass_ast_buffer typeclass_list;
	implementation_ast_buffer implementation_list;
	term_ast_buffer term_list;
	uint64_t_map* imported;
	string* file_offsets;
	uint64_t file_offset_count;
	uint64_t file_offset_capacity;
	string mainfile;
	uint64_t_map* enumerated_values;
	term_ptr_buffer_map* implemented_terms;
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

uint64_t push_binding(parser* const parse, scope* const s, token* const t, type_ast* const type);
void pop_binding(scope* const s, uint64_t pos);

typedef struct expr_stack expr_stack;
typedef struct expr_stack {
	pool* mem;
	expr_ast** exprs;
	uint64_t expr_capacity;
	uint64_t expr_count;
	expr_stack* next;
	expr_stack* prev;
} expr_stack;

uint64_t push_expr(expr_stack* const s, expr_ast* expr);
void pop_expr(expr_stack* const s, uint64_t pos);

GROWABLE_BUFFER_DECL(binding);

typedef struct scope_ptr_stack {
	pool* mem;
	uint64_t capacity;
	uint64_t count;
	uint64_t* ptrs;
	binding_buffer* scraped_bindings;
} scope_ptr_stack;

typedef struct token_stack {
	pool* mem;
	token* tokens;
	uint64_t count;
	uint64_t capacity;
} token_stack;

uint64_t token_stack_push(token_stack* const stack, token t);
void token_stack_pop(token_stack* const stack, uint64_t pos);
token token_stack_top(token_stack* const stack);

typedef struct walker {
	parser* parse;
	scope* local_scope;
	scope_ptr_stack* scope_ptrs;
	expr_stack* outer_exprs;
	string next_lambda;
	token_stack* term_stack;
} walker;

void push_expr_stack(walker* const walk);
void pop_expr_stack(walker* const walk);

uint64_t push_scope_ptr(walker* const walk);
void pop_scope_ptr(walker* const walk, uint64_t pos);
void scrape_binding(walker* const walk, binding* bind);
void scrape_lower_binding(walker* const walk, binding* bind);
void generate_new_lambda(walker* const walk);
void lift_lambda(walker* const walk, expr_ast* const expr, type_ast* const type, token newname);

GROWABLE_BUFFER_DECL(token);
MAP_DECL(token_buffer);

typedef struct map_stack map_stack;
typedef struct map_stack {
	token_map map;
	token_buffer_map deps;
	map_stack* next;
	map_stack* prev;
} map_stack;

typedef struct realias_walker {
	parser* parse;
	map_stack* relations;
	string next_generic;
	token_buffer generic_collection_buffer;
} realias_walker;

void push_map_stack(realias_walker* const walk);
void pop_map_stack(realias_walker* const walk);

void realias_type_expr(realias_walker* const walk, expr_ast* const expr);
void realias_type_term(realias_walker* const walk, term_ast* const term);
void realias_type(realias_walker* const walk, type_ast* const type);
void realias_type_structure(realias_walker* const walk, structure_ast* const s);

type_ast* sprinkle_deps(realias_walker* const walk, type_ast* term_type);
void collect_dependencies(realias_walker* const walk, type_ast* const type);
void collect_dependencies_struct(realias_walker* const walk, structure_ast* const s);
void scrape_deps(realias_walker* const walk, type_ast* const term_type);

type_ast* reduce_alias(parser* const parse, type_ast* start);
type_ast* reduce_alias_and_type(parser* const parse, type_ast* start);
type_ast* in_scope(walker* const walk, token* const bind, type_ast* const expected_type);
uint8_t type_equal(parser* const parse, type_ast* const left, type_ast* const right);
uint8_t type_equal_worker(parser* const parse, token_map* const generics, type_ast* const left, type_ast* const right);
uint8_t structure_equal(parser* const parse, token_map* const generics, structure_ast* const left, structure_ast* const right);
type_ast* deep_copy_type_replace(pool* const mem, type_ast_map* relation, type_ast* const source);
structure_ast* deep_copy_structure_replace(pool* const mem, type_ast_map* relation, structure_ast* const source);
uint64_t nearest_token(expr_ast* const e);
uint64_t nearest_pattern_token(pattern_ast* const pat);
type_ast* is_member(type_ast* const obj, expr_ast* const field);
type_ast_map* clash_types(parser* const parse, type_ast* const left, type_ast* const right);
uint8_t clash_types_worker(parser* const parse, type_ast_map* relation, type_ast* const left, type_ast* const right);
uint8_t clash_structure_worker(parser* const parse, type_ast_map* relation, structure_ast* const left, structure_ast* const right);
structure_ast* deep_copy_structure(walker* const walk, structure_ast* const source);
type_ast* deep_copy_type(walker* const walk, type_ast* const source);
uint8_t type_valid(parser* const parse, type_ast* const type);
uint8_t struct_valid(parser* const parse, structure_ast* const s);
implementation_ast* type_depends(walker* const walk, type_ast* const depends, type_ast* const func, type_ast* const arg_outer, type_ast* const arg);
void generate_new_generic(realias_walker* const walk);
uint8_t type_equiv(parser* const parse, type_ast* const left, type_ast* const right);
uint8_t type_equiv_worker(parser* const parse, token_map* const generics, type_ast_map* const relation, type_ast* const left, type_ast* const right);
uint8_t struct_equiv_worker(parser* const parse, token_map* const generics,  type_ast_map* const relation, structure_ast* const left, structure_ast* const right);

type_ast* walk_expr(walker* const walk, expr_ast* const expr, type_ast* expected_type, type_ast* const outer_type, uint8_t is_outer);
type_ast* walk_term(walker* const walk, term_ast* const term, type_ast* expected_type, uint8_t is_outer);
type_ast* walk_pattern(walker* const walk, pattern_ast* const pat, type_ast* const expected_type);
void check_program(parser* const parse);

typedef struct line_relay_node line_relay_node;
typedef struct line_relay_node {
	line_relay_node* next;
	expr_ast* line;
} line_relay_node;

typedef struct line_relay {
	pool* mem;
	line_relay_node* first;
	line_relay_node* last;
	uint64_t len;
} line_relay;

line_relay line_relay_init(pool* const mem);
void line_relay_append(line_relay* const lines, expr_ast* const line);
void line_relay_concat(line_relay* const left, line_relay* const right);

uint8_t type_recursive(parser* const parse, token name, type_ast* const type);
uint8_t type_recursive_struct(parser* const parse, token name, structure_ast* const s);
uint64_t sizeof_type(parser* const parse, type_ast* const type);
uint64_t sizeof_struct(parser* const parse, structure_ast* const s);
expr_ast* new_term(walker* const walk, type_ast* const type, expr_ast* const expression);
expr_ast* term_name(walker* const walk, term_ast* const term);
void function_to_structure_type(walker* const walk, term_ast* const term);
void function_to_structure_type_isolated(walker* const walk, type_ast* const type, type_ast* const host);
expr_ast* transform_expr(walker* const walk, expr_ast* const expr, uint8_t is_outer, line_relay* const newlines);
void transform_term(walker* const walk, term_ast* const term, uint8_t is_outer);
void transform_pattern(walker* const walk, pattern_ast* const pat, line_relay* const newlines);

typedef struct scope_info {
	uint8_t top_level;
	type_ast* type;
} scope_info;

scope_info
in_scope_transform(walker* const walk, token* const bind, type_ast* expected_type);

#endif
