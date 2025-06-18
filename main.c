#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "ink.h"

MAP_IMPL(TOKEN);
MAP_IMPL(typedef_ptr);
MAP_IMPL(alias_ptr);
MAP_IMPL(const_ptr);
MAP_IMPL(typeclass_ptr);
MAP_IMPL(implementation_ptr);
MAP_IMPL(implementation_ptr_map);
MAP_IMPL(term_ptr);
MAP_IMPL(type_ast);
MAP_IMPL(uint64_t);
MAP_IMPL(token);
MAP_IMPL(term_ast);
MAP_IMPL(expr_ptr);
MAP_IMPL(string);

GROWABLE_BUFFER_IMPL(typedef_ast);
GROWABLE_BUFFER_IMPL(alias_ast);
GROWABLE_BUFFER_IMPL(const_ast);
GROWABLE_BUFFER_IMPL(typeclass_ast);
GROWABLE_BUFFER_IMPL(implementation_ast);
GROWABLE_BUFFER_IMPL(term_ast);
GROWABLE_BUFFER_IMPL(token);
GROWABLE_BUFFER_IMPL(term_ptr);
GROWABLE_BUFFER_IMPL(expr_ast);

MAP_IMPL(token_buffer);
MAP_IMPL(term_ptr_buffer);

GROWABLE_BUFFER_IMPL(binding);

#define assert_local(c, r, s, ...)\
	if (!(c)){\
		memset(parse->err.str, 0, ERROR_STRING_MAX);\
		snprintf(parse->err.str, ERROR_STRING_MAX, s __VA_ARGS__);\
		parse->err.len = ERROR_STRING_MAX;\
		parse->err_token = parse->token_index;\
		return r;\
	}

#define walk_assert(c, i, s, ...)\
	if (!(c)){\
		memset(walk->parse->err.str, 0, ERROR_STRING_MAX);\
		snprintf(walk->parse->err.str, ERROR_STRING_MAX, s __VA_ARGS__);\
		walk->parse->err.len = ERROR_STRING_MAX;\
		walk->parse->err_token = i;\
		return NULL;\
	}

#define assert_prop(r)\
	if (parse->err.len != 0){\
		return r;\
	}

#define walk_assert_prop()\
	if (walk->parse->err.len != 0){\
		return NULL;\
	}

void
compile_file(char* input, const char* output){
	FILE* fd = fopen(input, "r");
	if (fd == NULL){
		fprintf(stderr, "File '%s' could not be opened\n", input);
		return;
	}
	pool mem = pool_alloc(ARENA_SIZE, POOL_STATIC);
	if (mem.buffer == NULL){
		fprintf(stderr, "Couldn't allocate arena\n");
		fclose(fd);
		return;
	}
	uint64_t read_bytes = fread(mem.buffer, sizeof(uint8_t), mem.left, fd);
	fclose(fd);
	if (read_bytes == mem.left){
		fprintf(stderr, "File too big\n");
		pool_dealloc(&mem);
		return;
	}
	string str = {
		.str = pool_request(&mem, read_bytes),
		.len = read_bytes
	};
	if (str.str == NULL){
		fprintf(stderr, "Unable to allocate buffer\n");
		pool_dealloc(&mem);
		return;
	}
	TOKEN_map keymap = TOKEN_map_init(&mem);
	keymap_fill(&keymap);
	pool token_mem = pool_alloc(TOKEN_ARENA_SIZE, POOL_STATIC);
	pool temp_mem = pool_alloc(TEMP_ARENA_SIZE, POOL_STATIC);
	typedef_ptr_map types = typedef_ptr_map_init(&mem);
	alias_ptr_map aliases = alias_ptr_map_init(&mem);
	const_ptr_map constants = const_ptr_map_init(&mem);
	typeclass_ptr_map typeclasses = typeclass_ptr_map_init(&mem);
	implementation_ptr_map_map implementations = implementation_ptr_map_map_init(&mem);
	term_ptr_map terms = term_ptr_map_init(&mem);
	uint64_t_map imported = uint64_t_map_init(&mem);
	uint64_t_map enum_vals = uint64_t_map_init(&mem);
	term_ptr_buffer_map impl_terms = term_ptr_buffer_map_init(&mem);
	term_ptr_map extern_terms = term_ptr_map_init(&mem);
	typedef_ptr_map extern_types = typedef_ptr_map_init(&mem);
	string_map symbol_to_name = string_map_init(&mem);
	parser parse = {
		.mem = &mem,
		.temp_mem = &temp_mem,
		.token_mem = &token_mem,
		.keymap = &keymap,
		.tokens = NULL,
		.text = str,
		.text_index = 0,
		.token_count = 0,
		.token_index = 0,
		.err.str = pool_request(&mem, ERROR_STRING_MAX),
		.err.len = 0,
		.err_token = 0,
		.types = &types,
		.aliases = &aliases,
		.constants = &constants,
		.typeclasses = &typeclasses,
		.implementations = &implementations,
		.terms = &terms,
		.alias_list = alias_ast_buffer_init(&mem),
		.const_list = const_ast_buffer_init(&mem),
		.type_list = typedef_ast_buffer_init(&mem),
		.typeclass_list = typeclass_ast_buffer_init(&mem),
		.implementation_list = implementation_ast_buffer_init(&mem),
		.term_list = term_ast_buffer_init(&mem),
		.imported = &imported,
		.file_offsets=pool_request(&mem, 2*sizeof(string)),
		.file_offset_capacity=2,
		.file_offset_count=0,
		.mainfile.str = input,
		.mainfile.len = strnlen(input, ERROR_STRING_MAX),
		.enumerated_values = &enum_vals,
		.implemented_terms = &impl_terms,
		.extern_terms = &extern_terms,
		.extern_types = &extern_types,
		.extern_term_list = term_ast_buffer_init(&mem),
		.extern_type_list = typedef_ast_buffer_init(&mem),
		.symbol_to_name = &symbol_to_name,
		.next_symbol_name = string_init(&mem, "?A")
	};
	parse.tokens = pool_request(parse.token_mem, sizeof(token));
	lex_string(&parse);
	if (parse.err.len != 0){
		printf("\033[1m[!] Failed to lex, \033[0m");
		string_print(&parse.err);
		printf("\n");
		return;
	}
#ifdef DEBUG
	show_tokens(parse.tokens, parse.token_count);
	printf("\n");
#endif
	parse_program(&parse);
	if (parse.err.len != 0){
		printf("\033[1m[!] Failed to parse, \033[0m");
		show_error(&parse);
		return;
	}
#ifdef DEBUG
	printf("----------------Parsed------------------\n");
#endif
	check_program(&parse);
	if (parse.err.len != 0){
		printf("\033[1m[!] Failed semantic checks, \033[0m");
		show_error(&parse);
		return;
	}
#ifdef DEBUG
	printf("----------------Checked-----------------\n");
#endif
	generate_c(&parse, input, output);
}

void
keymap_fill(TOKEN_map* const map){
	TOKEN_map_insert(map, string_init(map->mem, "->"), ARROW_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "if"), IF_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "else"), ELSE_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "match"), MATCH_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "while"), WHILE_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "for"), FOR_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "constant"), CONSTANT_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "break"), BREAK_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "continue"), CONTINUE_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "as"), AS_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "u8"), U8_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "u16"), U16_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "u32"), U32_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "u64"), U64_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "i8"), I8_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "i16"), I16_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "i32"), I32_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "i64"), I64_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "f32"), F32_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "f64"), F64_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "var"), VAR_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "alias"), ALIAS_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "type"), TYPE_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "struct"), STRUCT_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "enum"), ENUM_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "union"), UNION_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "=>"), DOUBLE_ARROW_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "typeclass"), TYPECLASS_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "implements"), IMPLEMENTS_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "return"), RETURN_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "import"), IMPORT_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "sizeof"), SIZEOF_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "~>"), EFFECT_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "external"), EXTERNAL_TOKEN);
	TOKEN_map_insert(map, string_init(map->mem, "pack"), PACKED_TOKEN);
}

uint8_t
issymbol(char c){
	return (
		(c > ' ' && c < '\'') ||
		(c > ')' && c < '0') ||
		(c > ';' && c < 'A') ||
		(c == '`') ||
		(c == '^') ||
		(c == '~') ||
		(c == ':') ||
		(c == '|')
	);
}

void
lex_string(parser* const parse){
	pool_request(parse->token_mem, sizeof(token));
	token* t = &parse->tokens[parse->token_count];
	while (parse->text_index < parse->text.len){
		char c = parse->text.str[parse->text_index];
		t->index = parse->token_count;
		t->data.name.str = &parse->text.str[parse->text_index];
		t->data.name.len = 0;
		parse->text_index += 1;
		switch (c){
		case ' ':
		case '\r':
		case '\t':
		case '\n':
			continue;
		case COLON_TOKEN:
		case PIPE_TOKEN:
		case CARROT_TOKEN:
		case EQUAL_TOKEN:
		case AMPERSAND_TOKEN:
			if (issymbol(parse->text.str[parse->text_index])){
				break;
			}
		case AT_TOKEN:
		case PAREN_OPEN_TOKEN:
		case PAREN_CLOSE_TOKEN:
		case BRACK_OPEN_TOKEN:
		case BRACK_CLOSE_TOKEN:
		case BRACE_OPEN_TOKEN:
		case BRACE_CLOSE_TOKEN:
		case COMMA_TOKEN:
		case SEMI_TOKEN:
		case LAMBDA_TOKEN:
		case BACKTICK_TOKEN:
		case COMPOSE_TOKEN:
		case SHIFT_TOKEN:
		case HOLE_TOKEN:
			t->data.name.len += 1;
			t->tag = c;
			t->content_tag = STRING_TOKEN_TYPE;
			pool_request(parse->token_mem, sizeof(token));
			parse->token_count += 1;
			t = &parse->tokens[parse->token_count];
			continue;
		case '"':
			t->tag = STRING_TOKEN;
			t->content_tag = STRING_TOKEN_TYPE;
			t->data.name.len += 1;
			while (parse->text_index < parse->text.len){
				c = parse->text.str[parse->text_index];
				parse->text_index += 1;
				if (c == '"'){
					t->data.name.len += 1;
					break;
				}
				t->data.name.len += 1;
			}
			pool_request(parse->token_mem, sizeof(token));
			parse->token_count += 1;
			t = &parse->tokens[parse->token_count];
			continue;
		case '\'':
			t->tag = CHAR_TOKEN;
			t->content_tag = INT_TOKEN_TYPE;
			t->data.name.len += 2;
			c = parse->text.str[parse->text_index];
			parse->text_index += 1;
			if (c == '\\'){
				t->data.name.len += 1;
			c = parse->text.str[parse->text_index];
				parse->text_index += 1;
				switch (c){
				case 'a': c = '\a'; break;
				case 'b': c = '\b'; break;
				case 'e': c = '\033'; break;
				case 'f': c = '\f'; break;
				case 'r': c = '\r'; break;
				case 't': c = '\t'; break;
				case 'v': c = '\v'; break;
				case '\\': c = '\\'; break;
				case '\'': c = '\''; break;
				case '"': c = '"'; break;
				case '?': c = '\?'; break;
				case 'n': c = '\n'; break;
				}
			}
			t->data.pos = c;
			c = parse->text.str[parse->text_index];
			parse->text_index += 1;
			t->data.name.len += 1;
			assert_local(c == '\'', , "expected \' to close character literal");
			pool_request(parse->token_mem, sizeof(token));
			parse->token_count += 1;
			t = &parse->tokens[parse->token_count];
			continue;
		default:
			break;
		}
		if (c == '/'){
			char k = parse->text.str[parse->text_index];
			if (k == '/'){
				while (parse->text_index < parse->text.len){
					c = parse->text.str[parse->text_index];
					parse->text_index += 1;
					if (c == '\n'){
						break;
					}
				}
				continue;
			}
			else if (k == '*'){
				parse->text_index += 1;
				while (parse->text_index < parse->text.len){
					c = parse->text.str[parse->text_index];
					parse->text_index += 1;
					if (c == '*'){
						k = parse->text.str[parse->text_index];
						if (k == '/'){
							parse->text_index += 1;
							break;
						}
					}
				}
				continue;
			}
		}
		if (isalpha(c)){
			t->data.name.len += 1;
			t->tag = IDENTIFIER_TOKEN;
			t->content_tag = STRING_TOKEN_TYPE;
			c = parse->text.str[parse->text_index];
			parse->text_index += 1;
			while ((parse->text_index < parse->text.len) && (isalpha(c) || c == '_' || isdigit(c))){
				t->data.name.len += 1;
				c = parse->text.str[parse->text_index];
				parse->text_index += 1;
			}
			parse->text_index -= 1;
			TOKEN* tok = TOKEN_map_access(parse->keymap, t->data.name);
			if (tok != NULL){
				t->tag = *tok;
			}
			pool_request(parse->token_mem, sizeof(token));
			parse->token_count += 1;
			t = &parse->tokens[parse->token_count];
			continue;
		}
		else if (issymbol(c)){
			if (c == '-'){
				c = parse->text.str[parse->text_index];
				if (isdigit(c) == 0){
					t->data.name.len += 1;
					t->tag = SYMBOL_TOKEN;
					t->content_tag = STRING_TOKEN_TYPE;
					c = parse->text.str[parse->text_index];
					parse->text_index += 1;
					while ((parse->text_index < parse->text.len) && issymbol(c)){
						t->data.name.len += 1;
						c = parse->text.str[parse->text_index];
						parse->text_index += 1;
					}
					parse->text_index -= 1;
					TOKEN* tok = TOKEN_map_access(parse->keymap, t->data.name);
					if (tok != NULL){
						t->tag = *tok;
					}
					else{
						if (cstring_compare(&t->data.name, "+") == 0) t->data.name = string_init(parse->mem, "~add");
						else if (cstring_compare(&t->data.name, "-") == 0) t->data.name = string_init(parse->mem, "~sub");
						else if (cstring_compare(&t->data.name, "*") == 0) t->data.name = string_init(parse->mem, "~mul");
						else if (cstring_compare(&t->data.name, "/") == 0) t->data.name = string_init(parse->mem, "~div");
						else if (cstring_compare(&t->data.name, "%") == 0) t->data.name = string_init(parse->mem, "~mod");
						else if (cstring_compare(&t->data.name, "!") == 0) t->data.name = string_init(parse->mem, "~not");
						else if (cstring_compare(&t->data.name, "&&") == 0) t->data.name = string_init(parse->mem, "~and");
						else if (cstring_compare(&t->data.name, "^&") == 0) t->data.name = string_init(parse->mem, "~bitand");
						else if (cstring_compare(&t->data.name, "||") == 0) t->data.name = string_init(parse->mem, "~or");
						else if (cstring_compare(&t->data.name, "^|") == 0) t->data.name = string_init(parse->mem, "~bitor");
						else if (cstring_compare(&t->data.name, "^^") == 0) t->data.name = string_init(parse->mem, "~bitxor");
						else if (cstring_compare(&t->data.name, "<") == 0) t->data.name = string_init(parse->mem, "~lt");
						else if (cstring_compare(&t->data.name, ">") == 0) t->data.name = string_init(parse->mem, "~gt");
						else if (cstring_compare(&t->data.name, "<=") == 0) t->data.name = string_init(parse->mem, "~le");
						else if (cstring_compare(&t->data.name, ">=") == 0) t->data.name = string_init(parse->mem, "~ge");
						else if (cstring_compare(&t->data.name, "==") == 0) t->data.name = string_init(parse->mem, "~eq");
						else if (cstring_compare(&t->data.name, "!=") == 0) t->data.name = string_init(parse->mem, "~neq");
						else{
							string* mem_name = string_map_access(parse->symbol_to_name, t->data.name);
							if (mem_name != NULL){
								t->data.name = *mem_name;
							}
							else{
								string_map_insert(parse->symbol_to_name, t->data.name, parse->next_symbol_name);
								t->data.name = parse->next_symbol_name;
								generate_new_symbol_name(parse);
							}
						}
					}
					pool_request(parse->token_mem, sizeof(token));
					parse->token_count += 1;
					t = &parse->tokens[parse->token_count];
					continue;
				}
			}
			else{
				t->data.name.len += 1;
				t->tag = SYMBOL_TOKEN;
				t->content_tag = STRING_TOKEN_TYPE;
				c = parse->text.str[parse->text_index];
				parse->text_index += 1;
				while ((parse->text_index < parse->text.len) && issymbol(c)){
					t->data.name.len += 1;
					c = parse->text.str[parse->text_index];
					parse->text_index += 1;
				}
				parse->text_index -= 1;
				TOKEN* tok = TOKEN_map_access(parse->keymap, t->data.name);
				if (tok != NULL){
					t->tag = *tok;
				}
				else{
					if (cstring_compare(&t->data.name, "+") == 0) t->data.name = string_init(parse->mem, "~add");
					else if (cstring_compare(&t->data.name, "-") == 0) t->data.name = string_init(parse->mem, "~sub");
					else if (cstring_compare(&t->data.name, "*") == 0) t->data.name = string_init(parse->mem, "~mul");
					else if (cstring_compare(&t->data.name, "/") == 0) t->data.name = string_init(parse->mem, "~div");
					else if (cstring_compare(&t->data.name, "%") == 0) t->data.name = string_init(parse->mem, "~mod");
					else if (cstring_compare(&t->data.name, "!") == 0) t->data.name = string_init(parse->mem, "~not");
					else if (cstring_compare(&t->data.name, "&&") == 0) t->data.name = string_init(parse->mem, "~and");
					else if (cstring_compare(&t->data.name, "^&") == 0) t->data.name = string_init(parse->mem, "~bitand");
					else if (cstring_compare(&t->data.name, "||") == 0) t->data.name = string_init(parse->mem, "~or");
					else if (cstring_compare(&t->data.name, "^|") == 0) t->data.name = string_init(parse->mem, "~bitor");
					else if (cstring_compare(&t->data.name, "^^") == 0) t->data.name = string_init(parse->mem, "~bitxor");
					else if (cstring_compare(&t->data.name, "^~") == 0) t->data.name = string_init(parse->mem, "~bitcomp");
					else if (cstring_compare(&t->data.name, "<") == 0) t->data.name = string_init(parse->mem, "~lt");
					else if (cstring_compare(&t->data.name, ">") == 0) t->data.name = string_init(parse->mem, "~gt");
					else if (cstring_compare(&t->data.name, "<=") == 0) t->data.name = string_init(parse->mem, "~le");
					else if (cstring_compare(&t->data.name, ">=") == 0) t->data.name = string_init(parse->mem, "~ge");
					else if (cstring_compare(&t->data.name, "==") == 0) t->data.name = string_init(parse->mem, "~eq");
					else if (cstring_compare(&t->data.name, "!=") == 0) t->data.name = string_init(parse->mem, "~neq");
					else{
						string* mem_name = string_map_access(parse->symbol_to_name, t->data.name);
						if (mem_name != NULL){
							t->data.name = *mem_name;
						}
						else{
							string_map_insert(parse->symbol_to_name, t->data.name, parse->next_symbol_name);
							t->data.name = parse->next_symbol_name;
							generate_new_symbol_name(parse);
						}
					}
				}
				pool_request(parse->token_mem, sizeof(token));
				parse->token_count += 1;
				t = &parse->tokens[parse->token_count];
				continue;
			}
		}
		if (isdigit(c) || c == '-'){
			t->tag = INTEGER_TOKEN;
			t->content_tag = UINT_TOKEN_TYPE;
			t->data.pos = 0;
			uint8_t neg = 0;
			uint64_t start_float = parse->text_index-1;
			if (c == '-'){
				t->content_tag = INT_TOKEN_TYPE;
				neg = 1;
				c = parse->text.str[parse->text_index];
				parse->text_index += 1;
			}
			if (c == '0'){
				c = parse->text.str[parse->text_index];
				parse->text_index += 1;
				if (c == 'x'){
					while (parse->text_index < parse->text.len){
						uint64_t last = t->data.pos;
						t->data.pos <<= 4;
						if (c >= '0' && c <= '9'){
							t->data.pos += (c - 48);
						}
						else if (c >= 'A' && c <= 'F'){
							t->data.pos += (c - 55);
						}
						else if (c >= 'a' && c <= 'f'){
							t->data.pos += (c - 87);
						}
						else{
							t->data.pos = last;
							parse->text_index -= 1;
							break;
						}
						c = parse->text.str[parse->text_index];
						parse->text_index += 1;
					}
					if (neg == 1){
						uint64_t pos = t->data.pos;
						t->data.neg = -pos;
					}
					pool_request(parse->token_mem, sizeof(token));
					parse->token_count += 1;
					t = &parse->tokens[parse->token_count];
					continue;
				}
				else if (c == 'b'){
					while (parse->text_index < parse->text.len){
						if (c!='0'||c!='1'){
							parse->text_index -= 1;
							break;
						}
						t->data.pos <<= 1;
						t->data.pos += (c-48);
						c = parse->text.str[parse->text_index];
						parse->text_index += 1;
					}
					if (neg == 1){
						uint64_t pos = t->data.pos;
						t->data.neg = pos;
					}
					pool_request(parse->token_mem, sizeof(token));
					parse->token_count += 1;
					t = &parse->tokens[parse->token_count];
					continue;
				}
				else if (c == 'o'){
					while (parse->text_index < parse->text.len){
						if (c < '0' && c > '7'){
							parse->text_index -= 1;
							break;
						}
						t->data.pos <<= 3;
						t->data.pos += (c-48);
						c = parse->text.str[parse->text_index];
						parse->text_index += 1;
					}
					if (neg == 1){
						uint64_t pos = t->data.pos;
						t->data.neg = -pos;
					}
					pool_request(parse->token_mem, sizeof(token));
					parse->token_count += 1;
					t = &parse->tokens[parse->token_count];
					continue;
				}
			}
			uint8_t is_float = 0;
			uint64_t end_float = parse->text_index;
			while (parse->text_index < parse->text.len){
				if (c == '.'){
					is_float = 1;
					while (parse->text_index < parse->text.len){
						c = parse->text.str[parse->text_index];
						parse->text_index += 1;
						if (c == 'f'){
							end_float = parse->text_index;
							break;
						}
						if (c == 'e' || c == 'E'){
							c = parse->text.str[parse->text_index];
							parse->text_index += 1;
							if (c == '-'){
								c = parse->text.str[parse->text_index];
								parse->text_index += 1;
							}
							while (parse->text_index < parse->text.len){
								c = parse->text.str[parse->text_index];
								parse->text_index += 1;
								if (isdigit(c) == 0){
									parse->text_index -= 1;
									break;
								}
							}
							end_float = parse->text_index+1;
							break;
						}
						if (isdigit(c) == 0){
							end_float = parse->text_index;
							parse->text_index -= 1;
							break;
						}
					}
					break;
				}
				else if (c == 'f'){
					is_float = 1;
					end_float = parse->text_index;
					break;
				}
				else if (c == 'e' || c == 'E'){
					is_float = 1;
					c = parse->text.str[parse->text_index];
					parse->text_index += 1;
					if (c == '-'){
						c = parse->text.str[parse->text_index];
						parse->text_index += 1;
					}
					while (parse->text_index < parse->text.len){
						c = parse->text.str[parse->text_index];
						parse->text_index += 1;
						if (isdigit(c) == 0){
							parse->text_index -= 1;
							break;
						}
					}
					end_float = parse->text_index+1;
					break;
				}
				if (isdigit(c) == 0){
					parse->text_index -= 1;
					break;
				}
				t->data.pos *= 10;
				t->data.pos += (c-48);
				c = parse->text.str[parse->text_index];
				parse->text_index += 1;
			}
			if (is_float == 1){
				t->tag = FLOAT_TOKEN;
				t->content_tag = FLOAT_TOKEN_TYPE;
				char save = parse->text.str[end_float];
				parse->text.str[end_float] = '\0';
				t->data.flt = atof(&parse->text.str[start_float]);
				parse->text.str[end_float] = save;
				pool_request(parse->token_mem, sizeof(token));
				parse->token_count += 1;
				t = &parse->tokens[parse->token_count];
				continue;
			}
			if (neg == 1){
				uint64_t pos = t->data.pos;
				t->data.neg = -pos;
			}
			pool_request(parse->token_mem, sizeof(token));
			parse->token_count += 1;
			t = &parse->tokens[parse->token_count];
			continue;
		}
		assert_local(0, , "Unknown symbol");
		return;
	}
}

void generate_new_symbol_name(parser* const parse){
	string old = parse->next_symbol_name;
	uint64_t i = 1;
	for (;i<old.len;++i){ // 1 because 0 is #
		if (old.str[i] < 'Z'){
			break;
		}
	}
	if (i < old.len){
		old = string_copy(parse->mem, &parse->next_symbol_name);
		for (uint64_t k = 1;k<i;++k){
			old.str[k] = 'A';
		}
		old.str[i] += 1;
	}
	else{
		old.str = pool_request(parse->mem, old.len+1);
		old.len += 1;
		old.str[0] = '#';
		for (uint64_t k = 1;k<old.len;++k){
			old.str[k] = 'A';
		}
	}
	parse->next_symbol_name = old;
}

void
show_tokens(token* tokens, uint64_t token_count){
	for (uint64_t i = 0;i<token_count;++i){
		token t = tokens[i];
		switch (t.tag){
		case PAREN_OPEN_TOKEN:
			printf("PAREN_OPEN ( ");
			break;
		case PAREN_CLOSE_TOKEN:
			printf("PAREN_CLOSE ) ");
			break;
		case BRACK_OPEN_TOKEN:
			printf("BRACK_OPEN [ ");
			break;
		case BRACK_CLOSE_TOKEN:
			printf("BRACK_CLOSE ] ");
			break;
		case BRACE_OPEN_TOKEN:
			printf("BRACE_OPEN { ");
			break;
		case BRACE_CLOSE_TOKEN:
			printf("BRACE CLOSED } ");
			break;
		case AT_TOKEN:
			printf("AT @ ");
			break;
		case COMMA_TOKEN:
			printf("COMMA , ");
			break;
		case SEMI_TOKEN:
			printf("SEMI ; ");
			break;
		case COLON_TOKEN:
			printf("COLON : ");
			break;
		case PIPE_TOKEN:
			printf("PIPE | ");
			break;
		case LAMBDA_TOKEN:
			printf("LAMBDA \\ ");
			break;
		case EQUAL_TOKEN:
			printf("EQUAL = ");
			break;
		case BACKTICK_TOKEN:
			printf("BACKTICK ` ");
			break;
case COMPOSE_TOKEN:
			printf("COMPOSE . ");
			break;
		case SHIFT_TOKEN:
			printf("SHIFT $ ");
			break;
		case CARROT_TOKEN:
			printf("CARROT ^ ");
			break;
		case AMPERSAND_TOKEN:
			printf("AMPERSAND & ");
			break;
		case HOLE_TOKEN:
			printf("HOLE _ ");
			break;
		case IDENTIFIER_TOKEN:
			printf("IDENTIFIER ");
			string_print(&t.data.name);
			printf(" ");
			break;
		case SYMBOL_TOKEN:
			printf("SYMBOL ");
			string_print(&t.data.name);
			printf(" ");
			break;
		case STRING_TOKEN:
			printf("STRING ");
			string_print(&t.data.name);
			printf(" ");
			break;
		case CHAR_TOKEN:
			char c = t.data.neg;
			printf("CHAR %c ", c);
			break;
		case INTEGER_TOKEN:
			printf("INTEGER %lu (%ld) ", t.data.pos, t.data.neg);
			break;
		case FLOAT_TOKEN:
			printf("FLOAT %lf ", t.data.flt);
			break;
		case ARROW_TOKEN:
			printf("ARROW -> ");
			break;
		case IF_TOKEN:
			printf("IF ");
			break;
		case ELSE_TOKEN:
			printf("ELSE ");
			break;
		case MATCH_TOKEN:
			printf("MATCH ");
			break;
		case WHILE_TOKEN:
			printf("WHILE ");
			break;
		case FOR_TOKEN:
			printf("FOR ");
			break;
		case U8_TOKEN:
			printf("U8 ");
			break;
		case U16_TOKEN:
			printf("U16 ");
			break;
		case U32_TOKEN:
			printf("U32 ");
			break;
		case U64_TOKEN:
			printf("U64 ");
			break;
		case I8_TOKEN:
			printf("I8 ");
			break;
		case I16_TOKEN:
			printf("I16 ");
			break;
		case I32_TOKEN:
			printf("I32 ");
			break;
		case I64_TOKEN:
			printf("I64 ");
			break;
		case F32_TOKEN:
			printf("F32 ");
			break;
		case F64_TOKEN:
			printf("F64 ");
			break;
		case VAR_TOKEN:
			printf("VAR ");
			break;
		case ALIAS_TOKEN:
			printf("ALIAS ");
			break;
		case TYPE_TOKEN:
			printf("TYPE ");
			break;
		case STRUCT_TOKEN:
			printf("STRUCT ");
			break;
		case PACKED_TOKEN:
			printf("PACKED STRUCT");
			break;
		case ENUM_TOKEN:
			printf("ENUM ");
			break;
		case UNION_TOKEN:
			printf("UNION ");
			break;
		case DOUBLE_ARROW_TOKEN:
			printf("DOUBLE_ARROW => ");
			break;
		case TYPECLASS_TOKEN:
			printf("TYPECLASS ");
			break;
		case IMPLEMENTS_TOKEN:
			printf("IMPLEMENTS ");
			break;
		case RETURN_TOKEN:
			printf("RETURN ");
			break;
		case IMPORT_TOKEN:
			printf("IMPORT ");
			break;
		case SIZEOF_TOKEN:
			printf("SIZEOF ");
			break;
		case BREAK_TOKEN:
			printf("BREAK ");
			break;
		case CONTINUE_TOKEN:
			printf("CONTINUE ");
			break;
		case CONSTANT_TOKEN:
			printf("CONSTANT ");
			break;
		case AS_TOKEN:
			printf("AS ");
			break;
		case EFFECT_TOKEN:
			printf("EFFECT ~> ");
			break;
		default:
			printf("UNKNOWN_TOKEN_TYPE ??? ");
			break;
		}
	}
}

type_ast*
parse_type_dependency(parser* const parse){
	type_ast* outer = pool_request(parse->mem, sizeof(type_ast));
	outer->tag = DEPENDENCY_TYPE;
	uint64_t capacity = 2;
	outer->data.dependency.typeclass_dependencies = pool_request(parse->mem, sizeof(token)*capacity);
	outer->data.dependency.dependency_typenames = pool_request(parse->mem, sizeof(token)*capacity);
	outer->data.dependency.dependency_count = 0;
	while (parse->token_index < parse->token_count){
		token* t = &parse->tokens[parse->token_index];
		parse->token_index += 1;
		if (t->tag == PAREN_CLOSE_TOKEN){
			t = &parse->tokens[parse->token_index];
			assert_local(t->tag == DOUBLE_ARROW_TOKEN, NULL, "expected =>");
			parse->token_index += 1;
			break;
		}
		if (outer->data.dependency.dependency_count == capacity){
			capacity *= 2;
			token* tc_depend = pool_request(parse->mem, sizeof(token)*capacity);
			token* depend_names = pool_request(parse->mem, sizeof(token)*capacity);
			for (uint64_t i = 0;i<outer->data.dependency.dependency_count;++i){
				tc_depend[i] = outer->data.dependency.typeclass_dependencies[i];
				depend_names[i] = outer->data.dependency.dependency_typenames[i];
			}
			outer->data.dependency.typeclass_dependencies = tc_depend;
			outer->data.dependency.dependency_typenames = depend_names;
		}
		assert_local(t->tag == IDENTIFIER_TOKEN, NULL, "expected identifier");
		outer->data.dependency.typeclass_dependencies[outer->data.dependency.dependency_count] = *t;
		t = &parse->tokens[parse->token_index];
		assert_local(t->tag == IDENTIFIER_TOKEN, NULL, "expected identifier");
		parse->token_index += 1;
		outer->data.dependency.dependency_typenames[outer->data.dependency.dependency_count] = *t;
		outer->data.dependency.dependency_count += 1;
		t = &parse->tokens[parse->token_index];
		parse->token_index += 1;
		if (t->tag == COMMA_TOKEN){
			continue;
		}
		else if (t->tag == PAREN_CLOSE_TOKEN){
			t = &parse->tokens[parse->token_index];
			assert_local(t->tag == DOUBLE_ARROW_TOKEN, NULL, "expected =>");
			parse->token_index += 1;
			break;
		}
	}
	return outer;
}

type_ast*
parse_type(parser* const parse, uint8_t named, TOKEN end){
	token* t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	type_ast* outer;
	if (t->tag == PAREN_OPEN_TOKEN){
		uint64_t save = parse->token_index;
		outer = parse_type_dependency(parse);
		if (parse->err.len != 0){
			parse->token_index = save - 1;
			parse->err.len = 0;
		}
		else{
			outer->data.dependency.type = parse_type_worker(parse, named, end);
			return outer;
		}
	}
	else{
		parse->token_index -= 1;
	}
	type_ast* inner = parse_type_worker(parse, named, end);
	return inner;
}

type_ast*
parse_type_worker(parser* const parse, uint8_t named, TOKEN end){
	token* t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	type_ast* base = pool_request(parse->mem, sizeof(type_ast));
	base->variable = 0;
	uint8_t parametric = 0;
	switch (t->tag){
	case U8_TOKEN:
	case U16_TOKEN:
	case U32_TOKEN:
	case U64_TOKEN:
	case I8_TOKEN:
	case I16_TOKEN:
	case I32_TOKEN:
	case I64_TOKEN:
		base->tag = LIT_TYPE;
		base->data.lit = t->tag - U8_TOKEN;
		break;
	case F32_TOKEN:
		base->tag = LIT_TYPE;
		base->data.lit = F32_TYPE;
		break;
	case F64_TOKEN:
		base->tag = LIT_TYPE;
		base->data.lit = F64_TYPE;
		break;
	case PACKED_TOKEN:
	case STRUCT_TOKEN:
	case UNION_TOKEN:
	case ENUM_TOKEN:
		base->tag = STRUCT_TYPE;
		parse->token_index -= 1;
	   	base->data.structure = parse_struct_type(parse);
		break;
	case IDENTIFIER_TOKEN:
		base->tag = NAMED_TYPE;
		base->data.named.name = *t;
		base->data.named.args = NULL;
		base->data.named.arg_count = 0;
		parametric = 1;
		break;
	case BRACK_OPEN_TOKEN:
		base->tag = FAT_PTR_TYPE;
		base->data.fat_ptr.ptr = parse_type_worker(parse, 0, BRACK_CLOSE_TOKEN);
		assert_prop(NULL);
		base->data.fat_ptr.len = 0;
		parse->token_index += 1;
		break;
	case PAREN_OPEN_TOKEN:
		type_ast* temp = parse_type_worker(parse, 0, PAREN_CLOSE_TOKEN);
		assert_prop(NULL);
		*base = *temp;
		parse->token_index += 1;
		break;
	default:
		assert_local(0, NULL, "unexpected token");
	}
	if (parametric == 1){
		uint8_t exit = 0;
		uint64_t capacity = 2;
		base->data.named.args = pool_request(parse->mem, capacity*sizeof(type_ast));
		while (parse->token_index < parse->token_count){
			if (base->data.named.arg_count == capacity){
				capacity *= 2;
				type_ast* new_buffer = pool_request(parse->mem, capacity*sizeof(type_ast));
				for (uint64_t i = 0;i<base->data.named.arg_count;++i){
					new_buffer[i] = base->data.named.args[i];
				}
				base->data.named.args = new_buffer;
			}
			type_ast* arg = &base->data.named.args[base->data.named.arg_count];
			t = &parse->tokens[parse->token_index];
			parse->token_index += 1;
			switch (t->tag){
			case U8_TOKEN:
			case U16_TOKEN:
			case U32_TOKEN:
			case U64_TOKEN:
			case I8_TOKEN:
			case I16_TOKEN:
			case I32_TOKEN:
			case I64_TOKEN:
				arg->tag = LIT_TYPE;
				arg->data.lit = t->tag-U8_TOKEN;
				base->data.named.arg_count += 1;
				break;
			case F32_TOKEN:
				arg->tag = LIT_TYPE;
				arg->data.lit = F32_TYPE;
				base->data.named.arg_count += 1;
				break;
			case F64_TOKEN:
				arg->tag = LIT_TYPE;
				arg->data.lit = F64_TYPE;
				base->data.named.arg_count += 1;
				break;
			case PACKED_TOKEN:
			case STRUCT_TOKEN:
			case UNION_TOKEN:
			case ENUM_TOKEN:
				arg->tag = STRUCT_TYPE;
				arg->data.structure = parse_struct_type(parse);
				parse->token_index -= 1;
				base->data.named.arg_count += 1;
				break;
			case PAREN_OPEN_TOKEN:
				type_ast* interm_arg = parse_type_worker(parse, 0, PAREN_CLOSE_TOKEN);
				assert_prop(NULL);
				*arg = *interm_arg;
				base->data.named.arg_count += 1;
				break;
			case BRACK_OPEN_TOKEN:
				*arg = *parse_type_worker(parse, 0, BRACK_CLOSE_TOKEN);
				assert_prop(NULL);
				base->data.named.arg_count += 1;
				break;
			case IDENTIFIER_TOKEN:
				arg->tag = NAMED_TYPE;
				arg->data.named.name = *t;
				arg->data.named.args = NULL;
				arg->data.named.arg_count = 0;
				base->data.named.arg_count += 1;
				break;
			case SYMBOL_TOKEN:
				assert_local(named == 1, NULL, "Unexpected symbol in unnamed type");
				parse->token_index -= 1;
				return base;
			default :
				parse->token_index -= 1;
				exit = 1;
				break;
			}
			if (exit == 1){
				break;
			}
		}
		if (t->tag == end){
			if (named == 1){
				parse->token_index -= 1;
				assert_local(base->tag == NAMED_TYPE, NULL, "expected base to be named");
				assert_local(base->data.named.arg_count > 0, NULL, "expected arguments in base type");
				base->data.named.arg_count -= 1;
				return base;
			}
		}
	}
	uint8_t exit = 0;
	while (parse->token_index < parse->token_count){
		t = &parse->tokens[parse->token_index];
		parse->token_index += 1;
		type_ast* outer;
		switch (t->tag){
		case VAR_TOKEN:
			base->variable = 1;
			break;
		case CARROT_TOKEN:
			outer = pool_request(parse->mem, sizeof(type_ast));
			outer->tag = PTR_TYPE;
			outer->data.ptr = base;
			base = outer;
			break;
		case ARROW_TOKEN:
			outer = pool_request(parse->mem, sizeof(type_ast));
			outer->tag = FUNCTION_TYPE;
			outer->data.function.left = base;
			outer->data.function.right = parse_type_worker(parse, named, end);
			assert_prop(NULL);
			base = outer;
			break;
		case EFFECT_TOKEN:
			outer = pool_request(parse->mem, sizeof(type_ast));
			outer->tag = FUNCTION_TYPE;
			outer->data.function.left = base;
			outer->data.function.right = mk_ptr(parse->mem, parse_type_worker(parse, named, end));
			assert_prop(NULL);
			base = outer;
			break;
		default:
			exit = 1;
			parse->token_index -= 1;
			break;
		}
		if (exit == 1){
			break;
		}
	}
	if (named == 1){
		if (t->tag == IDENTIFIER_TOKEN || t->tag == SYMBOL_TOKEN){
			assert_local(parse->tokens[parse->token_index+1].tag == end, NULL, "expected end of type");
			return base;
		}
	}
	assert_local(t->tag == end, NULL, "expected end of expression");
	return base;
}

structure_ast*
parse_struct_type(parser* const parse){
	structure_ast* structure = pool_request(parse->mem, sizeof(structure_ast));
	token* t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	uint64_t capacity = 2;
	switch (t->tag){
	case PACKED_TOKEN:
		structure->data.structure.packed = 1;
	case STRUCT_TOKEN:
		structure->tag = STRUCT_STRUCT;
		t = &parse->tokens[parse->token_index];
		parse->token_index += 1;
		assert_local(t->tag == BRACE_OPEN_TOKEN, NULL, "expected { to open structure");
		capacity = 2;
		structure->data.structure.names = pool_request(parse->mem, sizeof(token)*capacity);
		structure->data.structure.members = pool_request(parse->mem, sizeof(type_ast)*capacity);
		structure->data.structure.count = 0;
		while (parse->token_index < parse->token_count){
			type_ast* type = parse_type(parse, 1, SEMI_TOKEN);
			assert_prop(NULL);
			t = &parse->tokens[parse->token_index];
			parse->token_index += 1;
			assert_local(t->tag == IDENTIFIER_TOKEN || t->tag == SYMBOL_TOKEN, NULL, "Expected identifier or symbol for structure member name");
			token name = *t;
			t = &parse->tokens[parse->token_index];
			parse->token_index += 1;
			assert_local(t->tag == SEMI_TOKEN, NULL, "expected ; between members of structure type");
			if (structure->data.structure.count == capacity){
				capacity *= 2;
				token* names = pool_request(parse->mem, sizeof(token)*capacity);
				type_ast* members = pool_request(parse->mem, sizeof(type_ast)*capacity);
				for (uint64_t i = 0;i<structure->data.structure.count;++i){
					names[i] = structure->data.structure.names[i];
					members[i] = structure->data.structure.members[i];
				}
				structure->data.structure.names = names;
				structure->data.structure.members = members;
			}
			structure->data.structure.names[structure->data.structure.count] = name;
			structure->data.structure.members[structure->data.structure.count] = *type;
			structure->data.structure.count += 1;
			t = &parse->tokens[parse->token_index];
			parse->token_index += 1;
			if (t->tag == BRACE_CLOSE_TOKEN){
				break;
			}
			parse->token_index -= 1;
		}
		break;
	case UNION_TOKEN:
		structure->tag = UNION_STRUCT;
		t = &parse->tokens[parse->token_index];
		parse->token_index += 1;
		assert_local(t->tag == BRACE_OPEN_TOKEN, NULL, "expected { to open union type");
		capacity = 2;
		structure->data.union_structure.names = pool_request(parse->mem, sizeof(token)*capacity);
		structure->data.union_structure.members = pool_request(parse->mem, sizeof(structure_ast)*capacity);
		structure->data.union_structure.count = 0;
		while (parse->token_index < parse->token_count){
			type_ast* type = parse_type(parse, 1, SEMI_TOKEN);
			assert_prop(NULL);
			t = &parse->tokens[parse->token_index];
			parse->token_index += 1;
			assert_local(t->tag == IDENTIFIER_TOKEN || t->tag == SYMBOL_TOKEN, NULL, "expected identifier or symbol for union member name");
			token name = *t;
			t = &parse->tokens[parse->token_index];
			parse->token_index += 1;
			assert_local(t->tag == SEMI_TOKEN, NULL, "expected ; between union members");
			if (structure->data.union_structure.count == capacity){
				capacity *= 2;
				token* names = pool_request(parse->mem, sizeof(token)*capacity);
				type_ast* members = pool_request(parse->mem, sizeof(type_ast)*capacity);
				for (uint64_t i = 0;i<structure->data.union_structure.count;++i){
					names[i] = structure->data.union_structure.names[i];
					members[i] = structure->data.union_structure.members[i];
				}
				structure->data.union_structure.names = names;
				structure->data.union_structure.members = members;
			}
			structure->data.union_structure.names[structure->data.union_structure.count] = name;
			structure->data.union_structure.members[structure->data.union_structure.count] = *type;
			structure->data.structure.count += 1;
			t = &parse->tokens[parse->token_index];
			parse->token_index += 1;
			if (t->tag == BRACE_CLOSE_TOKEN){
				break;
			}
			parse->token_index -= 1;
		}
		break;
	case ENUM_TOKEN:
		structure->tag = ENUM_STRUCT;
		t = &parse->tokens[parse->token_index];
		parse->token_index += 1;
		assert_local(t->tag == BRACE_OPEN_TOKEN, NULL, "expected { to open enumeration type");
		capacity = 2;
		structure->data.enumeration.names = pool_request(parse->mem, sizeof(token)*capacity);
		structure->data.enumeration.values = pool_request(parse->mem, sizeof(uint64_t)*capacity);
		structure->data.enumeration.count = 0;
		uint64_t current_value = 0;
		while (parse->token_index < parse->token_count){
			t = &parse->tokens[parse->token_index];
			parse->token_index += 1;
			assert_local(t->tag == IDENTIFIER_TOKEN, NULL, "expected identifier as enumerator member");
			if (structure->data.enumeration.count == capacity){
				capacity *= 2;
				token* names = pool_request(parse->mem, sizeof(token)*capacity);
				uint64_t* values = pool_request(parse->mem, sizeof(uint64_t)*capacity);
				for (uint64_t i = 0;i<structure->data.enumeration.count;++i){
					names[i] = structure->data.enumeration.names[i];
					values[i] = structure->data.enumeration.values[i];
				}
				structure->data.enumeration.names = names;
				structure->data.enumeration.values = values;
			}
			structure->data.enumeration.names[structure->data.enumeration.count] = *t;
			string* name_copy = &t->data.name;
			t = &parse->tokens[parse->token_index];
			parse->token_index += 1;
			if (t->tag == EQUAL_TOKEN){
				t = &parse->tokens[parse->token_index];
				parse->token_index += 1;
				assert_local(t->tag == INTEGER_TOKEN, NULL, "expected integer for enumeration value");
				if (t->content_tag == UINT_TOKEN_TYPE){
					structure->data.enumeration.values[structure->data.enumeration.count] = t->data.pos;
					current_value = t->data.pos;
				}
				else if (t->content_tag == INT_TOKEN_TYPE){
					structure->data.enumeration.values[structure->data.enumeration.count] = t->data.neg;
					current_value = t->data.neg;
				}
				t = &parse->tokens[parse->token_index];
				parse->token_index += 1;
			}
			else {
				structure->data.enumeration.values[structure->data.enumeration.count] = current_value;
			}
			structure->data.enumeration.count += 1;
			uint8_t dup = uint64_t_map_insert(parse->enumerated_values, *name_copy, current_value);
			assert_local(dup==0, NULL, "Duplicate enumerated value");
			current_value += 1;
			if (t->tag == BRACE_CLOSE_TOKEN){
				break;
			}
			assert_local(t->tag == COMMA_TOKEN, NULL, "expected , between enumeration members");
		}
		break;
	default:
		assert_local(0, NULL, "unexpected token for structure type header");
	}
	return structure;
}

void
show_type(type_ast* const type){
	switch (type->tag){
	case DEPENDENCY_TYPE:
		printf("(");
		for (uint64_t i = 0;i<type->data.dependency.dependency_count;++i){
			if (i != 0){
				printf(", ");
			}
			string_print(&type->data.dependency.typeclass_dependencies[i].data.name);
			printf(" ");
			string_print(&type->data.dependency.dependency_typenames[i].data.name);
		}
		printf(") => ");
		show_type(type->data.dependency.type);
		break;
	case FUNCTION_TYPE:
		printf("(");
		show_type(type->data.function.left);
		printf(" -> ");
		show_type(type->data.function.right);
		printf(")");
		break;
	case LIT_TYPE:
		if (type->data.lit == U8_TYPE) printf("u8");
		else if (type->data.lit == U16_TYPE) printf("u16");
		else if (type->data.lit == U32_TYPE) printf("u32");
		else if (type->data.lit == U64_TYPE) printf("u64");
		else if (type->data.lit == I8_TYPE) printf("i8");
		else if (type->data.lit == I16_TYPE) printf("i16");
		else if (type->data.lit == I32_TYPE) printf("i32");
		else if (type->data.lit == I64_TYPE) printf("i64");
		else if (type->data.lit == F32_TYPE) printf("f32");
		else if (type->data.lit == F64_TYPE) printf("f64");
		else if (type->data.lit == INT_ANY) printf("int");
		break;
	case PTR_TYPE:
		show_type(type->data.ptr);
		printf("*");
		break;
	case FAT_PTR_TYPE:
		printf("[");
		show_type(type->data.fat_ptr.ptr);
		printf("]");
		break;
	case STRUCT_TYPE:
		show_structure(type->data.structure);
		break;
	case NAMED_TYPE:
		string_print(&type->data.named.name.data.name);
		for (uint64_t i = 0;i<type->data.named.arg_count;++i){
			printf(" ");
			show_type(&type->data.named.args[i]);
		}
		break;
	}
	if (type->variable == 1){
		printf(" var");
	}
}

void
show_structure(structure_ast* const s){
	switch (s->tag){
	case STRUCT_STRUCT:
		printf("struct {");
		for (uint64_t i = 0;i<s->data.structure.count;++i){
			if (i != 0){
				printf(" ");
			}
			show_type(&s->data.structure.members[i]);
			printf(" ");
			string_print(&s->data.structure.names[i].data.name);
			printf(";");
		}
		printf("}");
		break;
case UNION_STRUCT:
		printf("union {");
		for (uint64_t i = 0;i<s->data.structure.count;++i){
			if (i != 0){
				printf(" ");
			}
			show_type(&s->data.structure.members[i]);
			printf(" ");
			string_print(&s->data.structure.names[i].data.name);
			printf(";");
		}
		printf("}");
		break;
	case ENUM_STRUCT:
		printf("enum {");
		for (uint64_t i = 0;i<s->data.enumeration.count;++i){
			if (i != 0){
				printf(", ");
			}
			string_print(&s->data.enumeration.names[i].data.name);
			printf("=%lu", s->data.enumeration.values[i]);
		}
		printf("}");
	}
}

void
parse_external_symbols(parser* const parse){
	parse->token_index += 1;
	token* t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert_local(t->tag == BRACE_OPEN_TOKEN, , "Expected block of external definitions");
	while (parse->token_index < parse->token_count){
		t = &parse->tokens[parse->token_index];
		switch (t->tag){
		case TYPE_TOKEN:
			typedef_ast* type = parse_typedef(parse);
			if (parse->err.len == 0){
				assert_local(type->param_count == 0, , "External symbol types cannot be parametric");
				parse->token_index += 1;
				typedef_ast_buffer_insert(&parse->extern_type_list, *type);
				uint8_t dup = typedef_ptr_map_insert(parse->extern_types, type->name.data.name, typedef_ast_buffer_top(&parse->extern_type_list));
				assert_local(dup==0, , "Duplicate external type definition");
#ifdef DEBUG
				printf("extern ");
				show_typedef(type);
				printf("\n");
#endif
				t = &parse->tokens[parse->token_index];
				if (t->tag == BRACE_CLOSE_TOKEN){
					parse->token_index += 1;
					return;
				}
				continue;
			}
			break;
		default:
			type_ast* term_type = parse_type(parse, 1, SEMI_TOKEN);
			if (parse->err.len == 0){
				t = &parse->tokens[parse->token_index];
				parse->token_index += 2;
				term_ast term = {
					.type = term_type,
					.name = *t,
					.expression = NULL
				};
				term_ast_buffer_insert(&parse->extern_term_list, term);
				uint8_t dup = term_ptr_map_insert(parse->extern_terms, term.name.data.name, term_ast_buffer_top(&parse->extern_term_list));
				assert_local(dup == 0, , "Duplicate external term definition");
#ifdef DEBUG
				printf("extern ");
				show_term(&term);
				printf("\n");
#endif
				t = &parse->tokens[parse->token_index];
				if (t->tag == BRACE_CLOSE_TOKEN){
					parse->token_index += 1;
					return;
				}
				continue;
			}
			break;
		}
		assert_prop();
	}
}

void
parse_program(parser* const parse){
	while (parse->token_index < parse->token_count){
		token* t = &parse->tokens[parse->token_index];
		switch (t->tag){
		case IMPORT_TOKEN:
			parse_import(parse);
			if (parse->err.len == 0){
				continue;
			}
			break;
		case EXTERNAL_TOKEN:
			parse_external_symbols(parse);
			if (parse->err.len == 0){
				continue;
			}
			break;
		case CONSTANT_TOKEN:
			const_ast* constant = parse_constant(parse);
			if (parse->err.len == 0){
				const_ast_buffer_insert(&parse->const_list, *constant);
				uint8_t dup = const_ptr_map_insert(parse->constants, constant->name.data.name, const_ast_buffer_top(&parse->const_list));
				assert_local(dup == 0, , "Duplicate constant definition");
#ifdef DEBUG
				show_constant(constant);
				printf("\n");
#endif
				continue;
			}
			break;
		case ALIAS_TOKEN:
			alias_ast* alias = parse_alias(parse);
			if (parse->err.len == 0){
				parse->token_index += 1;
				alias_ast_buffer_insert(&parse->alias_list, *alias);
				uint8_t dup = alias_ptr_map_insert(parse->aliases, alias->name.data.name, alias_ast_buffer_top(&parse->alias_list));
				assert_local(dup==0, , "Duplicate alias definition");
#ifdef DEBUG
				show_alias(alias);
				printf("\n");
#endif
				continue;
			}
			break;
		case TYPE_TOKEN:
			typedef_ast* type = parse_typedef(parse);
			if (parse->err.len == 0){
				parse->token_index += 1;
				typedef_ast_buffer_insert(&parse->type_list, *type);
				uint8_t dup = typedef_ptr_map_insert(parse->types, type->name.data.name, typedef_ast_buffer_top(&parse->type_list));
				assert_local(dup==0, , "Duplicate type definition");
#ifdef DEBUG
				show_typedef(type);
				printf("\n");
#endif
				continue;
			}
			break;
		case TYPECLASS_TOKEN:
			typeclass_ast* class = parse_typeclass(parse);
			if (parse->err.len == 0){
				parse->token_index += 1;
				typeclass_ast_buffer_insert(&parse->typeclass_list, *class);
				uint8_t dup = typeclass_ptr_map_insert(parse->typeclasses, class->name.data.name, typeclass_ast_buffer_top(&parse->typeclass_list));
				assert_local(dup==0, , "Duplicate typeclass definition");
#ifdef DEBUG
				show_typeclass(class);
				printf("\n");
#endif
				continue;
			}
			break;
		default:
			token* next = &parse->tokens[parse->token_index+1];
			if (next->tag == IMPLEMENTS_TOKEN){
				implementation_ast* impl = parse_implementation(parse);
				if (parse->err.len == 0){
					implementation_ptr_map* map = implementation_ptr_map_map_access(parse->implementations, impl->type.data.name);
					if (map == NULL){
						implementation_ast_buffer_insert(&parse->implementation_list, *impl);
						implementation_ptr_map init = implementation_ptr_map_init(parse->mem);
						implementation_ptr_map_insert(&init, impl->typeclass.data.name, implementation_ast_buffer_top(&parse->implementation_list));
						uint8_t dup = implementation_ptr_map_map_insert(parse->implementations, impl->type.data.name, init);
						assert_local(dup == 0, , "Duplicate implementation definition");
#ifdef DEBUG
						show_implementation(impl);
						printf("\n");
#endif
						continue;
					}
					implementation_ast_buffer_insert(&parse->implementation_list, *impl);
					uint8_t dup = implementation_ptr_map_insert(map, impl->typeclass.data.name, implementation_ast_buffer_top(&parse->implementation_list));
					assert_local(dup==0, , "Duplicate implementation definition");
#ifdef DEBUG
					show_implementation(impl);
					printf("\n");
#endif
					continue;
				}		
			}
			else{
				term_ast* term = parse_term(parse);
				if (parse->err.len == 0){
					term_ast_buffer_insert(&parse->term_list, *term);
					uint8_t dup = term_ptr_map_insert(parse->terms, term->name.data.name, term_ast_buffer_top(&parse->term_list));
					assert_local(dup==0, , "Duplicate term definition");
#ifdef DEBUG
					show_term(term);
					printf("\n");
#endif
					continue;
				}	
			}
			break;
		}
		assert_prop();
	}
}

const_ast*
parse_constant(parser* const parse){
	const_ast* c = pool_request(parse->mem, sizeof(const_ast));
	token* t = &parse->tokens[parse->token_index];
	assert_local(t->tag == CONSTANT_TOKEN, NULL, "Expected constant to head constnat expression");
	parse->token_index += 1;
	t = &parse->tokens[parse->token_index];
	assert_local(t->tag == IDENTIFIER_TOKEN, NULL, "Expected identifier for constant name");
	c->name = *t;
	parse->token_index += 1;
	t = &parse->tokens[parse->token_index];
	assert_local(t->tag == EQUAL_TOKEN, NULL, "Expected = before constant definition");
	parse->token_index += 1;
	c->value = parse_expr(parse, SEMI_TOKEN);
	assert_prop(NULL);
	return c;
}

void
show_constant(const_ast* constant){
	printf("constant ");
	string_print(&constant->name.data.name);
	printf(" = ");
	show_expression(constant->value);
}

alias_ast*
parse_alias(parser* const parse){
	token* t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert_local(t->tag == ALIAS_TOKEN, NULL, "expected alias token to start alias definition");
	t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert_local(t->tag == IDENTIFIER_TOKEN, NULL, "expected identifier for alias defintion name");
	alias_ast* alias = pool_request(parse->mem, sizeof(alias_ast));
	alias->name = *t;
	t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert_local(t->tag == EQUAL_TOKEN, NULL, "expected = to assign alias definition");
	alias->type = parse_type(parse, 0, SEMI_TOKEN);
	return alias;
}

typedef_ast*
parse_typedef(parser* const parse){
	token* t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert_local(t->tag == TYPE_TOKEN, NULL, "expected type token to start type definition");
	t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert_local(t->tag == IDENTIFIER_TOKEN, NULL, "expected identifier for type definition name");
	typedef_ast* type = pool_request(parse->mem, sizeof(typedef_ast));
	type->name = *t;
	type->param_count = 0;
	uint64_t save = parse->token_index;
	while (parse->token_index < parse->token_count){
		t = &parse->tokens[parse->token_index];
		parse->token_index += 1;
		if (t->tag == EQUAL_TOKEN){
			break;
		}
		type->param_count += 1;
	}
	parse->token_index = save;
	type->params = pool_request(parse->mem, sizeof(token)*type->param_count);
	for (uint64_t i = 0;i<type->param_count;++i){
		t = &parse->tokens[parse->token_index];
		parse->token_index += 1;
		assert_local(t->tag == IDENTIFIER_TOKEN, NULL, "expected identifier for parameter name");
		type->params[i] = *t;
	}
	t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert_local(t->tag == EQUAL_TOKEN, NULL, "expected = to assign type definition");
	type->type = parse_type(parse, 0, SEMI_TOKEN);
	return type;
}

void
show_alias(alias_ast* const alias){
	printf("alias ");
	string_print(&alias->name.data.name);
	printf(" = ");
	show_type(alias->type);
}

void
show_typedef(typedef_ast* const type){
	printf("type ");
	string_print(&type->name.data.name);
	for (uint64_t i = 0;i<type->param_count;++i){
		printf(" ");
		string_print(&type->params[i].data.name);
	}
	printf(" = ");
	show_type(type->type);
}

typeclass_ast*
parse_typeclass(parser* const parse){
	token* t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert_local(t->tag == TYPECLASS_TOKEN, NULL, "expected typeclass token to begin typeclass definition");
	t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert_local(t->tag == IDENTIFIER_TOKEN, NULL, "expected identifier for typeclass name");
	typeclass_ast* class = pool_request(parse->mem, sizeof(typeclass_ast));
	class->name = *t;
	t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert_local(t->tag == IDENTIFIER_TOKEN, NULL, "expected identifier for typeclass parameter name");
	class->param = *t;
	t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert_local(t->tag == BRACE_OPEN_TOKEN, NULL, "expected { to begin typeclass definition");
	uint64_t capacity = 2;
	class->member_count = 0;
	class->members = pool_request(parse->mem, sizeof(term_ast)*capacity);
	while (parse->token_index < parse->token_count){
		type_ast* type = parse_type(parse, 1, SEMI_TOKEN);
		assert_prop(NULL);
		t = &parse->tokens[parse->token_index];
		parse->token_index += 2;
		term_ast term = {
			.type = type,
			.name = *t,
			.expression = NULL
		};
		if (class->member_count == capacity){
			capacity *= 2;
			term_ast* members = pool_request(parse->mem, sizeof(term_ast)*capacity);
			for (uint64_t i = 0;i<class->member_count;++i){
				members[i] = class->members[i];
			}
			class->members = members;
		}
		class->members[class->member_count] = term;
		class->member_count += 1;
		t = &parse->tokens[parse->token_index];
		if (t->tag == BRACE_CLOSE_TOKEN){
			break;
		}
	}
	return class;
}

implementation_ast*
parse_implementation(parser* const parse){
	token* t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert_local(t->tag == IDENTIFIER_TOKEN, NULL, "expected identifier for implementation type name");
	implementation_ast* impl = pool_request(parse->mem, sizeof(implementation_ast));
	impl->type = *t;
	t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert_local(t->tag == IMPLEMENTS_TOKEN, NULL, "expected implements token after type name")
	t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert_local(t->tag == IDENTIFIER_TOKEN, NULL, "expected identifier for typelcass implementation typeclass name");
	impl->typeclass = *t;
	t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert_local(t->tag == BRACE_OPEN_TOKEN, NULL, "expected { to begin typeclass implementation");
	uint64_t capacity = 2;
	impl->member_count = 0;
	impl->members = pool_request(parse->mem, sizeof(term_ast)*capacity);
	while (parse->token_index < parse->token_count){
		if (impl->member_count == capacity){
			capacity *= 2;
			term_ast* members = pool_request(parse->mem, sizeof(term_ast)*capacity);
			for (uint64_t i = 0;i<impl->member_count;++i){
				members[i] = impl->members[i];
			}
			impl->members = members;
		}
		term_ast* member = parse_term(parse);
		assert_prop(NULL);
		impl->members[impl->member_count] = *member;
		impl->member_count += 1;
		t = &parse->tokens[parse->token_index];
		if (t->tag == BRACE_CLOSE_TOKEN){
			parse->token_index += 1;
			break;
		}
	}
	return impl;
}

void
show_typeclass(typeclass_ast* const class){
	printf("typeclass ");
	string_print(&class->name.data.name);
	printf(" ");
	string_print(&class->param.data.name);
	printf(" {");
	for (uint64_t i = 0;i<class->member_count;++i){
		show_type(class->members[i].type);
		printf(" ");
		string_print(&class->members[i].name.data.name);
		printf("; ");
	}
	printf("}");
}

void
show_implementation(implementation_ast* const impl){
	string_print(&impl->type.data.name);
	printf(" implements ");
	string_print(&impl->typeclass.data.name);
	printf("{ ");
	for (uint64_t i = 0;i<impl->member_count;++i){
		show_term(&impl->members[i]);
	}
	printf(" }");
}

void
show_term(term_ast* term){
	show_type(term->type);
	printf(" ");
	string_print(&term->name.data.name);
	if (term->expression != NULL){
		printf(" = ");
		show_expression(term->expression);
		return;
	}
	printf("; ");
}

void
show_expression(expr_ast* expr){
	if (expr->type != 0){
		printf("\033[2m[");
		show_type(expr->type);
		printf("]\033[0m");
	}
	switch(expr->tag){
	case APPL_EXPR:
		printf("(");
		show_expression(expr->data.appl.left);
		printf(" ");
		show_expression(expr->data.appl.right);
		printf(")");
		break;
	case STRUCT_ACCESS_EXPR:
		printf("(");
		show_expression(expr->data.access.left);
		printf(".");
		show_expression(expr->data.access.right);
		printf(")");
		break;
	case FAT_PTR_EXPR:
		printf("[");
		show_expression(expr->data.fat_ptr.left);
		printf(", ");
		show_expression(expr->data.fat_ptr.right);
		printf("]");
		break;
	case ARRAY_ACCESS_EXPR:
		printf("(");
		show_expression(expr->data.access.left);
		printf(" ");
		show_expression(expr->data.access.right);
		printf(")");
		break;
	case LAMBDA_EXPR:
		printf("\\");
		for (uint64_t i = 0;i<expr->data.lambda.arg_count;++i){
			show_pattern(&expr->data.lambda.args[i]);
			printf(" ");
		}
		printf(": ");
		show_expression(expr->data.lambda.expression);
		if (expr->data.lambda.alt != NULL){
			printf("| ");
			show_expression(expr->data.lambda.alt);
		}
		break;
	case BLOCK_EXPR:
		printf("{\n");
		for (uint64_t i = 0;i<expr->data.block.line_count;++i){
			show_expression(&expr->data.block.lines[i]);
			printf("\n");
		}
		printf("}\n");
		break;
	case LIT_EXPR:
		show_literal(&expr->data.literal);
		break;
	case TERM_EXPR:
		show_term(expr->data.term);
		break;
	case STRING_EXPR:
		string_print(&expr->data.str.data.name);
		break;
	case LIST_EXPR:
		printf("[");
		for (uint64_t i = 0;i<expr->data.block.line_count;++i){
			if (i != 0){
				printf(", ");
			}
			show_expression(&expr->data.block.lines[i]);
		}
		printf("]");
		break;
	case STRUCT_EXPR:
		printf("{");
		printf("%lu::", expr->data.constructor.member_count);
		for (uint64_t i = 0;i<expr->data.constructor.member_count;++i){
			if (i != 0){
				printf(", ");
			}
			string_print(&expr->data.constructor.names[i].data.name);
			printf("=");
			show_expression(&expr->data.constructor.members[i]);
		}
		printf("}");
		break;
	case BINDING_EXPR:
		string_print(&expr->data.binding.data.name);
		break;
	case MUTATION_EXPR:
		show_expression(expr->data.mutation.left);
		printf(" = ");
		show_expression(expr->data.mutation.right);
		break;
	case RETURN_EXPR:
		printf("return ");
		show_expression(expr->data.ret);
		break;
	case SIZEOF_EXPR:
		printf("sizeof ");
		show_type(expr->data.size_type);
		break;
	case REF_EXPR:
		printf("&");
		show_expression(expr->data.ref);
		break;
	case DEREF_EXPR:
		printf("^");
		show_expression(expr->data.deref);
		break;
	case IF_EXPR:
		printf("if ");
		show_expression(expr->data.if_statement.pred);
		printf("{ ");
		show_expression(expr->data.if_statement.cons);
		printf("} ");
		if (expr->data.if_statement.alt != NULL){
			printf("else {");
			show_expression(expr->data.if_statement.alt);
			printf("} ");
		}
		break;
	case FOR_EXPR:
		printf("for ");
		string_print(&expr->data.for_statement.binding.data.name);
		printf(" ");
		show_expression(expr->data.for_statement.initial);
		printf(" ");
		show_expression(expr->data.for_statement.limit);
		printf(" ");
		show_expression(expr->data.for_statement.cons);
		break;
	case WHILE_EXPR:
		printf("while ");
		show_expression(expr->data.while_statement.pred);
		show_expression(expr->data.while_statement.cons);
		break;
	case MATCH_EXPR:
		printf("match ");
		show_expression(expr->data.match.pred);
		printf("\n");
		for (uint64_t i = 0;i<expr->data.match.count;++i){
			show_pattern(&expr->data.match.patterns[i]);
			show_expression(&expr->data.match.cases[i]);
			printf("\n");
		}
		break;
	case CAST_EXPR:
		printf("(");
		show_expression(expr->data.cast.source);
		printf(" as ");
		show_type(expr->data.cast.target);
		printf(")");
		break;
	case BREAK_EXPR:
		printf("break");
		break;
	case CONTINUE_EXPR:
		printf("continue");
		break;
	case NOP_EXPR:
		printf("nop");
		break;
	}
}

pattern_ast*
parse_pattern(parser* const parse){
	token* t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	token* outer = t;
	t = &parse->tokens[parse->token_index];
	if (t->tag == AT_TOKEN){
		assert_local(outer->tag == IDENTIFIER_TOKEN, NULL, "expected identifier for named structure tag");
		pattern_ast* named = pool_request(parse->mem, sizeof(pattern_ast));
		named->tag = NAMED_PATTERN;
		named->type = NULL;
		named->data.named.name = *outer;
		parse->token_index += 1;
		named->data.named.inner = parse_pattern(parse);
		return named;
	}
	if (t->tag == EQUAL_TOKEN){ // left=x
		assert_local(outer->tag == IDENTIFIER_TOKEN, NULL, "expected identifier for union selector name");
		pattern_ast* union_select = pool_request(parse->mem, sizeof(pattern_ast));
		union_select->tag = UNION_SELECTOR_PATTERN;
		union_select->type = NULL;
		union_select->data.union_selector.member = *outer;
		parse->token_index += 1;
		union_select->data.union_selector.nest = parse_pattern(parse);
		return union_select;
	}
	pattern_ast* pat = pool_request(parse->mem, sizeof(pattern_ast));
	pat->type = NULL;
	switch (outer->tag){
	case STRING_TOKEN:
		pat->tag = STRING_PATTERN;
		pat->data.str = *outer;
		break;
	case PAREN_OPEN_TOKEN:
		pat->tag = STRUCT_PATTERN;
		uint64_t capacity = 2;
		pat->data.structure.members = pool_request(parse->mem, sizeof(pattern_ast)*capacity);
		pat->data.structure.count = 0;
		while (parse->token_index < parse->token_count){
			pattern_ast* item = parse_pattern(parse);
			assert_prop(NULL);
			if (pat->data.structure.count == capacity){
				capacity *= 2;
				pattern_ast* members = pool_request(parse->mem, sizeof(pattern_ast)*capacity);
				for (uint64_t i = 0;i<pat->data.structure.count;++i){
					members[i] = pat->data.structure.members[i];
				}
				pat->data.structure.members = members;
			}
			pat->data.structure.members[pat->data.structure.count] = *item;
			pat->data.structure.count += 1;
			t = &parse->tokens[parse->token_index];
			if (t->tag == PAREN_CLOSE_TOKEN){
				parse->token_index += 1;
				break;
			}
		}
		break;
	case BRACK_OPEN_TOKEN:
		pat->tag = FAT_PTR_PATTERN;
		pat->data.fat_ptr.ptr = parse_pattern(parse);
		assert_prop(NULL);
		pat->data.fat_ptr.len = parse_pattern(parse);
		assert_prop(NULL);
		t = &parse->tokens[parse->token_index];
		parse->token_index += 1;
		assert_local(t->tag == BRACK_CLOSE_TOKEN, NULL, "expected ] to close fat pointer pattern");
		break;
	case HOLE_TOKEN:
		pat->tag = HOLE_PATTERN;
		break;
	case INTEGER_TOKEN:
		pat->tag = LITERAL_PATTERN;
		if (outer->content_tag == UINT_TOKEN_TYPE){
			pat->data.literal.tag = UINT_LITERAL;
			pat->data.literal.data.u = outer->data.pos;
		}
		else if (outer->content_tag == INT_TOKEN_TYPE){
			pat->data.literal.tag = INT_LITERAL;
			pat->data.literal.data.i = outer->data.neg;
		}
		break;
	case FLOAT_TOKEN:
		pat->tag = LITERAL_PATTERN;
		if (outer->content_tag == FLOAT_TOKEN_TYPE){
			pat->data.literal.tag = DOUBLE_LITERAL;
			pat->data.literal.data.d = outer->data.flt;
		}
		else {
			assert_local(0, NULL, "Unexpected literal integer type");
		}
		break;
	case IDENTIFIER_TOKEN:
		pat->tag = BINDING_PATTERN;
		pat->data.binding = *outer;
		break;
	default:
		assert_local(0, NULL, "Unexpected token for pattern");
	}
	return pat;
}

void
show_pattern(pattern_ast* pat){
	switch (pat->tag){
	case NAMED_PATTERN:
		string_print(&pat->data.named.name.data.name);
		printf("@");
		show_pattern(pat->data.named.inner);
		break;
	case STRUCT_PATTERN:
		printf("(");
		for (uint64_t i = 0;i<pat->data.structure.count;++i){
			if (i != 0){
				printf(" ");
			}
			show_pattern(&pat->data.structure.members[i]);
		}
		printf(")");
		break;
	case FAT_PTR_PATTERN:
		printf("[");
		show_pattern(pat->data.fat_ptr.ptr);
		printf(" ");
		show_pattern(pat->data.fat_ptr.len);
		printf("]");
		break;
	case HOLE_PATTERN:
		printf("_");
		break;
	case BINDING_PATTERN:
		string_print(&pat->data.binding.data.name);
		break;
	case LITERAL_PATTERN:
		show_literal(&pat->data.literal);
		break;
	case STRING_PATTERN:
		string_print(&pat->data.str.data.name);
		break;
	case UNION_SELECTOR_PATTERN:
		string_print(&pat->data.union_selector.member.data.name);
		printf("=");
		show_pattern(pat->data.union_selector.nest);
		break;
	}
}

void
show_literal(literal_ast* const lit){
	switch(lit->tag){
	case INT_LITERAL:
		printf("%ld", lit->data.i);
		break;
	case UINT_LITERAL:
		printf("%lu", lit->data.u);
		break;
	case FLOAT_LITERAL:
		printf("%f", lit->data.f);
		break;
	case DOUBLE_LITERAL:
		printf("%lf", lit->data.d);
		break;
	}
}

expr_ast*
parse_expr(parser* const parse, TOKEN end){
	token* t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	expr_ast* expr = pool_request(parse->mem, sizeof(expr_ast));
	expr->dot = 0;
	expr->type = NULL;
	expr_ast* outer = expr;
	if (t->tag == end){
		outer->tag = NOP_EXPR;
		return outer;
	}
	while (parse->token_index < parse->token_count){
		switch (t->tag){
		case LAMBDA_TOKEN:
			expr->tag = LAMBDA_EXPR;
			expr->data.lambda.arg_count = 0;
			uint64_t capacity = 2;
			expr->data.lambda.args = pool_request(parse->mem, sizeof(pattern_ast)*capacity);
			while (parse->token_index < parse->token_count){
				t = &parse->tokens[parse->token_index];
				if (t->tag == COLON_TOKEN){
					parse->token_index += 1;
					break;
				}
				pattern_ast* arg = parse_pattern(parse);
				assert_prop(NULL);
				if (expr->data.lambda.arg_count == capacity){
					capacity *= 2;
					pattern_ast* args = pool_request(parse->mem, sizeof(pattern_ast)*capacity);
					for (uint64_t i = 0;i<expr->data.lambda.arg_count;++i){
						args[i] = expr->data.lambda.args[i];
					}
					expr->data.lambda.args = args;
				}
				expr->data.lambda.args[expr->data.lambda.arg_count] = *arg;
				expr->data.lambda.arg_count += 1;
			}
			expr->data.lambda.expression = parse_expr(parse, end);
			assert_prop(NULL);
			t = &parse->tokens[parse->token_index];
			if (end == SEMI_TOKEN){
				if (t->tag == PIPE_TOKEN){
					parse->token_index += 1;
					assert_local(parse->tokens[parse->token_index].tag == LAMBDA_TOKEN, NULL, "expected \\ to begin alternate pattern case for function value");
					expr->data.lambda.alt = parse_expr(parse, end);
				}
				return outer;
			}
			return outer;
		case AS_TOKEN:
			assert_local(outer->tag == APPL_EXPR, NULL, "Expected expression as source of cast");
			expr_ast* source = outer->data.appl.left;
			outer->tag = CAST_EXPR;
			outer->data.cast.source = source;
			outer->data.cast.target = parse_type(parse, 0, end);
			assert_prop(NULL);
			parse->token_index += 1;
			return outer;
		case COMPOSE_TOKEN:
			expr->dot = 1;
		case SYMBOL_TOKEN:
			expr->tag = BINDING_EXPR;
			expr->data.binding = *t;
			if (outer->tag == APPL_EXPR){
				expr_ast* swap = outer->data.appl.left;
				outer->data.appl.left = outer->data.appl.right;
				outer->data.appl.right = swap;
			}
			break;
		case BREAK_TOKEN:
			expr->tag = BREAK_EXPR;
			expr->data.binding = *t;
			break;
		case CONTINUE_TOKEN:
			expr->tag = CONTINUE_EXPR;
			expr->data.binding = *t;
			break;
		case IDENTIFIER_TOKEN:
			expr->tag = BINDING_EXPR;
			expr->data.binding = *t;
			break;
		case EQUAL_TOKEN:
			assert_local(outer->tag == APPL_EXPR, NULL, "Mutation expected left value");
			outer->tag = MUTATION_EXPR;
			expr_ast* rvalue = parse_expr(parse, end);
			assert_prop(NULL);
			*expr = *rvalue;
			return outer;
		case SHIFT_TOKEN:
			assert_local(outer->tag == APPL_EXPR, NULL, "Shift expected left value");
			expr_ast* rside = parse_expr(parse, end);
			assert_prop(NULL);
			*expr = *rside;
			break;
		case PAREN_OPEN_TOKEN:
			expr_ast* temp = parse_expr(parse, PAREN_CLOSE_TOKEN);
			assert_prop(NULL);
			*expr = *temp;
			break;
		case BRACE_OPEN_TOKEN:
			uint64_t save = parse->token_index;
			parse_block_expression(parse, end, expr);
			if (parse->err.len != 0){
				parse->token_index = save;
				parse->err.len = 0;
				uint64_t struct_capacity = 2;
				expr->tag = STRUCT_EXPR;
				expr->data.constructor.member_count = 0;
				expr->data.constructor.names = pool_request(parse->mem, sizeof(token)*struct_capacity);
				expr->data.constructor.members = pool_request(parse->mem, sizeof(expr_ast)*struct_capacity);
				while (parse->token_index < parse->token_count){
					if (expr->data.constructor.member_count == struct_capacity){
						struct_capacity *= 2;
						token* names = pool_request(parse->mem, sizeof(token)*struct_capacity);
						expr_ast* members = pool_request(parse->mem, sizeof(expr_ast)*struct_capacity);
						for (uint64_t i = 0;i<expr->data.constructor.member_count;++i){
							names[i] = expr->data.constructor.names[i];
							members[i] = expr->data.constructor.members[i];
						}
						expr->data.constructor.names = names;
						expr->data.constructor.members = members;
					}
					token* name = &parse->tokens[parse->token_index];
					token* eq = &parse->tokens[parse->token_index+1];
					if (eq->tag == EQUAL_TOKEN && (name->tag == IDENTIFIER_TOKEN || name->tag == SYMBOL_TOKEN)){
						expr->data.constructor.names[expr->data.constructor.member_count] = *name;
						parse->token_index += 2;
						save = parse->token_index;
						expr_ast* temp = parse_expr(parse, COMMA_TOKEN);
						if (parse->err.len != 0){
							parse->token_index = save;
							parse->err.len = 0;
							temp = parse_expr(parse, BRACE_CLOSE_TOKEN);
							assert_prop(NULL);
							expr->data.constructor.members[expr->data.constructor.member_count] = *temp;
							expr->data.constructor.member_count += 1;
							break;
						}
						expr->data.constructor.members[expr->data.constructor.member_count] = *temp;
						expr->data.constructor.member_count += 1;
						continue;
					}
					expr->data.constructor.names[expr->data.constructor.member_count].data.name.len = 0;
					save = parse->token_index;
					expr_ast* temp = parse_expr(parse, COMMA_TOKEN);
					if (parse->err.len != 0){
						parse->token_index = save;
						parse->err.len = 0;
						expr_ast* temp = parse_expr(parse, BRACE_CLOSE_TOKEN);
						assert_prop(NULL);
						expr->data.constructor.members[expr->data.constructor.member_count] = *temp;
						expr->data.constructor.member_count += 1;
						break;
					}
					expr->data.constructor.members[expr->data.constructor.member_count] = *temp;
					expr->data.constructor.member_count += 1;
				}
			}
			break;
		case BRACK_OPEN_TOKEN:
			expr->tag = LIST_EXPR;
			uint64_t list_capacity = 2;
			expr->data.list.lines = pool_request(parse->mem, sizeof(expr_ast)*list_capacity);
			expr->data.list.line_count = 0;
			while (parse->token_index < parse->token_count){
				if (expr->data.list.line_count == list_capacity){
					list_capacity *= 2;
					expr_ast* lines = pool_request(parse->mem, sizeof(expr_ast)*list_capacity);
					for (uint64_t i = 0;i<expr->data.list.line_count;++i){
						lines[i] = expr->data.list.lines[i];
					}
					expr->data.list.lines = lines;
				}
				uint64_t item_save = parse->token_index;
				expr_ast* item = parse_expr(parse, COMMA_TOKEN);
				if (parse->err.len != 0){
					parse->token_index = item_save;
					parse->err.len = 0;
					item = parse_expr(parse, BRACK_CLOSE_TOKEN);
					assert_prop(NULL);
					expr->data.list.lines[expr->data.list.line_count] = *item;
					expr->data.list.line_count += 1;
					break;
				}
				expr->data.list.lines[expr->data.list.line_count] = *item;
				expr->data.list.line_count += 1;
			}
			break;
		case STRING_TOKEN:
			expr->tag = STRING_EXPR;
			expr->data.str = *t;
			break;
		case CARROT_TOKEN:
			expr->tag = DEREF_EXPR;
			expr->data.deref = parse_expr(parse, end);
			return outer;
		case AMPERSAND_TOKEN:
			expr->tag = REF_EXPR;
			expr->data.ref = parse_expr(parse, end);
			return outer;
		case SIZEOF_TOKEN:
			expr->tag = SIZEOF_EXPR;
			type_ast* target_type = parse_type(parse, 0, end);
			parse->token_index += 1;
			expr->data.size_type = target_type;
			return outer;
		case RETURN_TOKEN:
			expr->tag = RETURN_EXPR;
			expr->data.ret = parse_expr(parse, end);
			return outer;
		case IF_TOKEN:
			expr->tag = IF_EXPR;
			expr->data.if_statement.pred = parse_expr(parse, BRACE_OPEN_TOKEN);
			assert_prop(NULL);
			parse->token_index -= 1;
			expr->data.if_statement.cons = parse_expr(parse, BRACE_CLOSE_TOKEN);
			assert_prop(NULL);
			t = &parse->tokens[parse->token_index];
			if (t->tag == ELSE_TOKEN){
				parse->token_index += 1;
				t = &parse->tokens[parse->token_index];
				assert_local(t->tag == BRACE_OPEN_TOKEN, NULL, "expected { to begin if statement consequent");
				expr->data.if_statement.alt = parse_expr(parse, BRACE_CLOSE_TOKEN);
				assert_prop(NULL);
			}
			else {
				expr->data.if_statement.alt = NULL;
			}
			break;
		case FOR_TOKEN:
			expr->tag = FOR_EXPR;
			t = &parse->tokens[parse->token_index];
			parse->token_index += 1;
			assert_local(t->tag == IDENTIFIER_TOKEN, NULL, "expected identifier to bind as for loop variable");
			expr->data.for_statement.binding = *t;
			expr->data.for_statement.initial = parse_expr(parse, BRACE_OPEN_TOKEN);
			assert_prop(NULL);
			assert_local(expr->data.for_statement.initial->tag == APPL_EXPR, NULL, "expected 2 expressions for for loop bounds");
			expr->data.for_statement.limit = expr->data.for_statement.initial->data.appl.right;
			expr_ast* left = expr->data.for_statement.initial->data.appl.left;
			expr->data.for_statement.initial = left;
			parse->token_index -= 1;
			expr->data.for_statement.cons = parse_expr(parse, BRACE_CLOSE_TOKEN);
			assert_prop(NULL);
			break;
		case WHILE_TOKEN:
			expr->tag = WHILE_EXPR;
			expr->data.while_statement.pred = parse_expr(parse, BRACE_OPEN_TOKEN);
			assert_prop(NULL);
			parse->token_index -= 1;
			expr->data.while_statement.cons = parse_expr(parse, BRACE_CLOSE_TOKEN);
			assert_prop(NULL);
			break;
		case MATCH_TOKEN:
			expr->tag = MATCH_EXPR;
			expr->data.match.pred = parse_expr(parse, BRACE_OPEN_TOKEN);
			assert_prop(NULL);
			uint64_t match_capacity = 2;
			expr->data.match.count = 0;
			expr->data.match.patterns = pool_request(parse->mem, sizeof(pattern_ast)*match_capacity);
			expr->data.match.cases = pool_request(parse->mem, sizeof(expr_ast)*match_capacity);
			while (parse->token_index < parse->token_count){
				pattern_ast* case_pattern = parse_pattern(parse);
				assert_prop(NULL);
				t = &parse->tokens[parse->token_index];
				assert_local(t->tag == COLON_TOKEN, NULL, "expected : for pattern case in match");
				parse->token_index += 1;
				expr_ast* case_expr = parse_expr(parse, SEMI_TOKEN);
				assert_prop(NULL);
				if (expr->data.match.count == match_capacity){
					match_capacity *= 2;
					pattern_ast* patterns = pool_request(parse->mem, sizeof(pattern_ast)*match_capacity);
					expr_ast* cases = pool_request(parse->mem, sizeof(expr_ast)*match_capacity);
					for (uint64_t i = 0;i<expr->data.match.count;++i){
						patterns[i] = expr->data.match.patterns[i];
						cases[i] = expr->data.match.cases[i];
					}
					expr->data.match.patterns = patterns;
					expr->data.match.cases = cases;
				}
				expr->data.match.patterns[expr->data.match.count] = *case_pattern;
				expr->data.match.cases[expr->data.match.count] = *case_expr;
				expr->data.match.count += 1;
				t = &parse->tokens[parse->token_index];
				if (t->tag == BRACE_CLOSE_TOKEN){
					parse->token_index += 1;
					break;
				}
			}
			break;
		case INTEGER_TOKEN:
			expr->tag = LIT_EXPR;
			if (t->content_tag == UINT_TOKEN_TYPE){
				expr->data.literal.data.u = t->data.pos;
				expr->data.literal.tag = UINT_LITERAL;
			}
			else if (t->content_tag == INT_TOKEN_TYPE){
				expr->data.literal.data.i = t->data.neg;
				expr->data.literal.tag = INT_LITERAL;
			}
			break;
		case FLOAT_TOKEN:
			expr->tag = LIT_EXPR;
			expr->data.literal.data.d = t->data.flt;
			expr->data.literal.tag = DOUBLE_LITERAL;
			break;
		default:
			assert_local(0, NULL, "Unexpected token in expression");
		}
		t = &parse->tokens[parse->token_index];
		if (t->tag == end ){
			parse->token_index += 1;
			return outer;
		}
		expr_ast* temp = pool_request(parse->mem, sizeof(expr_ast));
		temp->tag = APPL_EXPR;
		temp->type = NULL;
		temp->dot = 0;
		temp->data.appl.left = outer;
		temp->data.appl.right = pool_request(parse->mem, sizeof(expr_ast));
		expr = temp->data.appl.right;
		expr->dot = 0;
		expr->type = NULL;
		outer = temp;
		outer->type = NULL;
		t = &parse->tokens[parse->token_index];
		parse->token_index += 1;
	}
	return NULL;
}

void
parse_block_expression(parser* const parse, TOKEN end, expr_ast* const expr){
	expr->tag = BLOCK_EXPR;
	uint64_t block_capacity = 2;
	expr->data.block.lines = pool_request(parse->mem, sizeof(expr_ast)*block_capacity);
	expr->data.block.line_count = 0;
	while (parse->token_index < parse->token_count){
		token* t = &parse->tokens[parse->token_index];
		uint64_t save = parse->token_index;
		term_ast* closure = parse_term(parse);
		expr_ast* line;
		if (parse->err.len == 0){
			line = pool_request(parse->mem, sizeof(expr_ast));
			line->tag = TERM_EXPR;
			line->data.term = closure;
		}
		else{
			parse->err.len = 0;
			parse->token_index = save;
			line = parse_expr(parse, SEMI_TOKEN);
			assert_prop();
		}
		if (expr->data.block.line_count == block_capacity){
			block_capacity *= 2;
			expr_ast* lines = pool_request(parse->mem, sizeof(expr_ast)*block_capacity);
			for (uint64_t i = 0;i<expr->data.block.line_count;++i){
				lines[i] = expr->data.block.lines[i];
			}
			expr->data.block.lines = lines;
		}
		expr->data.block.lines[expr->data.block.line_count] = *line;
		expr->data.block.line_count += 1;
		t = &parse->tokens[parse->token_index];
		if (t->tag == end){
			if (end != SEMI_TOKEN){
				break;
			}
		}
		if (t->tag == BRACE_CLOSE_TOKEN){
			parse->token_index += 1;
			break;
		}
	}
}

term_ast*
parse_term(parser* const parse){
	term_ast* term = pool_request(parse->mem, sizeof(term_ast));
	term->type = parse_type(parse, 1, EQUAL_TOKEN);
	assert_prop(NULL);
	token* t = &parse->tokens[parse->token_index];
	term->name = *t;
	parse->token_index += 2;
	term->expression = parse_expr(parse, SEMI_TOKEN);
	return term;
}

void
parse_import(parser* const parse){
	token* t = &parse->tokens[parse->token_index];
	assert_local(t->tag == IMPORT_TOKEN, , "expected import to being module import");
	parse->token_index += 1;
	t = &parse->tokens[parse->token_index];
	assert_local(t->tag == STRING_TOKEN, , "expected string path for import source");
	parse->token_index += 1;
	uint64_t* imported = uint64_t_map_access(parse->imported, t->data.name);
	if (imported != NULL){
		return;
	}
	char* cstr_file = pool_request(parse->mem, t->data.name.len);
	strncpy(cstr_file, t->data.name.str+1, t->data.name.len-2);
	string offset_entry = {
		.str = cstr_file,
		.len = t->data.name.len-2
	};
	uint64_t_map_insert(parse->imported, offset_entry, parse->token_count);
	if (parse->file_offset_count == parse->file_offset_capacity){
		parse->file_offset_capacity *= 2;
		string* new = pool_request(parse->mem, parse->file_offset_capacity*sizeof(string));
		for (uint64_t i = 0;i<parse->file_offset_count;++i){
			new[i] = parse->file_offsets[i];
		}
		parse->file_offsets = new;
	}
	parse->file_offsets[parse->file_offset_count] = offset_entry;
	parse->file_offset_count += 1;
	FILE* infile = fopen(cstr_file, "r");
	assert_local(infile != NULL, , "Could not open file for import");
	uint64_t read_bytes = fread(parse->mem->ptr, sizeof(uint8_t), parse->mem->left, infile);
	fclose(infile);
	assert_local(read_bytes != parse->mem->left, , "File too big");
	string str = {
		.str=pool_request(parse->mem, read_bytes),
		.len=read_bytes
	};
	assert_local(str.str != NULL, , "File read error\n");
	parse->text = str;
	parse->text_index = 0;
#ifdef DEBUG
	token* new_tokens = &parse->tokens[parse->token_count];
	uint64_t original_count = parse->token_count;
#endif
	lex_string(parse);
	assert_prop();
#ifdef DEBUG
	show_tokens(new_tokens, parse->token_count-original_count);
	printf("\n");
#endif
}

void
show_error(parser* const parse){
	string_print(&parse->err);
	printf("\n");
	if (parse->file_offset_count > 0){
		uint64_t i = 0;
		string last = parse->file_offsets[i];
		i += 1;
		uint64_t* offset = uint64_t_map_access(parse->imported, last);
		uint64_t last_offset = *offset;
		assert(offset != NULL);
		if (parse->err_token >= *offset){
			while (parse->err_token >= *offset){
				if (i >= parse->file_offset_count){
					break;
				}
				string last = parse->file_offsets[i];
				i += 1;
				last_offset = *offset;
				offset = uint64_t_map_access(parse->imported, last);
				assert(offset != NULL);
			}
			last = parse->file_offsets[i-1];
			uint64_t final_index = parse->err_token - last_offset;
			lex_err(parse, final_index, last);
			return;
		}
	}
	lex_err(parse, parse->err_token, parse->mainfile);
}

void
lex_err(parser* const parse, uint64_t goal, string filename){
	FILE* fd = fopen(filename.str, "r");
	assert(fd != NULL);
	uint64_t read_bytes = fread(parse->mem->ptr, sizeof(uint8_t), parse->mem->left, fd);
	fclose(fd);
	assert(read_bytes != parse->mem->left);
	string str = {
		.str = pool_request(parse->mem, read_bytes),
		.len = read_bytes
	};
	assert(str.str != NULL);
	uint64_t index = 0;
	uint64_t text_index = 0;
	char* line_start = str.str;
	uint64_t line_pos = 0;
	uint64_t line = 1;
	while (text_index < str.len){
		if (index == goal){
			uint64_t position = (1+text_index) - line_pos;
			printf("\033[1m%s:%lu:\033[0m\n", filename.str, line);
			while (line_pos < str.len){
				if (*line_start == '\0'){
					printf("\n");
					break;
				}
				printf("%c", *line_start);
				if (*line_start == '\n'){
					break;
				}
				line_start += 1;
				line_pos += 1;
			}
			for (uint64_t i = 0;i<position;++i){
				printf(" ");
			}
			printf("\033[1m^\033[0m\n");
			return;
		}
		char c = str.str[text_index];
		text_index += 1;
		switch (c){
		case ' ':
		case '\r':
		case '\t':
			continue;
		case '\n':
			line += 1;
			line_start = &str.str[text_index];
			line_pos = text_index;
			continue;
		case COLON_TOKEN:
		case PIPE_TOKEN:
		case CARROT_TOKEN:
		case EQUAL_TOKEN:
		case AMPERSAND_TOKEN:
			if (issymbol(str.str[text_index])){
				break;
			}
		case AT_TOKEN:
		case PAREN_OPEN_TOKEN:
		case PAREN_CLOSE_TOKEN:
		case BRACK_OPEN_TOKEN:
		case BRACK_CLOSE_TOKEN:
		case BRACE_OPEN_TOKEN:
		case BRACE_CLOSE_TOKEN:
		case COMMA_TOKEN:
		case SEMI_TOKEN:
		case LAMBDA_TOKEN:
		case BACKTICK_TOKEN:
		case COMPOSE_TOKEN:
		case SHIFT_TOKEN:
		case HOLE_TOKEN:
			index += 1;
			continue;
		case '"':
			while (text_index < str.len){
				c = str.str[text_index];
				text_index += 1;
				if (c == '\n'){
					line_start = &str.str[text_index];
					line_pos = text_index;
					line += 1;
				}
				if (c == '"'){
					break;
				}
			}
			index += 1;
			continue;
		case '\'':
			c = str.str[text_index];
			text_index += 1;
			if (c == '\\'){
				c = str.str[text_index];
				text_index += 1;
				switch (c){
				case 'a': c = '\a'; break;
				case 'b': c = '\b'; break;
				case 'e': c = '\033'; break;
				case 'f': c = '\f'; break;
				case 'r': c = '\r'; break;
				case 't': c = '\t'; break;
				case 'v': c = '\v'; break;
				case '\\': c = '\\'; break;
				case '\'': c = '\''; break;
				case '"': c = '"'; break;
				case '?': c = '\?'; break;
				case 'n': c = '\n'; break;
				case '\n':
					c = '\n';
					line_start = &str.str[text_index];
					line_pos = text_index;
					line += 1;
					break;
				}
			}
			c = str.str[text_index];
			text_index += 1;
			assert_local(c == '\'', , "expected \' to close character literal");
			index += 1;
			continue;
		default:
			break;
		}
		if (c == '/'){
			char k = str.str[text_index];
			if (k == '/'){
				while (text_index < str.len){
					c = str.str[text_index];
					text_index += 1;
					if (c == '\n'){
						line_start = &str.str[text_index];
						line_pos = text_index;
						line += 1;
						break;
					}
				}
				continue;
			}
			else if (k == '*'){
				text_index += 1;
				while (text_index < str.len){
					c = str.str[text_index];
					text_index += 1;
					if (c == '\n'){
						line_pos = text_index;
						line_start = &str.str[text_index];
						line += 1;
					}
					if (c == '*'){
						k = str.str[text_index];
						if (k == '/'){
							text_index += 1;
							break;
						}
					}
				}
				continue;
			}
		}
		if (isalpha(c)){
			c = str.str[text_index];
			text_index += 1;
			while ((text_index < str.len) && (isalpha(c) || c == '_' || isdigit(c))){
				c = str.str[text_index];
				text_index += 1;
			}
			text_index -= 1;
			index += 1;
			continue;
		}
		else if (issymbol(c)){
			if (c == '-'){
				c = str.str[text_index];
				if (isdigit(c) == 0){
					c = str.str[text_index];
					text_index += 1;
					while ((text_index < str.len) && issymbol(c)){
						c = str.str[text_index];
						text_index += 1;
					}
					text_index -= 1;
					index += 1;
					continue;
				}
			}
			else{
				c = str.str[text_index];
				text_index += 1;
				while ((text_index < str.len) && issymbol(c)){
					c = str.str[text_index];
					text_index += 1;
				}
				text_index -= 1;
				index += 1;
				continue;
			}
		}
		if (isdigit(c) || c == '-'){
			if (c == '-'){
				c = str.str[text_index];
				text_index += 1;
			}
			if (c == '0'){
				c = str.str[text_index];
				text_index += 1;
				if (c == 'x'){
					while (text_index < str.len){
						if (c >= '0' && c <= '9'){ }
						else if (c >= 'A' && c <= 'F'){ }
						else if (c >= 'a' && c <= 'f'){ }
						else{
							text_index -= 1;
							break;
						}
						c = str.str[text_index];
						text_index += 1;
					}
					index += 1;
					continue;
				}
				else if (c == 'b'){
					while (text_index < str.len){
						if (c!='0'||c!='1'){
							text_index -= 1;
							break;
						}
						c = str.str[text_index];
						text_index += 1;
					}
					index += 1;
					continue;
				}
				else if (c == 'o'){
					while (text_index < str.len){
						if (c < '0' && c > '7'){
							text_index -= 1;
							break;
						}
						c = str.str[text_index];
						text_index += 1;
					}
					index += 1;
					continue;
				}
			}
			while (text_index < str.len){
				if (c == '.'){
					while (text_index < str.len){
						c = str.str[text_index];
						text_index += 1;
						if (c == 'f'){
							break;
						}
						if (c == 'e' || c == 'E'){
							c = str.str[text_index];
							text_index += 1;
							if (c == '-'){
								c = str.str[text_index];
								text_index += 1;
							}
							while (text_index < str.len){
								c = str.str[text_index];
								text_index += 1;
								if (isdigit(c) == 0){
									text_index -= 1;
									break;
								}
							}
							break;
						}
						if (isdigit(c) == 0){
							text_index -= 1;
							break;
						}
					}
					break;
				}
				else if (c == 'f'){
					break;
				}
				if (c == 'e' || c == 'E'){
					c = str.str[text_index];
					text_index += 1;
					if (c == '-'){
						c = str.str[text_index];
						text_index += 1;
					}
					while (text_index < str.len){
						c = str.str[text_index];
						text_index += 1;
						if (isdigit(c) == 0){
							text_index -= 1;
							break;
						}
					}
					break;
				}
				if (isdigit(c) == 0){
					text_index -= 1;
					break;
				}
				c = str.str[text_index];
				text_index += 1;
			}
			index += 1;
			continue;
		}
		assert_local(0, , "Unknown symbol");
		return;
	}
}

//NOTE every return requires a pop of the local scope, except term, because that binding needs to persist
//NOTE every case reduces both type and alias except binding, which just reduces alias, as strict term typing matters when comparing two strict types
//NOTE every case uses the outer type from a term or the outer type from a mutation and passes it along, outer_type is set to null once, when lambdas dont know their return type
type_ast*
walk_expr(walker* const walk, expr_ast* const expr, type_ast* expected_type, type_ast* const outer_type, uint8_t is_outer){
	if (expr->type != NULL){
		if (expr->tag == BINDING_EXPR){
			in_scope(walk, &expr->data.binding, expected_type, expr->type);
		}
		return expr->type;
	}
	uint64_t token_pos = walk->term_stack->count;
	if (expr->tag != LAMBDA_EXPR && expr->tag != TERM_EXPR){
		token nulltoken = {
			.data.name.len=0
		};
		token_pos = token_stack_push(walk->term_stack, nulltoken);
	}
	uint64_t scope_pos = walk->local_scope->binding_count;
	uint64_t expr_count = walk->outer_exprs->expr_count;
	structure_ast* inner;
	type_ast* inner_struct;
	type_ast* original = expected_type;
	if (expected_type != NULL){
		if (expr->tag != BINDING_EXPR){
			expected_type = reduce_alias_and_type(walk->parse, expected_type);
			walk_assert_prop();
		}
		inner_struct = expected_type;
		if (expected_type->tag == STRUCT_TYPE){
			inner = expected_type->data.structure;
			if (inner->tag == UNION_STRUCT){
				for (uint64_t k = 0;k<inner->data.union_structure.count;++k){
					type_ast* match_inference = walk_expr(walk, expr, &inner->data.union_structure.members[k], &inner->data.union_structure.members[k], 0);
					if (match_inference == NULL){
						walk->parse->err.len = 0;
						continue;
					}
					expr->type = expected_type;
					pop_binding(walk->local_scope, scope_pos);
					token_stack_pop(walk->term_stack, token_pos);
					expr->type = expected_type;
					return expected_type;
				}
				pop_binding(walk->local_scope, scope_pos);
				token_stack_pop(walk->term_stack, token_pos);
				expr->type = NULL;
				return NULL;
			}
		}
	}
	switch (expr->tag){
	case APPL_EXPR:
		if (expr->data.appl.right->tag == LIST_EXPR){
			if (expr->data.appl.right->data.list.line_count == 1){
				// x[i]
				type_ast* array = walk_expr(walk, expr->data.appl.left, NULL, outer_type, 0);
				walk_assert_prop();
				walk_assert(array != NULL, nearest_token(expr), "Unable to discern type of left expression in list application");
				type_ast* any = pool_request(walk->parse->mem, sizeof(type_ast));
				any->tag = PTR_TYPE;
				any->data.ptr = pool_request(walk->parse->mem, sizeof(type_ast));
				any->data.ptr->tag = LIT_TYPE;
				any->data.ptr->data.lit = INT_ANY;
				type_ast* access = walk_expr(walk, expr->data.appl.right, any, any, 0);
				walk_assert_prop();
				walk_assert(access != NULL, nearest_token(expr), "Accessor type should be integer");
				expr->tag = ARRAY_ACCESS_EXPR;
				if (array->tag == FAT_PTR_TYPE){
					pop_binding(walk->local_scope, scope_pos);
					token_stack_pop(walk->term_stack, token_pos);
					expr->type = array->data.fat_ptr.ptr;
					return array->data.fat_ptr.ptr;
				}
				else if (array->tag == PTR_TYPE){
					pop_binding(walk->local_scope, scope_pos);
					token_stack_pop(walk->term_stack, token_pos);
					expr->type = array->data.ptr;
					return array->data.ptr;
				}
			}
		}
		if (expr->data.appl.left->tag == APPL_EXPR){
			if (expr->data.appl.left->data.appl.left->tag == BINDING_EXPR){
				if (expr->data.appl.left->data.appl.left->dot == 1){
					// ((. obj) field)
					type_ast* obj = walk_expr(walk, expr->data.appl.left->data.appl.right, NULL, outer_type, 0);
					walk_assert_prop();
					walk_assert(obj != NULL, nearest_token(expr->data.appl.left->data.appl.right), "Unable to determine left type of either composition or field access");
					obj = reduce_alias_and_type(walk->parse, obj);
					walk_assert_prop();
					if (obj->tag == STRUCT_TYPE){
						walk_assert(expr->data.appl.right->tag == BINDING_EXPR, nearest_token(expr->data.appl.right), "Expected field for structure access");
						type_ast* field = is_member(obj, expr->data.appl.right);
						walk_assert(field != NULL, nearest_token(expr->data.appl.right), "Expected member of structure in field access");
						expr->data.appl.right->type = field;
						expr->tag = STRUCT_ACCESS_EXPR;
						expr_ast* struct_expr = expr->data.appl.left->data.appl.right;
						expr_ast* field_expr = expr->data.appl.right;
						expr->data.access.left = struct_expr;
						expr->data.access.right = field_expr;
						pop_binding(walk->local_scope, scope_pos);
						token_stack_pop(walk->term_stack, token_pos);
						expr->type = field;
						return field;
					}
					else if (obj->tag == PTR_TYPE){
						walk_assert(expr->data.appl.right->tag == BINDING_EXPR, nearest_token(expr->data.appl.right), "Expected field for structure access");
						type_ast* inner = obj->data.ptr;
						inner = reduce_alias_and_type(walk->parse, inner);
						walk_assert_prop();
						walk_assert(inner->tag == STRUCT_TYPE, nearest_token(expr->data.appl.right), "Field access from pointer must be from pointer to structure");
						type_ast* field = is_member(inner, expr->data.appl.right);
						walk_assert(field != NULL, nearest_token(expr->data.appl.right), "Expected member of structure in field access");
						expr->data.appl.right->type = field;
						expr->tag = STRUCT_ACCESS_EXPR;
						expr_ast* struct_expr = expr->data.appl.left->data.appl.right;
						expr_ast* field_expr = expr->data.appl.right;
						expr->data.access.left = struct_expr;
						expr->data.access.right = field_expr;
						pop_binding(walk->local_scope, scope_pos);
						token_stack_pop(walk->term_stack, token_pos);
						expr->type = field;
						return field;
					}
					else if (obj->tag == FAT_PTR_TYPE){
						walk_assert(expr->data.appl.right->tag == BINDING_EXPR, nearest_token(expr->data.appl.right), "Expected field for structure access");
						if (cstring_compare(&expr->data.appl.right->data.binding.data.name, "ptr") == 0){
							expr->tag = STRUCT_ACCESS_EXPR;
							expr_ast* struct_expr = expr->data.appl.left->data.appl.right;
							expr_ast* field_expr = expr->data.appl.right;
							expr->data.access.left = struct_expr;
							expr->data.access.right = field_expr;
							pop_binding(walk->local_scope, scope_pos);
							token_stack_pop(walk->term_stack, token_pos);
							expr->type = obj->data.fat_ptr.ptr;
							return obj->data.fat_ptr.ptr;
						}
						if (cstring_compare(&expr->data.appl.right->data.binding.data.name, "len") == 0){
							type_ast* lenlit = pool_request(walk->parse->mem, sizeof(type_ast));
							lenlit->tag = LIT_TYPE;
							lenlit->data.lit = U64_TYPE;
							expr->tag = STRUCT_ACCESS_EXPR;
							expr_ast* struct_expr = expr->data.appl.left->data.appl.right;
							expr_ast* field_expr = expr->data.appl.right;
							expr->data.access.left = struct_expr;
							expr->data.access.right = field_expr;
							pop_binding(walk->local_scope, scope_pos);
							token_stack_pop(walk->term_stack, token_pos);
							expr->type = lenlit;
							return lenlit;
						}
						type_ast* inner = obj->data.fat_ptr.ptr;
						walk_assert(inner->tag == STRUCT_TYPE, nearest_token(expr->data.appl.right), "Field access from pointer must be from pointer to structure");
						type_ast* field = is_member(inner, expr->data.appl.right);
						walk_assert(field != NULL, nearest_token(expr->data.appl.right), "Expected member of structure in field access");
						expr->data.appl.right->type = field;
						expr->tag = STRUCT_ACCESS_EXPR;
						expr_ast* struct_expr = expr->data.appl.left->data.appl.right;
						expr_ast* field_expr = expr->data.appl.right;
						expr->data.access.left = struct_expr;
						expr->data.access.right = field_expr;
						pop_binding(walk->local_scope, scope_pos);
						token_stack_pop(walk->term_stack, token_pos);
						expr->type = field;
						return field;
					}
					walk_assert(obj->tag == FUNCTION_TYPE || (obj->tag == DEPENDENCY_TYPE && obj->data.dependency.type->tag == FUNCTION_TYPE), nearest_token(expr), "Expected either structure access or composition, but left type was neither a function nor a structure");
					// f . g
					expr_ast* comp = expr->data.appl.left->data.appl.left;
					comp->tag = BINDING_EXPR;
					comp->dot = 0;
					string_set(walk->parse->mem, &comp->data.binding.data.name, "compose");
					type_ast* mytype = walk_expr(walk, expr, expected_type, expected_type, 0);
					walk_assert_prop();
					walk_assert(mytype != NULL, nearest_token(expr), "Unable to determine type in composition expression");
					pop_binding(walk->local_scope, scope_pos);
					token_stack_pop(walk->term_stack, token_pos);
					expr->type = mytype;
					return mytype;
				}
			}
		}
		push_expr_stack(walk);
		type_ast* right = walk_expr(walk, expr->data.appl.right, NULL, outer_type, 0);
		pop_expr_stack(walk);
		walk_assert_prop();
		walk_assert(right != NULL, nearest_token(expr->data.appl.right), "Could not discern type");
		if (expected_type != NULL){
			push_expr(walk->outer_exprs, expr->data.appl.right);
			type_ast* expanded_type;
			if (right->tag == DEPENDENCY_TYPE){
				expanded_type = mk_func(walk->parse->mem, right->data.dependency.type, original);
			}
			else{
				expanded_type = mk_func(walk->parse->mem, right, original);
			}
			type_ast* left_real = walk_expr(walk, expr->data.appl.left, expanded_type, outer_type, 0);
			pop_expr(walk->outer_exprs, expr_count);
			walk_assert_prop();
			walk_assert(left_real != NULL, nearest_token(expr->data.appl.left), "Left type of application expression did not resolve to type");
			walk_assert(left_real->tag == FUNCTION_TYPE || (left_real->tag == DEPENDENCY_TYPE && left_real->data.dependency.type->tag == FUNCTION_TYPE), nearest_token(expr->data.appl.left), "Left side of application expression was not a function");
			left_real = deep_copy_type(walk, left_real);
			right = deep_copy_type(walk, expr->data.appl.right->type);
			type_ast* left_outer = NULL;
			if (left_real->tag == DEPENDENCY_TYPE){
				left_outer = left_real;
				left_real = left_real->data.dependency.type;
			}
			type_ast* right_outer = NULL;
			if (right->tag == DEPENDENCY_TYPE){
				right_outer = right;
				right = right->data.dependency.type;
			}
			uint64_t dep_count = 0;
			type_depends(walk, left_outer, left_real, right_outer, right);
			walk_assert_prop();
			if (left_outer != NULL){
				dep_count += left_outer->data.dependency.dependency_count;
			}
			if (right_outer != NULL){
				dep_count += right_outer->data.dependency.dependency_count;
			}
			type_ast* outer_depends = NULL;
			if (left_outer != NULL || right_outer != NULL){
				outer_depends = pool_request(walk->parse->mem, sizeof(type_ast));
				outer_depends->tag = DEPENDENCY_TYPE;
				outer_depends->data.dependency.dependency_count = dep_count;
				outer_depends->data.dependency.dependency_typenames = pool_request(walk->parse->mem, sizeof(token)*dep_count);
				outer_depends->data.dependency.typeclass_dependencies = pool_request(walk->parse->mem, sizeof(token)*dep_count);
				uint64_t dpos = 0;
				if (left_outer != NULL){
					for (;dpos<left_outer->data.dependency.dependency_count;++dpos){
						outer_depends->data.dependency.dependency_typenames[dpos] = left_outer->data.dependency.dependency_typenames[dpos];
						outer_depends->data.dependency.typeclass_dependencies[dpos] = left_outer->data.dependency.typeclass_dependencies[dpos];
					}
				}
				if (right_outer != NULL){
					uint64_t i = 0;
					for (;dpos<dep_count;++dpos){
						outer_depends->data.dependency.dependency_typenames[dpos] = right_outer->data.dependency.dependency_typenames[i];
						outer_depends->data.dependency.typeclass_dependencies[dpos] = right_outer->data.dependency.typeclass_dependencies[i];
						i += 1;
					}
				}
			}
			clash_relation relation = clash_types(walk->parse, left_real->data.function.left, right);
			walk_assert(relation.relation != NULL, nearest_token(expr->data.appl.left), "First argument of left side of application with known type did not match right side of application");
			type_ast* generic_applied_type = deep_copy_type_replace(walk->parse->mem, &relation, left_real->data.function.right);
			type_ast* reduced_generic = reduce_alias_and_type(walk->parse, generic_applied_type);
			uint8_t applied_equal = type_equiv(walk, reduced_generic, expected_type);
			walk_assert(applied_equal == 1, nearest_token(expr), "Applied generic type did not match expected type");
			walk_assert_prop();
			if (is_generic(walk->parse, expr->data.appl.left->type) == 1){
				type_ast* left_generic = deep_copy_type(walk, expr->data.appl.left->type);
				type_ast* expected_generic = deep_copy_type(walk, expanded_type);
				type_ast* real_type = try_monomorph(walk, expr->data.appl.left, expr->data.appl.right, left_generic, expected_generic);
				walk_assert_prop();
				pop_binding(walk->local_scope, scope_pos);
				token_stack_pop(walk->term_stack, token_pos);
				expr->type = real_type;
				return real_type;
			}
			pop_binding(walk->local_scope, scope_pos);
			token_stack_pop(walk->term_stack, token_pos);
			expr->type = generic_applied_type;
			return generic_applied_type;
		}
		push_expr(walk->outer_exprs, expr->data.appl.right);
		type_ast* left = walk_expr(walk, expr->data.appl.left, NULL, outer_type, 0);
		pop_expr(walk->outer_exprs, expr_count);
		walk_assert_prop();
		walk_assert(left != NULL, nearest_token(expr->data.appl.left), "Unable to infer type of left of application");
		walk_assert(left->tag == FUNCTION_TYPE || (left->tag == DEPENDENCY_TYPE && left->data.dependency.type->tag == FUNCTION_TYPE), nearest_token(expr->data.appl.left), "Left of application type needs to be function");
		left = deep_copy_type(walk, left);
		right = deep_copy_type(walk, expr->data.appl.right->type);
		type_ast* left_outer = NULL;
		if (left->tag == DEPENDENCY_TYPE){
			left_outer = left;
			left = left->data.dependency.type;
		}
		type_ast* right_outer = NULL;
		if (right->tag == DEPENDENCY_TYPE){
			right_outer = right;
			right = right->data.dependency.type;
		}
		uint64_t dep_count = 0;
		type_depends(walk, left_outer, left, right_outer, right);
		walk_assert_prop();
		if (left_outer != NULL){
			dep_count += left_outer->data.dependency.dependency_count;
		}
		if (right_outer != NULL){
			dep_count += right_outer->data.dependency.dependency_count;
		}
		type_ast* outer_depends = NULL;
		if (left_outer != NULL || right_outer != NULL){
			outer_depends = pool_request(walk->parse->mem, sizeof(type_ast));
			outer_depends->tag = DEPENDENCY_TYPE;
			outer_depends->data.dependency.dependency_count = dep_count;
			outer_depends->data.dependency.dependency_typenames = pool_request(walk->parse->mem, sizeof(token)*dep_count);
			outer_depends->data.dependency.typeclass_dependencies = pool_request(walk->parse->mem, sizeof(token)*dep_count);
			uint64_t dpos = 0;
			if (left_outer != NULL){
				for (;dpos<left_outer->data.dependency.dependency_count;++dpos){
					outer_depends->data.dependency.dependency_typenames[dpos] = left_outer->data.dependency.dependency_typenames[dpos];
					outer_depends->data.dependency.typeclass_dependencies[dpos] = left_outer->data.dependency.typeclass_dependencies[dpos];
				}
			}
			if (right_outer != NULL){
				uint64_t i = 0;
				for (;dpos<dep_count;++dpos){
					outer_depends->data.dependency.dependency_typenames[dpos] = right_outer->data.dependency.dependency_typenames[i];
					outer_depends->data.dependency.typeclass_dependencies[dpos] = right_outer->data.dependency.typeclass_dependencies[i];
					i += 1;
				}
			}
		}
		clash_relation relation = clash_types(walk->parse, left->data.function.left, right);
		walk_assert(relation.relation != NULL, nearest_token(expr->data.appl.left), "First argument of left side of application did not match right side of application");
		type_ast* generic_applied_type;
	   	if (outer_depends == NULL){
			generic_applied_type = deep_copy_type_replace(walk->parse->mem, &relation, left->data.function.right);
		}
		else{
			outer_depends->data.dependency.type = left->data.function.right;
			generic_applied_type = deep_copy_type_replace(walk->parse->mem, &relation, outer_depends);
		}
		if (is_generic(walk->parse, expr->data.appl.left->type) == 1){
			type_ast* left_generic = deep_copy_type(walk, expr->data.appl.left->type);
			type_ast* real_type = try_monomorph(walk, expr->data.appl.left, expr->data.appl.right, left_generic, NULL);
			walk_assert_prop();
			pop_binding(walk->local_scope, scope_pos);
			token_stack_pop(walk->term_stack, token_pos);
			expr->type = real_type;
			return real_type;
		}
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = generic_applied_type;
		return generic_applied_type;
	case LAMBDA_EXPR:
		if (expected_type == NULL){
			uint64_t arg_pos = walk->outer_exprs->expr_count-1;
			type_ast* built_type = pool_request(walk->parse->mem, sizeof(type_ast));
			type_ast* type_focus = built_type;
			uint64_t scope_ptr = push_scope_ptr(walk);
			for (uint64_t i = 0;i<expr->data.lambda.arg_count;++i){
				expr_ast* arg = walk->outer_exprs->exprs[arg_pos];
				walk_assert(arg->type != NULL, nearest_token(arg), "Type of lambda arg should have been previously inferrable");
				type_ast* arg_type = arg->type;
				type_ast* real_type = walk_pattern(walk, &expr->data.lambda.args[i], arg_type);
				walk_assert_prop();
				walk_assert(real_type != NULL, nearest_pattern_token(&expr->data.lambda.args[i]), "Lambda term argument did not match expected type from outer arguments");
				type_focus->tag = FUNCTION_TYPE;
				type_focus->data.function.left = arg_type;
				type_focus->data.function.right = pool_request(walk->parse->mem, sizeof(type_ast));
				type_focus = type_focus->data.function.right;
				if (arg_pos == 0){
					walk_assert(i+1 == expr->data.lambda.arg_count, nearest_token(expr), "Types of spare arguments in lambda were not deducible");
					break;
				}
				arg_pos -= 1;
			}
			token newname = {
				.content_tag = STRING_TOKEN_TYPE,
				.tag = IDENTIFIER_TOKEN,
				.index = 0,
				.data.name = walk->next_lambda
			};
			generate_new_lambda(walk);
			type_ast* eval_type = walk_expr(walk, expr->data.lambda.expression, NULL, NULL, 0);
			walk_assert_prop();
			walk_assert(eval_type != NULL, nearest_token(expr->data.lambda.expression), "Lambda term expression did not have inferrable type");
			*type_focus = *eval_type;
			if (expr->data.lambda.alt != NULL){
				walk_assert(expr->data.lambda.alt->data.lambda.arg_count == expr->data.lambda.arg_count, nearest_token(expr->data.lambda.alt), "Alternate lambda branches must match in arity");
				pop_binding(walk->local_scope, scope_pos);
				type_ast* alt_type = walk_expr(walk, expr->data.lambda.alt, NULL, NULL, 1);
				walk_assert_prop();
				walk_assert(alt_type != NULL, nearest_token(expr->data.lambda.expression), "Lambda term alternate did not have inferrable type");
			}
			if (is_outer == 0){
				lift_lambda(walk, expr, built_type, newname);
				//NOTE this is now operating in an application expression, expr was mutated
			}
			pop_scope_ptr(walk, scope_ptr);
			pop_binding(walk->local_scope, scope_pos);
			expr->type = built_type;
			return built_type;
		}
		type_ast* expected_view = expected_type;
		uint64_t scope_ptr = push_scope_ptr(walk);
		for (uint64_t i = 0;i<expr->data.lambda.arg_count;++i){
			if (expected_view->tag == DEPENDENCY_TYPE){
				expected_view = expected_view->data.dependency.type;
			}
			walk_assert(expected_view->tag == FUNCTION_TYPE, nearest_token(expr), "Too many arguments given to lambda for expected type");
			type_ast* arg_type = expected_view->data.function.left;
			type_ast* real_type = walk_pattern(walk, &expr->data.lambda.args[i], arg_type);
			expected_view = expected_view->data.function.right;
			walk_assert_prop();
			walk_assert(real_type != NULL, nearest_pattern_token(&expr->data.lambda.args[i]), "Lambda term argument did not match expected type");
		}
		token newname = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = walk->next_lambda
		};
		generate_new_lambda(walk);
		type_ast* eval_type = walk_expr(walk, expr->data.lambda.expression, expected_view, expected_view, 0);
		walk_assert_prop();
		walk_assert(eval_type != NULL, nearest_token(expr->data.lambda.expression), "Lambda term expression did not match expected type");
		if (expr->data.lambda.alt != NULL){
			walk_assert(expr->data.lambda.alt->data.lambda.arg_count == expr->data.lambda.arg_count, nearest_token(expr->data.lambda.alt), "Alternate lambda branches must match in arity");
			pop_binding(walk->local_scope, scope_pos);
			type_ast* alt_type = walk_expr(walk, expr->data.lambda.alt, expected_type, expected_view, 1);
			walk_assert_prop();
			walk_assert(alt_type != NULL, nearest_token(expr->data.lambda.expression), "Lambda term alternate did not match expected type");
		}
		if (is_outer == 0){
			lift_lambda(walk, expr, expected_type, newname);
			//NOTE this is now operating in an application expression, expr was mutated
		}
		pop_scope_ptr(walk, scope_ptr);
		pop_binding(walk->local_scope, scope_pos);
		expr->type = expected_type;
		return expected_type;
	case BLOCK_EXPR:
		for (uint64_t i = 0;i<expr->data.block.line_count;++i){
			if (expr->data.block.lines[i].tag == RETURN_EXPR){
				type_ast* line_type = walk_expr(walk, &expr->data.block.lines[i], expected_type, outer_type, 0);
				walk_assert_prop();
				walk_assert(line_type != NULL, nearest_token(&expr->data.block.lines[i]), "Return expression did not resolve to any type");
				pop_binding(walk->local_scope, scope_pos);
				token_stack_pop(walk->term_stack, token_pos);
				expr->type = line_type;
				return line_type;
			}
			walk_expr(walk, &expr->data.block.lines[i], NULL, outer_type, 0);
			walk_assert_prop();
		}
		if (expected_type != NULL){
			walk_assert(expr->data.block.lines[expr->data.block.line_count-1].tag == RETURN_EXPR, nearest_token(expr), "Expected last expression in block to return");
		}
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = expected_type;
		return expected_type;
	case LIT_EXPR:
		if (expected_type != NULL){
			type_ast lit_type = {
				.tag = LIT_TYPE,
				.data.lit = INT_ANY
			};
			if (expected_type->data.lit > INT_ANY){
				lit_type.data.lit = F32_TYPE;
			}
			walk_assert(type_equal(walk->parse, expected_type, &lit_type), nearest_token(expr), "Literal type assigned to non matching type");
			pop_binding(walk->local_scope, scope_pos);
			token_stack_pop(walk->term_stack, token_pos);
			expr->type = expected_type;
			return expected_type;
		}
		type_ast* lit_type = pool_request(walk->parse->mem, sizeof(type_ast));
		if (expr->data.literal.tag <= UINT_LITERAL){
			lit_type->tag = LIT_TYPE;
			lit_type->data.lit = INT_ANY;
		}
		else{
			lit_type->tag = LIT_TYPE;
			lit_type->data.lit = F32_TYPE;
		}
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = lit_type;
		return lit_type;
	case TERM_EXPR:
		type_ast* term_type = walk_term(walk, expr->data.term, expected_type, 0);
		expr->type = term_type;
		return term_type;
	case STRING_EXPR:
		if (expected_type == NULL){
			type_ast* string_type = pool_request(walk->parse->mem, sizeof(type_ast));
			string_type->tag = PTR_TYPE;
			string_type->data.ptr = pool_request(walk->parse->mem, sizeof(type_ast));
			string_type->data.ptr->tag = LIT_TYPE;
			string_type->data.ptr->data.lit = I8_TYPE;
			pop_binding(walk->local_scope, scope_pos);
			token_stack_pop(walk->term_stack, token_pos);
			expr->type = string_type;
			return string_type;
		}
		walk_assert(expected_type->tag == PTR_TYPE || expected_type->tag == FAT_PTR_TYPE, nearest_token(expr), "String must be assigned to [i8] or i8^");
		if (expected_type->tag == FAT_PTR_TYPE){
			walk_assert(expected_type->data.fat_ptr.ptr->tag == LIT_TYPE && expected_type->data.fat_ptr.ptr->data.lit == I8_TYPE, nearest_token(expr), "String must be assigned to [i8] or i8^");
			expr_ast* swrapper = pool_request(walk->parse->mem, sizeof(expr_ast));
			swrapper->tag = STRUCT_EXPR;
			swrapper->data.constructor.member_count = 2;
			swrapper->data.constructor.members = pool_request(walk->parse->mem, sizeof(expr_ast)*2);
			swrapper->data.constructor.members[0] = *expr;
			swrapper->data.constructor.members[1].tag = LIT_EXPR;
			swrapper->data.constructor.members[1].data.literal.tag = UINT_LITERAL;
			swrapper->data.constructor.members[1].data.literal.data.u = expr->data.str.data.name.len;
			swrapper->data.constructor.names = pool_request(walk->parse->mem, sizeof(token)*2);
			token ptrname = {
				.content_tag = STRING_TOKEN_TYPE,
				.tag = IDENTIFIER_TOKEN,
				.index = 0,
				.data.name = string_init(walk->parse->mem, "ptr")
			};
			token lenname = {
				.content_tag = STRING_TOKEN_TYPE,
				.tag = IDENTIFIER_TOKEN,
				.index = 0,
				.data.name = string_init(walk->parse->mem, "len")
			};
			swrapper->data.constructor.names[0] = ptrname;
			swrapper->data.constructor.names[1] = lenname;
			*expr = *swrapper;
			pop_binding(walk->local_scope, scope_pos);
			token_stack_pop(walk->term_stack, token_pos);
			expr->type = expected_type;
			return expected_type;
		}
		walk_assert(expected_type->data.ptr->tag == LIT_TYPE && expected_type->data.ptr->data.lit == I8_TYPE, nearest_token(expr), "String must be assigned to [i8] or i8^");
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = expected_type;
		return expected_type;
	case LIST_EXPR:
		if (expected_type == NULL){
			type_ast* first;
			for (uint64_t i = 0;i<expr->data.block.line_count;++i){
				if (i == 0){
					first = walk_expr(walk, &expr->data.block.lines[i], NULL, outer_type, 0);
					walk_assert_prop();
					walk_assert(first != NULL, nearest_token(expr), "List element not able to resolve to type");
					continue;
				}
				type_ast* rest = walk_expr(walk, &expr->data.block.lines[i], first, first, 0);
				walk_assert_prop();
				walk_assert(rest != NULL, nearest_token(expr), "List element not able to resolve to type");
			}
			pop_binding(walk->local_scope, scope_pos);
			token_stack_pop(walk->term_stack, token_pos);
			expr->type = first;
			return first;
		}
		walk_assert(expected_type->tag == FAT_PTR_TYPE || expected_type->tag == PTR_TYPE, nearest_token(expr), "List assignment to non pointer type");
		if (expected_type->tag == FAT_PTR_TYPE){
			walk_assert(expr->data.block.line_count == 2, nearest_token(expr), "Expected fat pointer constructor to be in the format [pointer, length]");
			type_ast* synth_ptr = mk_ptr(walk->parse->mem, expected_type->data.fat_ptr.ptr);
			type_ast* integer = mk_lit(walk->parse->mem, INT_ANY);
			type_ast* ptr = walk_expr(walk, &expr->data.block.lines[0], synth_ptr, synth_ptr, 0);
			walk_assert_prop();
			walk_assert(ptr != NULL, nearest_token(&expr->data.block.lines[0]), "Expected pointer to expression for fat pointer constructor");
			type_ast* len = walk_expr(walk, &expr->data.block.lines[1], integer, integer, 0);
			walk_assert_prop();
			walk_assert(len != NULL, nearest_token(&expr->data.block.lines[1]), "Expected integer expressino for fat pointer constructor length");
			expr_ast* fat_left = &expr->data.block.lines[0];
			expr_ast* fat_right = &expr->data.block.lines[1];
			expr->tag = FAT_PTR_EXPR;
			expr->data.fat_ptr.left = fat_left;
			expr->data.fat_ptr.right = fat_right;
			pop_binding(walk->local_scope, scope_pos);
			token_stack_pop(walk->term_stack, token_pos);
			expr->type = expected_type;
			return expected_type;
		}
		for (uint64_t i = 0;i<expr->data.block.line_count;++i){
			type_ast* rest = walk_expr(walk, &expr->data.block.lines[i], expected_type->data.ptr, expected_type->data.ptr, 0);
			walk_assert_prop();
			walk_assert(rest != NULL, nearest_token(expr), "List element not able to resolve to type");
		}
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = expected_type;
		return expected_type;
	case STRUCT_EXPR:
		if (expected_type == NULL){
			type_ast* struct_type = pool_request(walk->parse->mem, sizeof(type_ast));
			struct_type->tag = STRUCT_TYPE;
			struct_type->data.structure = pool_request(walk->parse->mem, sizeof(structure_ast));
			structure_ast* s = struct_type->data.structure;
			s->tag = STRUCT_STRUCT;
			uint64_t capacity = 2;
			s->data.structure.members = pool_request(walk->parse->mem, sizeof(type_ast)*capacity);
			s->data.structure.names = pool_request(walk->parse->mem, sizeof(token)*capacity);
			for (uint64_t i = 0;i<expr->data.constructor.member_count;++i){
				if (s->data.structure.count == capacity){
					capacity *= 2;
					type_ast* members = pool_request(walk->parse->mem, sizeof(type_ast)*capacity);
					token* names = pool_request(walk->parse->mem, sizeof(token)*capacity);
					for (uint64_t k = 0;k<s->data.structure.count;++k){
						members[k] = s->data.structure.members[k];
						names[k] = s->data.structure.names[k];
					}
					s->data.structure.members = members;
					s->data.structure.names = names;
				}
				walk_assert(expr->data.constructor.names[i].data.name.len != 0, nearest_token(expr), "Anonymous structure members must be named");
				type_ast* member_type = walk_expr(walk, &expr->data.constructor.members[i], NULL, outer_type, 0);
				walk_assert_prop();
				walk_assert(member_type != NULL, nearest_token(expr), "Unable to determine type of anonymous structure member");
				s->data.structure.members[s->data.structure.count] = *member_type;
				s->data.structure.names[s->data.structure.count] = expr->data.constructor.names[i];
				s->data.structure.count += 1;
			}
			pop_binding(walk->local_scope, scope_pos);
			token_stack_pop(walk->term_stack, token_pos);
			expr->type = struct_type;
			return struct_type;
		}
		walk_assert(expected_type->tag == STRUCT_TYPE, nearest_token(expr), "Structure was found where non structure was expected");
		if (inner->tag == STRUCT_STRUCT){
			uint64_t current_member = 0;
			for (uint64_t i = 0;i<expr->data.constructor.member_count;++i){
				if (expr->data.constructor.names[i].data.name.len != 0){ // not named constructor value
					uint8_t found = 0;
					for (uint64_t k = 0;k<inner->data.structure.count;++k){
						if (string_compare(&inner->data.structure.names[k].data.name, &expr->data.constructor.names[i].data.name) == 0){
							type_ast* inferred = walk_expr(walk, &expr->data.constructor.members[i], &inner->data.structure.members[k], &inner->data.structure.members[k], 0);
							walk_assert_prop();
							walk_assert(inferred != NULL, nearest_token(&expr->data.constructor.members[i]), "Unexpected type for structure member");
							current_member = k+1;
							found = 1;
						}
					}
					walk_assert(found == 1, expr->data.constructor.names[i].index, "Unknown member of structure or union");
					continue;
				}
				walk_assert(current_member < inner->data.structure.count, expr->data.constructor.names[i].index, "Extra member in constructor");
				type_ast* inferred = walk_expr(walk, &expr->data.constructor.members[i], &inner->data.structure.members[current_member], &inner->data.structure.members[current_member], 0);
				walk_assert_prop();
				walk_assert(inferred != NULL, nearest_token(&expr->data.constructor.members[i]), "Unexpected type for structure member");
				current_member += 1;
			}
			pop_binding(walk->local_scope, scope_pos);
			token_stack_pop(walk->term_stack, token_pos);
			expr->type = expected_type;
			return expected_type;
		}
		walk_assert(inner->tag == ENUM_STRUCT, nearest_token(expr), "Expected enumerator value");
		walk_assert(expr->data.constructor.member_count == 1, nearest_token(expr), "Constructed enumerator requires 1 and only 1 value");
		type_ast* enum_type = walk_expr(walk, &expr->data.constructor.members[0], inner_struct, inner_struct, 0);
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = enum_type;
		return enum_type;
	case BINDING_EXPR:
		type_ast* actual = in_scope(walk, &expr->data.binding, expected_type, NULL);
		walk_assert(actual != NULL, nearest_token(expr), "Binding not found in scope");
		if (expected_type == NULL){
			pop_binding(walk->local_scope, scope_pos);
			token_stack_pop(walk->term_stack, token_pos);
			expr->type = actual;
			return actual;
		}
		uint8_t bind_equal = type_equiv(walk, actual, expected_type);
		walk_assert(bind_equal == 1, nearest_token(expr), "Binding was not the expected type");
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = actual;
		return actual;
	case MUTATION_EXPR:
		walk_assert(expected_type == NULL, nearest_token(expr), "Mutation should not be expected to resolve to a type");
		type_ast* mut_left = walk_expr(walk, expr->data.mutation.left, NULL, outer_type, 0);
		walk_assert_prop();
		walk_assert(mut_left != NULL, nearest_token(expr->data.mutation.left), "Left side of mutation did not resolve to a type");
		walk_assert(mut_left->variable == 1, nearest_token(expr->data.mutation.left), "Left side of mutation must be a variable");
		type_ast* mut_right = walk_expr(walk, expr->data.mutation.right, mut_left, mut_left, 0);
		walk_assert_prop();
		walk_assert(mut_right != NULL, nearest_token(expr->data.mutation.right), "Left side of mutation did not match type of right side");
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = NULL;
		return NULL;
	case RETURN_EXPR:
		type_ast* ret_type = walk_expr(walk, expr->data.ret, outer_type, outer_type, 0);
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = ret_type;
		return ret_type;
	case SIZEOF_EXPR:
		type_ast* sizeof_type = pool_request(walk->parse->mem, sizeof(type_ast));
		sizeof_type->tag = LIT_TYPE;
		sizeof_type->data.lit = U64_TYPE;
		if (expected_type == NULL){
			pop_binding(walk->local_scope, scope_pos);
			token_stack_pop(walk->term_stack, token_pos);
			expr->type = sizeof_type;
			return sizeof_type;
		}
		walk_assert(type_equal(walk->parse, sizeof_type, expected_type), nearest_token(expr), "Expected type did not match type of sizeof expression (u64 or int_any)");
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = sizeof_type;
		return sizeof_type;
	case REF_EXPR:
		if (expected_type == NULL){
			type_ast* ref_infer = walk_expr(walk, expr->data.ref, NULL, outer_type, 0);
			walk_assert_prop();
			walk_assert(ref_infer != NULL, nearest_token(expr), "Unable to infer type to reference");
			type_ast* ref = pool_request(walk->parse->mem, sizeof(type_ast));
			ref->tag = PTR_TYPE;
			ref->data.ptr = ref_infer;
			pop_binding(walk->local_scope, scope_pos);
			token_stack_pop(walk->term_stack, token_pos);
			expr->type = ref;
			return ref;
		}
		walk_assert(expected_type->tag == PTR_TYPE || expected_type->tag == FAT_PTR_TYPE, nearest_token(expr), "Unexpected reference where non pointer was expected");
		type_ast* ref_inner;
		if (expected_type->tag == FAT_PTR_TYPE){
			ref_inner = expected_type->data.fat_ptr.ptr;
		}
		else{
			ref_inner = expected_type->data.ptr;
		}
		type_ast* ref_infer = walk_expr(walk, expr->data.ref, ref_inner, ref_inner, 0);
		walk_assert_prop();
		walk_assert(ref_infer != NULL, nearest_token(expr), "Reference to type did not match expected type reference");
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = expected_type;
		return expected_type;
	case DEREF_EXPR:
		if (expected_type == NULL){
			type_ast* deref_infer = walk_expr(walk, expr->data.deref, NULL, outer_type, 0);
			walk_assert_prop();
			walk_assert(deref_infer != NULL, nearest_token(expr), "Unable to infer type to dereference");
			walk_assert(deref_infer->tag == PTR_TYPE || deref_infer->tag == FAT_PTR_TYPE, nearest_token(expr), "Expected pointer to dereference");
			if (deref_infer->tag == FAT_PTR_TYPE){
				pop_binding(walk->local_scope, scope_pos);
				token_stack_pop(walk->term_stack, token_pos);
				expr->type = deref_infer->data.fat_ptr.ptr;
				return deref_infer->data.fat_ptr.ptr;
			}
			pop_binding(walk->local_scope, scope_pos);
			token_stack_pop(walk->term_stack, token_pos);
			expr->type = deref_infer->data.ptr;
			return deref_infer->data.ptr;
		}
		type_ast* expected_ptr = pool_request(walk->parse->mem, sizeof(type_ast));
		expected_ptr->tag = PTR_TYPE;
		expected_ptr->data.ptr = expected_type;
		type_ast* deref_infer = walk_expr(walk, expr->data.deref, expected_ptr, expected_ptr, 0);
		walk_assert_prop();
		walk_assert(deref_infer != NULL, nearest_token(expr), "Expected pointer to dereference");
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = expected_type;
		return expected_type;
	case IF_EXPR:
		type_ast* if_predicate = pool_request(walk->parse->mem, sizeof(type_ast));
		if_predicate->tag = LIT_TYPE;
		if_predicate->data.lit = INT_ANY;
		type_ast* ifpredtype = walk_expr(walk, expr->data.if_statement.pred, if_predicate, if_predicate, 0);
		walk_assert_prop();
		walk_assert(ifpredtype != NULL, nearest_token(expr->data.if_statement.pred), "If predicate must be integral");
		if (expected_type != NULL){
			type_ast* cons_type = walk_expr(walk, expr->data.if_statement.cons, NULL, outer_type, 0);
			walk_assert_prop();
			walk_assert(type_equal(walk->parse, cons_type, expected_type), nearest_token(expr->data.if_statement.cons), "If statement consequent did not resolve to expected type");
			if (expr->data.if_statement.alt != NULL){
				type_ast* alt_type = walk_expr(walk, expr->data.if_statement.alt, cons_type, outer_type, 0);
			   	walk_assert_prop();
				walk_assert(alt_type != NULL, nearest_token(expr->data.if_statement.alt), "If alternate must be same type as cons when if statement is used as expression");
			}
			pop_binding(walk->local_scope, scope_pos);
			token_stack_pop(walk->term_stack, token_pos);
			expr->type = cons_type;
			return cons_type;
		}
		type_ast* cons_type = walk_expr(walk, expr->data.if_statement.cons, NULL, outer_type, 0);
		walk_assert_prop();
		if (expr->data.if_statement.alt != NULL){
			type_ast* alt_type = walk_expr(walk, expr->data.if_statement.alt, NULL, outer_type, 0);
			if (type_equal(walk->parse, cons_type, alt_type) == 1){
				pop_binding(walk->local_scope, scope_pos);
				token_stack_pop(walk->term_stack, token_pos);
				expr->type = cons_type;
				return cons_type;
			}
			pop_binding(walk->local_scope, scope_pos);
			token_stack_pop(walk->term_stack, token_pos);
			expr->type = NULL;
			return NULL;
		}
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = cons_type;
		return cons_type;
	case FOR_EXPR:
		walk_assert(expected_type == NULL, nearest_token(expr), "Iterative loops cannot be used as expressions");
		type_ast* for_type = pool_request(walk->parse->mem, sizeof(type_ast));
		for_type->tag = LIT_TYPE;
		for_type->data.lit = INT_ANY;
		type_ast* forinittype = walk_expr(walk, expr->data.for_statement.initial, for_type, for_type, 0);
		walk_assert_prop();
	   	walk_assert(forinittype != NULL, nearest_token(expr->data.for_statement.initial), "For loop range must be integral");
		type_ast* forlimittype = walk_expr(walk, expr->data.for_statement.limit, for_type, for_type, 0);
		walk_assert_prop();
	   	walk_assert(forlimittype != NULL, nearest_token(expr->data.for_statement.limit), "For loop range must be integral");
		push_binding(walk, walk->local_scope, &expr->data.for_statement.binding, for_type);
		walk_expr(walk, expr->data.for_statement.cons, NULL, outer_type, 0);
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = NULL;
		return NULL;
	case WHILE_EXPR:
		walk_assert(expected_type == NULL, nearest_token(expr), "Iterative loops cannot be used as expressions");
		type_ast* while_predicate = pool_request(walk->parse->mem, sizeof(type_ast));
		while_predicate->tag = LIT_TYPE;
		while_predicate->data.lit = INT_ANY;
		type_ast* whilepredtype = walk_expr(walk, expr->data.while_statement.pred, while_predicate, while_predicate, 0);
		walk_assert_prop();
	   	walk_assert(whilepredtype != NULL, nearest_token(expr->data.while_statement.pred), "While predicate must be integral");
		walk_expr(walk, expr->data.while_statement.cons, NULL, outer_type, 0);
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = NULL;
		return NULL;
	case MATCH_EXPR:
		type_ast* match_infer = walk_expr(walk, expr->data.match.pred, NULL, outer_type, 0);
		walk_assert(match_infer != NULL, nearest_token(expr->data.match.pred), "Could not infer type of match predicate");
		if (expected_type != NULL){
			for (uint64_t i = 0;i<expr->data.match.count;++i){
				type_ast* pat_confirm = walk_pattern(walk, &expr->data.match.patterns[i], match_infer);
				walk_assert_prop();
				walk_assert(pat_confirm != NULL, nearest_pattern_token(&expr->data.match.patterns[i]), "Pattern in match did not resolve to correct type");
				type_ast* confirm = walk_expr(walk, &expr->data.match.cases[i], expected_type, outer_type, 0);
				walk_assert_prop();
				walk_assert(confirm != NULL, nearest_token(&expr->data.match.cases[i]), "Match case did not resolve to expected type");
			}
			pop_binding(walk->local_scope, scope_pos);
			token_stack_pop(walk->term_stack, token_pos);
			expr->type = expected_type;
			return expected_type;
		}
		type_ast* first;
		uint8_t matches = 1;
		for (uint64_t i = 0;i<expr->data.match.count;++i){
			type_ast* pat_confirm = walk_pattern(walk, &expr->data.match.patterns[i], match_infer);
			walk_assert_prop();
			walk_assert(pat_confirm != NULL, nearest_pattern_token(&expr->data.match.patterns[i]), "Pattern in match did not resolve to correct type");
			if (i == 0){
				first = walk_expr(walk, &expr->data.match.cases[i], NULL, outer_type, 0);
				walk_assert_prop();
				pop_binding(walk->local_scope, scope_pos);
				token_stack_pop(walk->term_stack, token_pos);
				continue;
			}
			type_ast* next = walk_expr(walk, &expr->data.match.cases[i], NULL, outer_type, 0);
			walk_assert_prop();
			if (matches == 1){
				if (type_equal(walk->parse, next, first) == 0){
					matches = 0;
				}
			}
		}
		if (matches == 0){
			pop_binding(walk->local_scope, scope_pos);
			token_stack_pop(walk->term_stack, token_pos);
			expr->type = NULL;
			return NULL;
		}
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = first;
		return first;
	case CAST_EXPR:
		type_ast* cast_confirm = walk_expr(walk, expr->data.cast.source, NULL, outer_type, 0);
		walk_assert(cast_confirm != NULL, nearest_token(expr), "Could not infer source type of cast");
		if (expected_type == NULL){
			pop_binding(walk->local_scope, scope_pos);
			token_stack_pop(walk->term_stack, token_pos);
			expr->type = expr->data.cast.target;
			return expr->data.cast.target;
		}
		walk_assert(type_equal(walk->parse, expected_type, expr->data.cast.target), nearest_token(expr), "Expected type did not match target type of cast");
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = expr->data.cast.target;
		return expr->data.cast.target;
	case BREAK_EXPR:
		walk_assert(expected_type == NULL, nearest_token(expr), "Expected type, found break");
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = NULL;
		return NULL;
	case CONTINUE_EXPR:
		walk_assert(expected_type == NULL, nearest_token(expr), "Expected type, found continue");
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = NULL;
		return NULL;
	case NOP_EXPR:
		walk_assert(expected_type == NULL, nearest_token(expr), "Expected type, found NOP expression");
		pop_binding(walk->local_scope, scope_pos);
		token_stack_pop(walk->term_stack, token_pos);
		expr->type = NULL;
		return NULL;
	case FAT_PTR_EXPR:
	case STRUCT_ACCESS_EXPR:
	case ARRAY_ACCESS_EXPR:
		walk_assert(expr->type != NULL, nearest_token(expr), "Type should already have been evaluated for this access");
		return expr->type;
	}
	return NULL;
}

type_ast*
walk_term(walker* const walk, term_ast* const term, type_ast* expected_type, uint8_t is_outer){
	if (is_generic(walk->parse, term->type) == 1){
		if (term->type->tag == NAMED_TYPE && term->type->data.named.arg_count == 0){
			uint64_t pos = push_binding(walk, walk->local_scope, &term->name, term->type);
			walk_assert_prop();
			uint64_t token_pos = token_stack_push(walk->term_stack, term->name);
			uint64_t mapstack_pos = term_map_stack_push(walk->replacements);
			type_ast* real_type = walk_expr(walk, term->expression, NULL, NULL, is_outer);
			term_map_stack_pop(walk->replacements, mapstack_pos);
			token_stack_pop(walk->term_stack, token_pos);
			pop_binding(walk->local_scope, pos);
			walk_assert_prop();
			walk_assert(real_type != NULL, nearest_token(term->expression), "Term type did not match declared type");
			term->type = real_type;
			return term->type;
		}
		term_map_stack_push_relation(walk->replacements, term->name.data.name, term);
		push_binding(walk, walk->local_scope, &term->name, term->type);
		return expected_type;
	}
	uint64_t pos = push_binding(walk, walk->local_scope, &term->name, term->type);
	walk_assert_prop();
	uint64_t token_pos = token_stack_push(walk->term_stack, term->name);
	uint64_t mapstack_pos = term_map_stack_push(walk->replacements);
	type_ast* real_type = walk_expr(walk, term->expression, term->type, term->type, is_outer);
	term_map_stack_pop(walk->replacements, mapstack_pos);
	token_stack_pop(walk->term_stack, token_pos);
	pop_binding(walk->local_scope, pos);
	walk_assert_prop();
	walk_assert(real_type != NULL, nearest_token(term->expression), "Term type did not match declared type");
	return term->type;
}

uint64_t
push_binding(walker* const walk, scope* const s, token* const t, type_ast* const type){
	parser* parse = walk->parse;
	for (uint64_t i = 0;i<s->binding_count;++i){
		uint8_t duplicate = string_compare(&t->data.name, &s->bindings[i].name->data.name);
		assert_local(duplicate != 0, 0, "Duplicate bound name");
	}
	if (s->binding_count == s->binding_capacity){
		s->binding_capacity *= 2;
		binding* bindings = pool_request(s->mem, sizeof(binding)*s->binding_capacity);
		for (uint64_t i = 0;i<s->binding_count;++i){
			bindings[i] = s->bindings[i];
		}
		s->bindings = bindings;
	}
	binding b = {
		.name = t,
		.type = deep_copy_type(walk, type)
	};
	s->bindings[s->binding_count] = b;
	s->binding_count += 1;
	return s->binding_count;
}

void
pop_binding(scope* const s, uint64_t pos){
	s->binding_count = pos;
}

uint64_t push_expr(expr_stack* const s, expr_ast* expr){
	if (s->expr_count == s->expr_capacity){
		s->expr_capacity *= 2;
		expr_ast** exprs = pool_request(s->mem, sizeof(expr_ast)*s->expr_capacity);
		for (uint64_t i = 0;i<s->expr_count;++i){
			exprs[i] = s->exprs[i];
		}
		s->exprs = exprs;
	}
	s->exprs[s->expr_count] = expr;
	s->expr_count += 1;
	return s->expr_count;
}

void pop_expr(expr_stack* const s, uint64_t pos){
	s->expr_count = pos;
}

void push_expr_stack(walker* const walk){
	if (walk->outer_exprs->next != NULL){
		walk->outer_exprs = walk->outer_exprs->next;
		walk->outer_exprs->expr_count = 0;
		return;
	}
	walk->outer_exprs->next = pool_request(walk->parse->mem, sizeof(expr_stack));
	walk->outer_exprs->next->prev = walk->outer_exprs;
	walk->outer_exprs = walk->outer_exprs->next;
	walk->outer_exprs->next = NULL;
	walk->outer_exprs->exprs = pool_request(walk->parse->mem, sizeof(expr_ast*));
	walk->outer_exprs->expr_capacity = 2;
	walk->outer_exprs->expr_count = 0;
}

void pop_expr_stack(walker* const walk){
	if (walk->outer_exprs->prev == NULL){
		return;
	}
	walk->outer_exprs = walk->outer_exprs->prev;
}

type_ast*
reduce_alias(parser* const parse, type_ast* start_type){
	type_ast* outer_type = NULL;
	if (start_type->tag == DEPENDENCY_TYPE){
		outer_type = pool_request(parse->mem, sizeof(type_ast));
		*outer_type = *start_type;
		start_type = start_type->data.dependency.type;
	}
	while (start_type->tag == NAMED_TYPE){
		alias_ast** alias = alias_ptr_map_access(parse->aliases, start_type->data.named.name.data.name);
		if (alias == NULL){
			return start_type;
		}
		start_type = (*alias)->type;
	}
	if (outer_type != NULL){
		outer_type->data.dependency.type = start_type;
		return outer_type;
	}
	return start_type;
}

type_ast*
reduce_alias_and_type(parser* const parse, type_ast* start_type){
	type_ast* outer_type = NULL;
	if (start_type->tag == DEPENDENCY_TYPE){
		outer_type = pool_request(parse->mem, sizeof(type_ast));
		*outer_type = *start_type;
		start_type = start_type->data.dependency.type;
	}
	while (start_type->tag == NAMED_TYPE){
		alias_ast** alias = alias_ptr_map_access(parse->aliases, start_type->data.named.name.data.name);
		if (alias != NULL){
			start_type = (*alias)->type;
			continue;
		}
		typedef_ast** type = typedef_ptr_map_access(parse->types, start_type->data.named.name.data.name);
		if (type != NULL){
			if (start_type->data.named.arg_count != 0){
				type_ast_map relation = type_ast_map_init(parse->mem);
				assert_local((*type)->param_count >= start_type->data.named.arg_count, NULL, "Too many arguments given for parametric type\n");
				for (uint64_t i = 0;i<start_type->data.named.arg_count;++i){
					type_ast_map_insert(&relation, (*type)->params[i].data.name, start_type->data.named.args[i]);
				}
				type_ast_map empty_ptr_only = type_ast_map_init(parse->mem);
				clash_relation r = {
					.relation = &relation,
					.pointer_only = &empty_ptr_only
				};
				start_type = deep_copy_type_replace(parse->mem, &r, (*type)->type);
				continue;
			}
			start_type = (*type)->type;
			continue;
		}
		type = typedef_ptr_map_access(parse->extern_types, start_type->data.named.name.data.name);
		if (type != NULL){
			assert_local(start_type->data.named.arg_count == 0, NULL, "External type symbols must be nonparametric");
			start_type = (*type)->type;
		}
		if (outer_type != NULL){
			outer_type->data.dependency.type = start_type;
			return outer_type;
		}
		return start_type;
	}
	if (outer_type != NULL){
		outer_type->data.dependency.type = start_type;
		return outer_type;
	}
	return start_type;
}

type_ast*
in_scope(walker* const walk, token* const bind, type_ast* expected_type, type_ast* const real_type){
	if (expected_type != NULL){
		expected_type = reduce_alias(walk->parse, expected_type);
	}
	type_ast* builtin = is_builtin(walk, bind, expected_type);
	if (builtin != NULL){
		return builtin;
	}
	term_ast** term = term_ptr_map_access(walk->parse->terms, bind->data.name);
	if (term != NULL){
		return (*term)->type;
	}
	term = term_ptr_map_access(walk->parse->extern_terms, bind->data.name);
	if (term != NULL){
		return (*term)->type;
	}
	uint64_t* value = uint64_t_map_access(walk->parse->enumerated_values, bind->data.name);
	if (value != NULL){
		if (expected_type != NULL){
			if ((expected_type->tag == STRUCT_TYPE) && (expected_type->data.structure->tag == ENUM_STRUCT)){
				for (uint64_t i = 0;i<expected_type->data.structure->data.enumeration.count;++i){
					if (string_compare(&expected_type->data.structure->data.enumeration.names[i].data.name, &bind->data.name) == 0){
						return expected_type;
					}
				}
			}
		}
		type_ast* any = pool_request(walk->parse->mem, sizeof(type_ast));
		any->tag = LIT_TYPE;
		any->data.lit = INT_ANY;
		return any;
	}
	for (uint64_t i = 0;i<walk->local_scope->binding_count;++i){
		if (string_compare(&bind->data.name, &walk->local_scope->bindings[i].name->data.name) == 0){
			if (i < walk->scope_ptrs->ptrs[walk->scope_ptrs->count-1]){
				if (real_type != NULL){
					if (is_generic(walk->parse, real_type) == 0){
						scrape_binding(walk, &walk->local_scope->bindings[i]);
					}
				}
				else{
					if (is_generic(walk->parse, walk->local_scope->bindings[i].type) == 0){
						scrape_binding(walk, &walk->local_scope->bindings[i]);
					}
				}
			}
			type_ast_map empty = type_ast_map_init(walk->parse->mem);
			type_ast_map ptr_empty = type_ast_map_init(walk->parse->mem);
			clash_relation r = {&empty, &ptr_empty};
			return deep_copy_type_replace(walk->parse->mem, &r, walk->local_scope->bindings[i].type);
		}
	}
	term_ptr_buffer* poly_funcs = term_ptr_buffer_map_access(walk->parse->implemented_terms, bind->data.name);
	if (poly_funcs != NULL){
		for (uint64_t i = 0;i<poly_funcs->count;++i){
			term_ast* term = poly_funcs->buffer[i];
			type_ast* type = term->type;
			if (expected_type == NULL){
				uint64_t index = walk->outer_exprs->expr_count-1;
				uint8_t broke = 0;
				while (type->tag == FUNCTION_TYPE){
					expr_ast* arg = walk->outer_exprs->exprs[index];
					type_ast* candidate = walk_expr(walk, arg, NULL, NULL, 0);
					if (candidate == NULL){
						broke = 1;
						break;
					}
					if (type_equal(walk->parse, candidate, type->data.function.left) == 0){
						broke = 1;
						break;
					}
					type = type->data.function.right;
					if (index == 0){
						break;
					}
					index -= 1;
				}
				if (broke == 0){
					return deep_copy_type(walk, term->type);
				}
			}
			else{
				if (type_equal(walk->parse, expected_type, type) == 1){
					return expected_type;
				}
			}
		}
	}
	return NULL;
}

type_ast*
is_builtin(walker* const walk, token* const bind, type_ast* const expected_type){
	if ((cstring_compare(&bind->data.name, "~add") == 0)
	|| (cstring_compare(&bind->data.name, "~sub") == 0)
	|| (cstring_compare(&bind->data.name, "~mul") == 0)
	|| (cstring_compare(&bind->data.name, "~div") == 0)
	|| (cstring_compare(&bind->data.name, "~lt") == 0)
	|| (cstring_compare(&bind->data.name, "~gt") == 0)
	|| (cstring_compare(&bind->data.name, "~le") == 0)
	|| (cstring_compare(&bind->data.name, "~ge") == 0)
	|| (cstring_compare(&bind->data.name, "~eq") == 0)
	|| (cstring_compare(&bind->data.name, "~neq") == 0)
	|| (cstring_compare(&bind->data.name, "~and") == 0)
	|| (cstring_compare(&bind->data.name, "~bitand") == 0)
	|| (cstring_compare(&bind->data.name, "~or") == 0)
	|| (cstring_compare(&bind->data.name, "~bitor") == 0)
	|| (cstring_compare(&bind->data.name, "~bitxor") == 0)){
		type_ast* any = mk_lit(walk->parse->mem, INT_ANY);
		type_ast* builtin_binary = mk_func(walk->parse->mem, any, mk_func(walk->parse->mem, any, any));
		if (expected_type != NULL){
			if (type_equal(walk->parse, expected_type, builtin_binary)){
				return expected_type;
			}
		}
		return builtin_binary;
	}
	else if (cstring_compare(&bind->data.name, "~mod") == 0){
		type_ast* any = mk_lit(walk->parse->mem, INT_ANY);
		type_ast* builtin_binary = mk_func(walk->parse->mem, any, mk_func(walk->parse->mem, any, any));
		if (expected_type != NULL){
			if (type_equal(walk->parse, expected_type, builtin_binary)){
				walk_assert(expected_type->data.function.left->data.lit <= INT_ANY, 0, " %% can only be used with integral types\n");
				return expected_type;
			}
		}
		return builtin_binary;
	}
	else if ( (cstring_compare(&bind->data.name, "~not") == 0)
	|| (cstring_compare(&bind->data.name, "~bitcomp") == 0)){
		type_ast* any = mk_lit(walk->parse->mem, INT_ANY);
		type_ast* builtin_unary = mk_func(walk->parse->mem, any, any);
		if (expected_type != NULL){
			if (type_equal(walk->parse, expected_type, builtin_unary)){
				return expected_type;
			}
		}
		return builtin_unary;
	}
	return NULL;
}

uint8_t
type_equal(parser* const parse, type_ast* const left, type_ast* const right){
	token_map generics = token_map_init(parse->temp_mem);
	return type_equal_worker(parse, &generics, left, right);
}

uint8_t
type_equal_worker(parser* const parse, token_map* const generics, type_ast* const left, type_ast* const right){
	if (left->tag != right->tag){
		return 0;
	}
	switch (left->tag){
	case DEPENDENCY_TYPE:
		if (left->data.dependency.dependency_count != right->data.dependency.dependency_count){
			return 0;
		}
		for (uint64_t i = 0;i<left->data.dependency.dependency_count;++i){
			if (string_compare(&left->data.dependency.typeclass_dependencies[i].data.name, &right->data.dependency.typeclass_dependencies[i].data.name) != 0){
				return 0;
			}
			token_map_insert(generics, left->data.dependency.dependency_typenames[i].data.name, right->data.dependency.dependency_typenames[i]);
		}
		return type_equal_worker(parse, generics, left->data.dependency.type, right->data.dependency.type);
	case FUNCTION_TYPE:
		return type_equal_worker(parse, generics, left->data.function.left, right->data.function.left)
		     & type_equal_worker(parse, generics, left->data.function.right, right->data.function.right);
	case LIT_TYPE:
		if ((left->data.lit == INT_ANY && right->data.lit <= INT_ANY) || (right->data.lit == INT_ANY && left->data.lit <= INT_ANY)){
			return 1;
		}
		if (left->data.lit == F64_TYPE){
			return 1;
		}
		return (right->data.lit < left->data.lit + 1);
	case PTR_TYPE:
		return type_equal_worker(parse, generics, left->data.ptr, right->data.ptr);
	case FAT_PTR_TYPE:
		return type_equal_worker(parse, generics, left->data.fat_ptr.ptr, right->data.fat_ptr.ptr);
	case STRUCT_TYPE:
		return structure_equal(parse, generics, left->data.structure, right->data.structure);
	case NAMED_TYPE:
		token* isgeneric = token_map_access(generics, left->data.named.name.data.name);
		if (isgeneric != NULL){
			if (string_compare(&isgeneric->data.name, &right->data.named.name.data.name) != 0){
				return 0;
			}
		}
		else {
			typedef_ast** istypedef = typedef_ptr_map_access(parse->types, left->data.named.name.data.name);
			typedef_ast** isextern = typedef_ptr_map_access(parse->extern_types, left->data.named.name.data.name);
			if (istypedef != NULL){
				typedef_ast** isrighttypedef = typedef_ptr_map_access(parse->types, right->data.named.name.data.name);
				if (isrighttypedef == NULL){
					return 0;
				}
				if ((*istypedef) != (*isrighttypedef)){
					return 0;
				}
			}
			else if (isextern != NULL){
				typedef_ast** isrighttypedef = typedef_ptr_map_access(parse->extern_types, right->data.named.name.data.name);
				if (isrighttypedef == NULL){
					return 0;
				}
				if ((*isextern) != (*isrighttypedef)){
					return 0;
				}
			}
			else {
				alias_ast** isalias = alias_ptr_map_access(parse->aliases, left->data.named.name.data.name);
				if (isalias != NULL){
					alias_ast** isrightalias = alias_ptr_map_access(parse->aliases, right->data.named.name.data.name);
					if (isrightalias == NULL){
						return 0;
					}
					if ((*isalias) != (*isrightalias)){
						return 0;
					}
				}
				else {
					typedef_ast** righttypedef = typedef_ptr_map_access(parse->types, right->data.named.name.data.name);
					typedef_ast** right_extern = typedef_ptr_map_access(parse->extern_types, right->data.named.name.data.name);
					alias_ast** rightalias = alias_ptr_map_access(parse->aliases, right->data.named.name.data.name);
					if (rightalias != NULL || righttypedef != NULL || right_extern != NULL){
						return 0;
					}
					token_map_insert(generics, left->data.named.name.data.name, right->data.named.name);
				}
			}
		}
		if (left->data.named.arg_count != right->data.named.arg_count){
			return 0;
		}
		for (uint64_t i = 0;i<left->data.named.arg_count;++i){
			if (type_equal_worker(parse, generics, &left->data.named.args[i], &right->data.named.args[i]) == 0){
				return 0;
			}
		}
		return 1;
	}
	return 0;
}

uint8_t
structure_equal(parser* const parse, token_map* const generics, structure_ast* const left, structure_ast* const right){
	if (left->tag != right->tag){
		return 0;
	}
	switch (left->tag){
	case STRUCT_STRUCT:
		if (left->data.structure.count != right->data.structure.count){
			return 0;
		}
		for (uint64_t i = 0;i<left->data.structure.count;++i){
			if (type_equal_worker(parse, generics, &left->data.structure.members[i], &right->data.structure.members[i]) == 0){
				return 0;
			}
		}
		return 1;
	case UNION_STRUCT:
		if (left->data.union_structure.count != right->data.union_structure.count){
			return 0;
		}
		for (uint64_t i = 0;i<left->data.union_structure.count;++i){
			if (type_equal_worker(parse, generics, &left->data.union_structure.members[i], &right->data.union_structure.members[i]) == 0){
				return 0;
			}
		}
		return 1;
	case ENUM_STRUCT:
		if (left->data.enumeration.count != right->data.enumeration.count){
			return 0;
		}
		for (uint64_t i = 0;i<left->data.enumeration.count;++i){
			if (string_compare(&left->data.enumeration.names[i].data.name, &right->data.enumeration.names[i].data.name) != 0){
				return 0;
			}
			if (left->data.enumeration.values[i] != right->data.enumeration.values[i]){
				return 0;
			}
		}
		return 1;
	}
	return 0;
}

uint64_t
nearest_token(expr_ast* const e){
	switch (e->tag){
	case APPL_EXPR:
		return nearest_token(e->data.appl.left);
	case FAT_PTR_EXPR:
		return nearest_token(e->data.access.left);
	case STRUCT_ACCESS_EXPR:
	case ARRAY_ACCESS_EXPR:
		return nearest_token(e->data.access.left);
	case LAMBDA_EXPR:
		return nearest_token(e->data.lambda.expression);
	case BLOCK_EXPR:
		if (e->data.block.line_count > 0){
			return nearest_token(&e->data.block.lines[0]);
		}
		return 0;
	case LIT_EXPR:
		return 0;
	case TERM_EXPR:
		return e->data.term->name.index;
	case STRING_EXPR:
		return e->data.str.index;
	case LIST_EXPR:
		if (e->data.list.line_count > 0){
			return nearest_token(&e->data.list.lines[0]);
		}
		return 0;
	case STRUCT_EXPR:
		if (e->data.constructor.member_count > 0){
			return nearest_token(&e->data.constructor.members[0]);
		}
		return 0;
	case BINDING_EXPR:
		return e->data.binding.index;
	case MUTATION_EXPR:
		return nearest_token(e->data.mutation.left);
	case RETURN_EXPR:
		return nearest_token(e->data.ret);
	case SIZEOF_EXPR:
		return 0;
	case REF_EXPR:
		return nearest_token(e->data.ref);
	case DEREF_EXPR:
		return nearest_token(e->data.deref);
	case IF_EXPR:
		return nearest_token(e->data.if_statement.pred);
	case FOR_EXPR:
		return e->data.for_statement.binding.index;
	case WHILE_EXPR:
		return nearest_token(e->data.while_statement.pred);
	case MATCH_EXPR:
		return nearest_token(e->data.match.pred);
	case CAST_EXPR:
		return nearest_token(e->data.cast.source);
	case BREAK_EXPR:
	case CONTINUE_EXPR:
	case NOP_EXPR:
		return 0;
	}
	return 0;
}

type_ast*
deep_copy_type_replace(pool* const mem, clash_relation* crelation, type_ast* const source){
	type_ast_map* relation = crelation->relation;
	type_ast_map* pointer_only = crelation->pointer_only;
	type_ast* dest = pool_request(mem, sizeof(type_ast));
	*dest = *source;
	switch (source->tag){
	case DEPENDENCY_TYPE:
		for (uint64_t i = 0;i<source->data.dependency.dependency_count;++i){
			type_ast* replacement = type_ast_map_access(relation, source->data.dependency.dependency_typenames[i].data.name);
			if (replacement != NULL){
				if (replacement->tag != NAMED_TYPE){
					continue; // TODO this is testing "what if we just keep dependencies which have been fully disolved", NOTE we probably just dissolve them later
				}
				dest->data.dependency.dependency_typenames[i] = replacement->data.named.name;
			}
		}
		dest->data.dependency.type = deep_copy_type_replace(mem, crelation, source->data.dependency.type);
		return dest;
	case FUNCTION_TYPE:
		dest->data.function.left = deep_copy_type_replace(mem, crelation, source->data.function.left);
		dest->data.function.right = deep_copy_type_replace(mem, crelation, source->data.function.right);
		return dest;
	case LIT_TYPE:
		return dest;
	case PTR_TYPE:
		dest->data.ptr = deep_copy_type_replace(mem, crelation, source->data.ptr);
		return dest;
	case FAT_PTR_TYPE:
		if (dest->data.fat_ptr.ptr->tag == NAMED_TYPE){
			type_ast* replacement = type_ast_map_access(pointer_only, dest->data.fat_ptr.ptr->data.named.name.data.name);
			if (replacement != NULL){
				type_ast_map empty_relation = type_ast_map_init(mem);
				type_ast_map empty_pointer = type_ast_map_init(mem);
				clash_relation rel = {
					.relation = &empty_relation,
					.pointer_only = &empty_pointer
				};
				return deep_copy_type_replace(mem, &rel, replacement);
			}
		}
		dest->data.fat_ptr.ptr = deep_copy_type_replace(mem, crelation, source->data.fat_ptr.ptr);
		return dest;
	case STRUCT_TYPE:
		dest->data.structure = deep_copy_structure_replace(mem, crelation, source->data.structure);
		return dest;
	case NAMED_TYPE:
		type_ast* replacement = type_ast_map_access(relation, source->data.named.name.data.name);
		if (replacement == NULL){
			for (uint64_t i = 0;i<source->data.named.arg_count;++i){
				dest->data.named.args[i] = *deep_copy_type_replace(mem, crelation, &source->data.named.args[i]);
			}
			return dest;
		}
		type_ast_map empty_relation = type_ast_map_init(mem);
		type_ast_map empty_pointer = type_ast_map_init(mem);
		clash_relation rel = {
			.relation = &empty_relation,
			.pointer_only = &empty_pointer
		};
		return deep_copy_type_replace(mem, &rel, replacement);
	}
	return NULL;
}

structure_ast*
deep_copy_structure_replace(pool* const mem, clash_relation* relation, structure_ast* const source){
	structure_ast* dest = pool_request(mem, sizeof(structure_ast));
	*dest = *source;
	switch (source->tag){
	case STRUCT_STRUCT:
		for (uint64_t i = 0;i<source->data.structure.count;++i){
			dest->data.structure.members[i] = *deep_copy_type_replace(mem, relation, &source->data.structure.members[i]);
		}
		return dest;
	case UNION_STRUCT:
		for (uint64_t i = 0;i<source->data.union_structure.count;++i){
			dest->data.union_structure.members[i] = *deep_copy_type_replace(mem, relation, &source->data.union_structure.members[i]);
		}
		return dest;
	case ENUM_STRUCT:
		return dest;
	}
	return NULL;
}

type_ast*
walk_pattern(walker* const walk, pattern_ast* const pat, type_ast* expected_type){
	if (pat->tag != BINDING_PATTERN){
		expected_type = reduce_alias_and_type(walk->parse, expected_type);
		walk_assert_prop();
	}
	pat->type = expected_type;
	switch (pat->tag){
	case NAMED_PATTERN:
		push_binding(walk, walk->local_scope, &pat->data.named.name, expected_type);
		walk_assert_prop();
		return walk_pattern(walk, pat->data.named.inner, expected_type);
	case STRUCT_PATTERN:
		walk_assert(expected_type->tag == STRUCT_TYPE, nearest_pattern_token(pat), "Tried to destructure non structure type as structure pattern");
		walk_assert(expected_type->data.structure->tag == STRUCT_STRUCT, nearest_pattern_token(pat),"Tried to destructure non structure structure type in pattern destructure");
		walk_assert(pat->data.structure.count <= expected_type->data.structure->data.structure.count, nearest_pattern_token(pat), "Expected structure pattern destructure to at most match structure member count");
		for (uint64_t i = 0;i<pat->data.structure.count;++i){
			walk_pattern(walk, &pat->data.structure.members[i], &expected_type->data.structure->data.structure.members[i]);
			walk_assert_prop();
		}
		return expected_type;
	case FAT_PTR_PATTERN:
		walk_assert(expected_type->tag == FAT_PTR_TYPE, nearest_pattern_token(pat), "Expected fat pointer to destructure pattern");
		type_ast* len_type = pool_request(walk->parse->mem, sizeof(type_ast));
		len_type->tag = LIT_TYPE;
		len_type->data.lit = INT_ANY;
		walk_pattern(walk, pat->data.fat_ptr.len, len_type);
		walk_assert_prop();
		type_ast* inner_ptr = pool_request(walk->parse->mem, sizeof(type_ast));
		inner_ptr->tag = PTR_TYPE;
		inner_ptr->data.ptr = expected_type->data.fat_ptr.ptr;
		walk_pattern(walk, pat->data.fat_ptr.ptr, inner_ptr);
		return expected_type;
	case HOLE_PATTERN:
		return expected_type;
	case BINDING_PATTERN:
		if (expected_type != NULL){
			if ((expected_type->tag == STRUCT_TYPE) && (expected_type->data.structure->tag == ENUM_STRUCT)){
				for (uint64_t i = 0;i<expected_type->data.structure->data.enumeration.count;++i){
					if (string_compare(&expected_type->data.structure->data.enumeration.names[i].data.name, &pat->data.binding.data.name) == 0){
						pat->tag = LITERAL_PATTERN;
						pat->data.literal.tag = UINT_LITERAL;
						pat->data.literal.data.u = expected_type->data.structure->data.enumeration.values[i];
						return expected_type;
					}
				}
			}
		}
		push_binding(walk, walk->local_scope, &pat->data.binding, expected_type);
		walk_assert_prop();
		return expected_type;
	case LITERAL_PATTERN:
		if (expected_type != NULL){
			if ((expected_type->tag == STRUCT_TYPE) && (expected_type->data.structure->tag == ENUM_STRUCT)){
				return expected_type;
			}
		}
		walk_assert(expected_type->tag == LIT_TYPE, nearest_pattern_token(pat), "Tried to destructure non literal as literal pattern");
		return expected_type;
	case STRING_PATTERN:
		walk_assert(expected_type->tag == PTR_TYPE || expected_type->tag == FAT_PTR_TYPE, nearest_pattern_token(pat), "Tried to destructure non string type as string pattern");
		if (expected_type->tag == FAT_PTR_TYPE){
			walk_assert(expected_type->data.fat_ptr.ptr->tag == LIT_TYPE && expected_type->data.fat_ptr.ptr->data.lit == U8_TYPE, nearest_pattern_token(pat), "Destructuring a string must be from [u8] or u8^");
			return expected_type;
		}
		walk_assert(expected_type->data.ptr->tag == LIT_TYPE && expected_type->data.ptr->data.lit == U8_TYPE, nearest_pattern_token(pat), "String must be destructured from [u8] or u8^");
		return expected_type;
	case UNION_SELECTOR_PATTERN:
		walk_assert(expected_type->tag == STRUCT_TYPE, nearest_pattern_token(pat), "Expected union structure type to destructure");
		walk_assert(expected_type->data.structure->tag == UNION_STRUCT, nearest_pattern_token(pat), "Expected structure type to be union in pattern destructure");
		for (uint64_t i = 0;i<expected_type->data.structure->data.union_structure.count;++i){
			if (string_compare(&expected_type->data.structure->data.union_structure.names[i].data.name, &pat->data.union_selector.member.data.name) == 0){
				walk_pattern(walk, pat->data.union_selector.nest, &expected_type->data.structure->data.union_structure.members[i]);
				return expected_type;
			}
		}
		return NULL;
	}
	return NULL;
}

uint64_t
nearest_pattern_token(pattern_ast* const pat){
	switch (pat->tag){
	case NAMED_PATTERN:
		return pat->data.named.name.index;
	case STRUCT_PATTERN:
		if (pat->data.structure.count == 0){
			return 0;
		}
		return nearest_pattern_token(&pat->data.structure.members[0]);
	case FAT_PTR_PATTERN:
		return nearest_pattern_token(pat->data.fat_ptr.ptr);
	case HOLE_PATTERN:
		return 0;
	case BINDING_PATTERN:
		return pat->data.binding.index;
	case LITERAL_PATTERN:
		return 0;
	case STRING_PATTERN:
		return pat->data.str.index;
	case UNION_SELECTOR_PATTERN:
		return nearest_pattern_token(pat->data.union_selector.nest);
	}
	return 0;
}

type_ast* 
is_member(type_ast* const outer, expr_ast* const field){
	token* name = &field->data.binding;
	structure_ast* obj = outer->data.structure;
	switch (obj->tag){
	case STRUCT_STRUCT:
		for (uint64_t i = 0;i<obj->data.structure.count;++i){
			if (string_compare(&name->data.name, &obj->data.structure.names[i].data.name) == 0){
				return &obj->data.structure.members[i];
			}
		}
		return NULL;
	case UNION_STRUCT:
		for (uint64_t i = 0;i<obj->data.union_structure.count;++i){
			if (string_compare(&name->data.name, &obj->data.union_structure.names[i].data.name) == 0){
				return &obj->data.union_structure.members[i];
			}
		}
		return NULL;
	case ENUM_STRUCT:
		for (uint64_t i = 0;i<obj->data.enumeration.count;++i){
			if (string_compare(&name->data.name, &obj->data.enumeration.names[i].data.name) == 0){
				return outer;
			}
		}
		return NULL;
	}
	return NULL;
}

clash_relation
clash_types(parser* const parse, type_ast* const left, type_ast* const right){
	type_ast_map* relation = pool_request(parse->mem, sizeof(type_ast_map));
	*relation = type_ast_map_init(parse->mem);
	type_ast_map* pointer_only = pool_request(parse->mem, sizeof(type_ast_map));
	*pointer_only = type_ast_map_init(parse->mem);
	if (clash_types_worker(parse, relation, pointer_only, left, right) == 0){
		return (clash_relation){.relation = NULL};
	}
	clash_relation r = {
		.relation = relation,
		.pointer_only = pointer_only
	};
	return r;
}

uint8_t
clash_types_worker(parser* const parse, type_ast_map* relation, type_ast_map* pointer_only, type_ast* const left, type_ast* const right){
	if (left->tag != right->tag){
		if (left->tag == FAT_PTR_TYPE && right->tag == FUNCTION_TYPE){
			if (left->data.fat_ptr.ptr->tag == NAMED_TYPE){
				type_ast* existing_ptr = type_ast_map_access(pointer_only, left->data.fat_ptr.ptr->data.named.name.data.name);
				if (existing_ptr != NULL){
					if (type_equal(parse, existing_ptr, right) == 0){
						return 0;
					}
					return 1;
				}
				typedef_ast** istypedef = typedef_ptr_map_access(parse->types, left->data.fat_ptr.ptr->data.named.name.data.name);
				typedef_ast** isextern = typedef_ptr_map_access(parse->extern_types, left->data.fat_ptr.ptr->data.named.name.data.name);
				alias_ast** isalias = alias_ptr_map_access(parse->aliases, left->data.fat_ptr.ptr->data.named.name.data.name);
				if (istypedef != NULL || isalias != NULL || isextern != NULL){
					return 0;
				}
				type_ast_map_insert(pointer_only, left->data.fat_ptr.ptr->data.named.name.data.name, *right);
				return 1;
			}
		}
		if (left->tag != NAMED_TYPE){
			return 0;
		}
		typedef_ast** istypedef = typedef_ptr_map_access(parse->types, left->data.named.name.data.name);
		typedef_ast** isextern = typedef_ptr_map_access(parse->extern_types, left->data.named.name.data.name);
		alias_ast** isalias = alias_ptr_map_access(parse->aliases, left->data.named.name.data.name);
		if (istypedef != NULL || isalias != NULL || isextern != NULL){
			return 0;
		}
		type_ast* confirm = type_ast_map_access(relation, left->data.named.name.data.name);
		if (confirm != NULL){
			if (type_equal(parse, confirm, right) == 0){
				return 0;
			}
			return 1;
		}
		type_ast_map_insert(relation, left->data.named.name.data.name, *right);
		return 1;
	}
	switch (left->tag){
	case DEPENDENCY_TYPE:
		if (left->data.dependency.dependency_count != right->data.dependency.dependency_count){
			return 0;
		}
		for (uint64_t i = 0;i<left->data.dependency.dependency_count;++i){
			if (string_compare(&left->data.dependency.typeclass_dependencies[i].data.name, &right->data.dependency.typeclass_dependencies[i].data.name) != 0){
				return 0;
			}
			type_ast* synthetic = pool_request(parse->mem, sizeof(type_ast));
			synthetic->tag = NAMED_TYPE;
			synthetic->data.named.name = right->data.dependency.dependency_typenames[i];
			synthetic->data.named.args = NULL;
			synthetic->data.named.arg_count = 0;
			type_ast_map_insert(relation, left->data.dependency.dependency_typenames[i].data.name, *synthetic);
		}
		return clash_types_worker(parse, relation, pointer_only, left->data.dependency.type, right->data.dependency.type);
	case FUNCTION_TYPE:
		return clash_types_worker(parse, relation, pointer_only, left->data.function.left, right->data.function.left)
		     & clash_types_worker(parse, relation, pointer_only, left->data.function.right, right->data.function.right);
	case LIT_TYPE:
		if ((left->data.lit == INT_ANY && right->data.lit <= INT_ANY) || (right->data.lit == INT_ANY && left->data.lit <= INT_ANY)){
			return 1;
		}
		if (left->data.lit == F64_TYPE){
			return 1;
		}
		return (right->data.lit < left->data.lit + 1);
	case PTR_TYPE:
		return clash_types_worker(parse, relation, pointer_only, left->data.ptr, right->data.ptr);
	case FAT_PTR_TYPE:
		return clash_types_worker(parse, relation, pointer_only, left->data.fat_ptr.ptr, right->data.fat_ptr.ptr);
	case STRUCT_TYPE:
		return clash_structure_worker(parse, relation, pointer_only, left->data.structure, right->data.structure);
	case NAMED_TYPE:
		type_ast* supposed_pointer = type_ast_map_access(pointer_only, left->data.named.name.data.name);
		if (supposed_pointer != NULL){
			return 0;
		}
		type_ast* confirm = type_ast_map_access(relation, left->data.named.name.data.name);
		if (confirm != NULL){
			if (type_equal(parse, confirm, right) == 0){
				return 0;
			}
		}
		else{
			typedef_ast** istypedef = typedef_ptr_map_access(parse->types, left->data.named.name.data.name);
			typedef_ast** isextern = typedef_ptr_map_access(parse->extern_types, left->data.named.name.data.name);
			if (istypedef != NULL){
				typedef_ast** isrighttypedef = typedef_ptr_map_access(parse->types, right->data.named.name.data.name);
				if (isrighttypedef == NULL){
					return 0;
				}
				if ((*istypedef) != (*isrighttypedef)){
					return 0;
				}
			}
			else if (isextern != NULL){
				typedef_ast** isrighttypedef = typedef_ptr_map_access(parse->types, right->data.named.name.data.name);
				if (isrighttypedef == NULL){
					return 0;
				}
				if ((*isextern) != (*isrighttypedef)){
					return 0;
				}
			}
			else {
				alias_ast** isalias = alias_ptr_map_access(parse->aliases, left->data.named.name.data.name);
				if (isalias != NULL){
					alias_ast** isrightalias = alias_ptr_map_access(parse->aliases, right->data.named.name.data.name);
					if (isrightalias == NULL){
						return 0;
					}
					if ((*isalias) != (*isrightalias)){
						return 0;
					}
				}
				else {
					type_ast_map_insert(relation, left->data.named.name.data.name, *right);
				}
			}
		}
		if (left->data.named.arg_count != right->data.named.arg_count){
			return 0;
		}
		for (uint64_t i = 0;i<left->data.named.arg_count;++i){
			if (clash_types_worker(parse, relation, pointer_only, &left->data.named.args[i], &right->data.named.args[i]) == 0){
				return 0;
			}
		}
		return 1;
	}
	return 0;
}

uint8_t
clash_structure_worker(parser* const parse, type_ast_map* relation, type_ast_map* pointer_only, structure_ast* const left, structure_ast* const right){
	if (left->tag != right->tag){
		return 0;
	}
	switch (left->tag){
	case STRUCT_STRUCT:
		if (left->data.structure.count != right->data.structure.count){
			return 0;
		}
		for (uint64_t i = 0;i<left->data.structure.count;++i){
			if (clash_types_worker(parse, relation, pointer_only, &left->data.structure.members[i], &right->data.structure.members[i]) == 0){
				return 0;
			}
		}
		return 1;
	case UNION_STRUCT:
		if (left->data.union_structure.count != right->data.union_structure.count){
			return 0;
		}
		for (uint64_t i = 0;i<left->data.union_structure.count;++i){
			if (clash_types_worker(parse, relation, pointer_only, &left->data.union_structure.members[i], &right->data.union_structure.members[i]) == 0){
				return 0;
			}
		}
		return 1;
	case ENUM_STRUCT:
		if (left->data.enumeration.count != right->data.enumeration.count){
			return 0;
		}
		for (uint64_t i = 0;i<left->data.enumeration.count;++i){
			if (string_compare(&left->data.enumeration.names[i].data.name, &right->data.enumeration.names[i].data.name) != 0){
				return 0;
			}
			if (left->data.enumeration.values[i] != right->data.enumeration.values[i]){
				return 0;
			}
		}
		return 1;
	}
	return 0;
}

//NOTE these next two function assume that type checking has already occured, and that everything lines up correctly
void
clash_types_priority(walker* const walk, type_ast_map* relation, type_ast_map* pointer_only, type_ast* const left, type_ast* const right){
	if (left->tag != right->tag){
		if (left->tag == FAT_PTR_TYPE && right->tag == FUNCTION_TYPE){
			if (left->data.fat_ptr.ptr->tag == NAMED_TYPE){
				if (is_generic(walk->parse, right) == 1){
					return;
				}
				type_ast* existing_ptr = type_ast_map_access(pointer_only, left->data.fat_ptr.ptr->data.named.name.data.name);
				if (existing_ptr != NULL){
					if (is_generic(walk->parse, existing_ptr) == 1){
						type_ast_map_insert(pointer_only, left->data.fat_ptr.ptr->data.named.name.data.name, *right);
					}
					return;
				}
				typedef_ast** istypedef = typedef_ptr_map_access(walk->parse->types, left->data.fat_ptr.ptr->data.named.name.data.name);
				typedef_ast** isextern = typedef_ptr_map_access(walk->parse->extern_types, left->data.fat_ptr.ptr->data.named.name.data.name);
				alias_ast** isalias = alias_ptr_map_access(walk->parse->aliases, left->data.fat_ptr.ptr->data.named.name.data.name);
				if (istypedef != NULL || isalias != NULL || isextern != NULL){
					return;
				}
				type_ast_map_insert(pointer_only, left->data.fat_ptr.ptr->data.named.name.data.name, *right);
				return;
			}
		}
		if (left->tag != NAMED_TYPE){
			return;
		}
		if (is_generic(walk->parse, right) == 1){
			return;
		}
		typedef_ast** istypedef = typedef_ptr_map_access(walk->parse->types, left->data.named.name.data.name);
		typedef_ast** isextern = typedef_ptr_map_access(walk->parse->extern_types, left->data.named.name.data.name);
		alias_ast** isalias = alias_ptr_map_access(walk->parse->aliases, left->data.named.name.data.name);
		if (istypedef != NULL || isalias != NULL || isextern != NULL){
			return;
		}
		type_ast* confirm = type_ast_map_access(relation, left->data.named.name.data.name);
		if (confirm != NULL){
			if (is_generic(walk->parse, confirm) == 1){
				type_ast_map_insert(relation, left->data.named.name.data.name, *right);
			}
			clash_types_priority(walk, relation, pointer_only, right, confirm);
			return;
		}
		type_ast_map_insert(relation, left->data.named.name.data.name, *right);
		return;
	}
	switch (left->tag){
	case DEPENDENCY_TYPE:
		if (left->data.dependency.dependency_count != right->data.dependency.dependency_count){
			return;
		}
		for (uint64_t i = 0;i<left->data.dependency.dependency_count;++i){
			if (string_compare(&left->data.dependency.typeclass_dependencies[i].data.name, &right->data.dependency.typeclass_dependencies[i].data.name) != 0){
				return;
			}
			type_ast* synthetic = pool_request(walk->parse->mem, sizeof(type_ast));
			synthetic->tag = NAMED_TYPE;
			synthetic->data.named.name = right->data.dependency.dependency_typenames[i];
			synthetic->data.named.args = NULL;
			synthetic->data.named.arg_count = 0;
			type_ast_map_insert(relation, left->data.dependency.dependency_typenames[i].data.name, *synthetic);
		}
		clash_types_priority(walk, relation, pointer_only, left->data.dependency.type, right->data.dependency.type);
		return;
	case FUNCTION_TYPE:
		clash_types_priority(walk, relation, pointer_only, left->data.function.left, right->data.function.left);
		clash_types_priority(walk, relation, pointer_only, left->data.function.right, right->data.function.right);
		return;
	case LIT_TYPE:
		return;
	case PTR_TYPE:
		clash_types_priority(walk, relation, pointer_only, left->data.ptr, right->data.ptr);
		return;
	case FAT_PTR_TYPE:
		clash_types_priority(walk, relation, pointer_only, left->data.fat_ptr.ptr, right->data.fat_ptr.ptr);
		return;
	case STRUCT_TYPE:
		clash_structure_priority(walk, relation, pointer_only, left->data.structure, right->data.structure);
		return;
	case NAMED_TYPE:
		type_ast* supposed_pointer = type_ast_map_access(pointer_only, left->data.named.name.data.name);
		if (supposed_pointer != NULL){
			return;
		}
		type_ast* confirm = type_ast_map_access(relation, left->data.named.name.data.name);
		if (confirm != NULL){
			if (is_generic(walk->parse, confirm) == 1){
				type_ast_map_insert(relation, left->data.named.name.data.name, *right);
			}
		}
		else{
			typedef_ast** istypedef = typedef_ptr_map_access(walk->parse->types, left->data.named.name.data.name);
			typedef_ast** isextern = typedef_ptr_map_access(walk->parse->extern_types, left->data.named.name.data.name);
			if (istypedef != NULL){
				typedef_ast** isrighttypedef = typedef_ptr_map_access(walk->parse->types, right->data.named.name.data.name);
				if (isrighttypedef == NULL){
					return;
				}
				if ((*istypedef) != (*isrighttypedef)){
					return;
				}
			}
			else if (isextern != NULL){
				typedef_ast** isrighttypedef = typedef_ptr_map_access(walk->parse->types, right->data.named.name.data.name);
				if (isrighttypedef == NULL){
					return;
				}
				if ((*isextern) != (*isrighttypedef)){
					return;
				}
			}
			else {
				alias_ast** isalias = alias_ptr_map_access(walk->parse->aliases, left->data.named.name.data.name);
				if (isalias != NULL){
					alias_ast** isrightalias = alias_ptr_map_access(walk->parse->aliases, right->data.named.name.data.name);
					if (isrightalias == NULL){
						return;
					}
					if ((*isalias) != (*isrightalias)){
						return;
					}
				}
				else {
					if (is_generic(walk->parse, right) == 0){
						type_ast_map_insert(relation, left->data.named.name.data.name, *right);
					}
				}
			}
		}
		if (left->data.named.arg_count != right->data.named.arg_count){
			return;
		}
		for (uint64_t i = 0;i<left->data.named.arg_count;++i){
			clash_types_priority(walk, relation, pointer_only, &left->data.named.args[i], &right->data.named.args[i]);
		}
		return;
	}
}

void
clash_structure_priority(walker* const walk, type_ast_map* relation, type_ast_map* pointer_only, structure_ast* const left, structure_ast* const right){
	switch (left->tag){
	case STRUCT_STRUCT:
		for (uint64_t i = 0;i<left->data.structure.count;++i){
			clash_types_priority(walk, relation, pointer_only, &left->data.structure.members[i], &right->data.structure.members[i]);
		}
		return;
	case UNION_STRUCT:
		for (uint64_t i = 0;i<left->data.union_structure.count;++i){
			clash_types_priority(walk, relation, pointer_only, &left->data.union_structure.members[i], &right->data.union_structure.members[i]);
		}
		return;
	case ENUM_STRUCT:
		return;
	}
}

void
check_program(parser* const parse){
	term_ast** main_term = term_ptr_map_access(parse->terms, string_init(parse->temp_mem, "main"));
   	assert_local(main_term != NULL, , "Missing entrypoint");
	assert_local((*main_term)->type->tag == LIT_TYPE, , "Main must be integer type");
	assert_local((*main_term)->type->data.lit <= INT_ANY, , "Main must be integer type");
	scope local_scope = {
		.mem = parse->mem,
		.bindings = pool_request(parse->mem, sizeof(binding)*2),
		.binding_capacity = 2,
		.binding_count = 0
	};
	scope_ptr_stack ptrs = {
		.mem = parse->mem,
		.ptrs = pool_request(parse->mem, sizeof(uint64_t)*2),
		.capacity = 2,
		.count = 0,
		.scraped_bindings = pool_request(parse->mem, sizeof(binding_buffer)*2)
	};
	for (uint64_t i = 0;i<ptrs.capacity;++i){
		ptrs.scraped_bindings[i] = binding_buffer_init(parse->mem);
	}
	expr_stack outer_exprs = {
		.mem = parse->mem,
		.exprs = pool_request(parse->mem, sizeof(expr_ast*)*2),
		.expr_capacity = 2,
		.expr_count = 0,
		.next = NULL,
		.prev = NULL
	};
	token_stack term_stack = {
		.mem = parse->mem,
		.count = 0,
		.capacity = 2,
		.tokens = pool_request(parse->mem, sizeof(token)*2)
	};
	token_map wrappers = token_map_init(parse->mem);
	term_map_stack replacements = {
		.mem = parse->mem,
		.map = pool_request(parse->mem, sizeof(term_ast_map)*2),
		.count = 0,
		.capacity = 2
	};
	for (uint64_t i = 0;i<replacements.capacity;++i){
		replacements.map[i] = term_ast_map_init(parse->mem);
	}
	string_map struct_mono_names = string_map_init(parse->mem);
	walker walk = {
		.parse = parse,
		.local_scope = &local_scope,
		.scope_ptrs = &ptrs,
		.outer_exprs = &outer_exprs,
		.next_lambda = string_init(parse->mem, "#A"),
		.term_stack = &term_stack,
		.wrappers = &wrappers,
		.replacements = &replacements,
		.struct_mono_names = &struct_mono_names
	};
	realias_walker realias = {
		.parse = parse,
		.relations = NULL,
		.next_generic = string_init(parse->mem, "@A"),
		.generic_collection_buffer = token_buffer_init(parse->mem)
	};
	for (uint64_t i = 0;i<parse->extern_term_list.count;++i){
		assert_local(type_valid(parse, parse->extern_term_list.buffer[i].type) == 1, , "Invalid type for external term definition");
	}
	for (uint64_t i = 0;i<parse->extern_type_list.count;++i){
		assert_local(type_valid(parse, parse->extern_type_list.buffer[i].type) == 1, , "Invalid type for external type definition");
	}
	for (uint64_t i = 0;i<parse->term_list.count;++i){
		pool_empty(parse->temp_mem);
		realias_type_term(&realias, &parse->term_list.buffer[i]);
		assert_prop();
	}
	assert(realias.relations == NULL);
	pool_empty(parse->temp_mem);
	for (uint64_t i = 0;i<parse->typeclass_list.count;++i){
		typeclass_ast* class = &parse->typeclass_list.buffer[i];
		push_map_stack(&realias);
		token name = class->name;
		token generic = class->param;
		for (uint64_t t = 0;t<class->member_count;++t){
			type_ast* type = class->members[t].type;
			if (type->tag == DEPENDENCY_TYPE){
				uint8_t found = 0;
				for (uint64_t k = 0;k<type->data.dependency.dependency_count;++k){
					if (string_compare(&type->data.dependency.typeclass_dependencies[k].data.name, &name.data.name) == 0){
						if (string_compare(&type->data.dependency.dependency_typenames[k].data.name, &generic.data.name) == 0){
							found = 1;
							break;
						}
					}
				}
				if (found == 0){
					uint64_t new_count = type->data.dependency.dependency_count+1;
					token* typeclass_dependencies = pool_request(parse->mem, sizeof(token)*new_count);
					token* dependency_typenames = pool_request(parse->mem, sizeof(token)*new_count);
					for (uint64_t k = 0;k<new_count-1;++k){
						typeclass_dependencies[k] = type->data.dependency.typeclass_dependencies[k];
						dependency_typenames[k] = type->data.dependency.dependency_typenames[k];
					}
					type->data.dependency.typeclass_dependencies = typeclass_dependencies;
					type->data.dependency.dependency_typenames = dependency_typenames;
					type->data.dependency.typeclass_dependencies[new_count-1] = name;
					type->data.dependency.dependency_typenames[new_count-1] = generic;
					type->data.dependency.dependency_count = new_count;
				}
			}
			else {
				type_ast* outer = pool_request(parse->mem, sizeof(type_ast));
				outer->tag = DEPENDENCY_TYPE;
				outer->data.dependency.type = type;
				outer->data.dependency.dependency_count = 1;
				outer->data.dependency.typeclass_dependencies = pool_request(parse->mem, sizeof(token));
				outer->data.dependency.dependency_typenames = pool_request(parse->mem, sizeof(token));
				outer->data.dependency.typeclass_dependencies[0] = name;
				outer->data.dependency.dependency_typenames[0] = generic;
				class->members[t].type = outer;
			}
			realias_type_term(&realias, &class->members[i]);
		}
		pop_map_stack(&realias);
	}
	assert(realias.relations == NULL);
	pool_empty(parse->temp_mem);
	for (uint64_t i = 0;i<parse->implementation_list.count;++i){
		implementation_ast* impl = &parse->implementation_list.buffer[i];
		typeclass_ast** isclass = typeclass_ptr_map_access(parse->typeclasses, impl->typeclass.data.name);
		assert_local(isclass != NULL, , "Unable to find source typeclass for implementation attempt");
		typeclass_ast* class = *isclass;
		assert_local(impl->member_count == class->member_count, , "Implementation did not have the same number of functions as the typeclass its implementing");
		for (uint64_t t = 0;t<impl->member_count;++t){
			realias_type_term(&realias, &impl->members[t]);
			uint8_t found = 0;
			for (uint64_t k = 0;k<class->member_count;++k){
				if (string_compare(&impl->members[t].name.data.name, &class->members[k].name.data.name)){
					continue;
				}
				found = 1;
				assert_local(class->members[k].type->tag == DEPENDENCY_TYPE, , "class definition functions should have had dependencies distributed over them by now...");
				assert_local(type_equiv(&walk, impl->members[t].type, class->members[k].type->data.dependency.type) == 1, , "Type of implemented typeclass function did not match definition in typeclass");
			}
			assert_local(found == 1, , "Unable to find implemented function in source typeclass");
			term_ptr_buffer* impls = term_ptr_buffer_map_access(parse->implemented_terms, impl->members[t].name.data.name);
			if (impls == NULL){
				string locator = impl->members[i].name.data.name;
				term_ptr_buffer new = term_ptr_buffer_init(parse->mem);
				token newname = {
					.content_tag = STRING_TOKEN_TYPE,
					.tag = IDENTIFIER_TOKEN,
					.index = 0,
					.data.name = walk.next_lambda
				};
				generate_new_lambda(&walk);
				impl->members[i].name = newname;
				term_ptr_buffer_insert(&new, &impl->members[t]);
				term_ptr_buffer_map_insert(parse->implemented_terms, locator, new);
			}
			else{
				token newname = {
					.content_tag = STRING_TOKEN_TYPE,
					.tag = IDENTIFIER_TOKEN,
					.index = 0,
					.data.name = walk.next_lambda
				};
				generate_new_lambda(&walk);
				impl->members[i].name = newname;
				term_ptr_buffer_insert(impls, &impl->members[t]);
			}
		}
	}
	assert(realias.relations == NULL);
	pool_empty(parse->temp_mem);
	for (uint64_t i = 0;i<parse->implementation_list.count;++i){
		implementation_ast* impl = &parse->implementation_list.buffer[i];
		for (uint64_t t = 0;t<impl->member_count;++t){
			if (is_generic(parse, impl->members[t].type) == 1){
				continue;
			}
			uint64_t pos = walk.local_scope->binding_count;
			walk_term(&walk, &impl->members[t], NULL, 1);
			pop_binding(walk.local_scope, pos);
			assert_prop();
#ifdef DEBUG
			show_term(&impl->members[t]);
			printf("\n");
#endif
		}
	}
	for (uint64_t i = 0;i<parse->term_list.count;++i){
		pool_empty(parse->temp_mem);
		if (is_generic(parse, parse->term_list.buffer[i].type) == 1){
			continue;
		}
		uint64_t pos = walk.local_scope->binding_count;
		walk_term(&walk, &parse->term_list.buffer[i], NULL, 1);
		pop_binding(walk.local_scope, pos);
		assert_prop();
#ifdef DEBUG
		show_term(&parse->term_list.buffer[i]);
		printf("\n");
#endif
	}
#ifdef DEBUG
	printf("--------------------Transformations--------------------:\n");
#endif
	uint64_t pre_transform_limit = parse->term_list.count;
	pool_empty(parse->temp_mem);
	for (uint64_t i = 0;i<parse->implementation_list.count;++i){
		implementation_ast* impl = &parse->implementation_list.buffer[i];
		for (uint64_t t = 0;t<impl->member_count;++t){
			if (is_generic(parse, impl->members[t].type) == 1){
				continue;
			}
			pool_empty(parse->temp_mem);
			transform_term(&walk, &impl->members[t], 1);
			assert_prop();
		}
	}
	for (uint64_t i = 0;i<pre_transform_limit;++i){
		pool_empty(parse->temp_mem);
		if (is_generic(parse, parse->term_list.buffer[i].type) == 1){
			continue;
		}
		pool_empty(parse->temp_mem);
		transform_term(&walk, &parse->term_list.buffer[i], 1);
		assert_prop();
	}
	for (uint64_t i = 0;i<parse->implementation_list.count;++i){
		implementation_ast* impl = &parse->implementation_list.buffer[i];
		for (uint64_t t = 0;t<impl->member_count;++t){
			if (is_generic(parse, impl->members[t].type) == 1){
				continue;
			}
			function_to_structure_type(&walk, &impl->members[t]);
		}
	}
	for (uint64_t i = 0;i<parse->term_list.count;++i){
		pool_empty(parse->temp_mem);
		if (is_generic(parse, parse->term_list.buffer[i].type) == 1){
			continue;
		}
		function_to_structure_type(&walk, &parse->term_list.buffer[i]);
	}
	for (uint64_t i = 0;i<parse->alias_list.count;++i){
		function_to_structure_recursive(&walk, parse->alias_list.buffer[i].type);
		assert_local(type_recursive(parse, parse->alias_list.buffer[i].name, parse->alias_list.buffer[i].type) == 0, , "Detected recursive alias definition");
	}
	for (uint64_t i = 0;i<parse->type_list.count;++i){
		if (parse->type_list.buffer[i].param_count > 0){
			continue;
		}
		function_to_structure_recursive(&walk, parse->type_list.buffer[i].type);
		assert_local(type_recursive(parse, parse->type_list.buffer[i].name, parse->type_list.buffer[i].type) == 0, , "Detected recursive type definition");
	}
#ifdef DEBUG
	for (uint64_t i = 0;i<parse->alias_list.count;++i){
		show_alias(&parse->alias_list.buffer[i]);
		printf("\n");
	}
	for (uint64_t i = 0;i<parse->type_list.count;++i){
		show_typedef(&parse->type_list.buffer[i]);
		printf("\n");
	}
	for (uint64_t i = 0;i<parse->implementation_list.count;++i){
		implementation_ast* impl = &parse->implementation_list.buffer[i];
		for (uint64_t t = 0;t<impl->member_count;++t){
			show_term(&impl->members[t]);
			printf("\n");
		}
	}
	for (uint64_t i = 0;i<parse->term_list.count;++i){
		show_term(&parse->term_list.buffer[i]);
		printf("\n");
	}
#endif
}

type_ast*
deep_copy_type(walker* const walk, type_ast* const source){
	type_ast* new = pool_request(walk->parse->mem, sizeof(type_ast));
	*new = *source;
	switch (source->tag){
	case DEPENDENCY_TYPE:
		new->data.dependency.type = deep_copy_type(walk, source->data.dependency.type);
		new->data.dependency.typeclass_dependencies = pool_request(walk->parse->mem, sizeof(token)*new->data.dependency.dependency_count);
		new->data.dependency.dependency_typenames = pool_request(walk->parse->mem, sizeof(token)*new->data.dependency.dependency_count);
		for (uint64_t i = 0;i<new->data.dependency.dependency_count;++i){
			new->data.dependency.typeclass_dependencies[i] = source->data.dependency.typeclass_dependencies[i];
			new->data.dependency.dependency_typenames[i] = source->data.dependency.dependency_typenames[i];
		}
		return new;
	case FUNCTION_TYPE:
		new->data.function.left = deep_copy_type(walk, source->data.function.left);
		new->data.function.right = deep_copy_type(walk, source->data.function.right);
		return new;
	case LIT_TYPE:
		return new;
	case PTR_TYPE:
		new->data.ptr = deep_copy_type(walk, source->data.ptr);
		return new;
	case FAT_PTR_TYPE:
		new->data.fat_ptr.ptr = deep_copy_type(walk, source->data.fat_ptr.ptr);
		return new;
	case STRUCT_TYPE:
		new->data.structure = deep_copy_structure(walk, source->data.structure);
		return new;
	case NAMED_TYPE:
		for (uint64_t i = 0;i<source->data.named.arg_count;++i){
			new->data.named.args[i] = *deep_copy_type(walk, &source->data.named.args[i]);
		}
		return new;
	}
	return new;
}

void
generate_new_generic(realias_walker* const walk){
	string old = walk->next_generic;
	uint64_t i = 1;
	for (;i<old.len;++i){ // 1 because 0 is @
		if (old.str[i] < 'Z'){
			break;
		}
	}
	if (i < old.len){
		old = string_copy(walk->parse->mem, &walk->next_generic);
		for (uint64_t k = 1;k<i;++k){
			old.str[k] = 'A';
		}
		old.str[i] += 1;
	}
	else{
		old.str = pool_request(walk->parse->mem, old.len+1);
		old.len += 1;
		old.str[0] = '@';
		for (uint64_t k = 1;k<old.len;++k){
			old.str[k] = 'A';
		}
	}
	walk->next_generic = old;
}

void
generate_new_lambda(walker* const walk){
	string old = walk->next_lambda;
	uint64_t i = 1;
	for (;i<old.len;++i){ // 1 because 0 is #
		if (old.str[i] < 'Z'){
			break;
		}
	}
	if (i < old.len){
		old = string_copy(walk->parse->mem, &walk->next_lambda);
		for (uint64_t k = 1;k<i;++k){
			old.str[k] = 'A';
		}
		old.str[i] += 1;
	}
	else{
		old.str = pool_request(walk->parse->mem, old.len+1);
		old.len += 1;
		old.str[0] = '#';
		for (uint64_t k = 1;k<old.len;++k){
			old.str[k] = 'A';
		}
	}
	walk->next_lambda = old;
}

structure_ast*
deep_copy_structure(walker* const walk, structure_ast* const source){
	structure_ast* new = pool_request(walk->parse->mem, sizeof(structure_ast));
	*new = *source;
	switch (source->tag){
	case STRUCT_STRUCT:
		for (uint64_t i = 0;i<source->data.structure.count;++i){
			new->data.structure.members[i] = *deep_copy_type(walk, &source->data.structure.members[i]);
		}
		return new;
	case UNION_STRUCT:
		for (uint64_t i = 0;i<source->data.union_structure.count;++i){
			new->data.union_structure.members[i] = *deep_copy_type(walk, &source->data.union_structure.members[i]);
		}
		return new;
	case ENUM_STRUCT:
		return new;
	}
	return new;
}

uint8_t
type_valid(parser* const parse, type_ast* const type){
	switch (type->tag){
	case DEPENDENCY_TYPE:
		return type_valid(parse, type->data.dependency.type);
	case FUNCTION_TYPE:
		return type_valid(parse, type->data.function.left)
		     & type_valid(parse, type->data.function.right);
	case LIT_TYPE:
		return 1;
	case PTR_TYPE:
		return type_valid(parse, type->data.ptr);
	case FAT_PTR_TYPE:
		return type_valid(parse, type->data.fat_ptr.ptr);
	case STRUCT_TYPE:
		return struct_valid(parse, type->data.structure);
	case NAMED_TYPE:
		typedef_ast** def = typedef_ptr_map_access(parse->types, type->data.named.name.data.name);
		if (def == NULL){
			alias_ast** alias = alias_ptr_map_access(parse->aliases, type->data.named.name.data.name);
			if (alias == NULL){
				typedef_ast** ext = typedef_ptr_map_access(parse->extern_types, type->data.named.name.data.name);
				if (ext == NULL){
					return 0; // this means generics are not valid normal form types
			   }
			}
		}
		for (uint64_t i = 0;i<type->data.named.arg_count;++i){
			if (type_valid(parse, &type->data.named.args[i]) == 0){
				return 0;
			}
		}
		return 1;
	}
	return 0;
}

uint8_t
struct_valid(parser* const parse, structure_ast* const s){
	switch (s->tag){
	case STRUCT_STRUCT:
		for (uint64_t i = 0;i<s->data.structure.count;++i){
			if (type_valid(parse, &s->data.structure.members[i]) == 0){
				return 0;
			}
		}
		return 1;
	case UNION_STRUCT:
		for (uint64_t i = 0;i<s->data.union_structure.count;++i){
			if (type_valid(parse, &s->data.union_structure.members[i]) == 0){
				return 0;
			}
		}
		return 1;
	case ENUM_STRUCT:
		return 1;
	}
	return 0;
}

//NOTE the return of this function should be largely ignored for now
implementation_ast*
type_depends(walker* const walk, type_ast* const depends, type_ast* const func, type_ast* arg_outer, type_ast* const arg){
	if (depends != NULL){
		if (func->data.function.left->tag != NAMED_TYPE){
			return NULL;
		}
		for (uint64_t i = 0;i<depends->data.dependency.dependency_count;++i){
			if (string_compare(&depends->data.dependency.dependency_typenames[i].data.name, &func->data.function.left->data.named.name.data.name) != 0){
				continue;
			}
			walk_assert(arg->tag == NAMED_TYPE, 0, "Dependent argument must be a named type");
			implementation_ptr_map* implementations = implementation_ptr_map_map_access(walk->parse->implementations, arg->data.named.name.data.name);
			if (implementations == NULL){
				walk_assert(arg_outer != NULL, 0, "Generic argument did not have dependency to match function applied to it");
				uint8_t found = 0;
				for (uint64_t k = 0;k<arg_outer->data.dependency.dependency_count;++k){
					if (string_compare(&depends->data.dependency.dependency_typenames[i].data.name, &arg->data.named.name.data.name) != 0){
						continue;
					}
					found = 1;
					break;
				}
				walk_assert(found == 1, 0, "Generic argument did not match dependency of the function applied to it");
			}
			else{
				walk_assert(implementations != NULL, 0, "No implementations found for given argument type");
				implementation_ast** impl = implementation_ptr_map_access(implementations, depends->data.dependency.typeclass_dependencies[i].data.name);
				walk_assert(impl != NULL, 0, "No implementation of dependency found for given argument type");
				depends->data.dependency.dependency_count -= 1;
				for (uint64_t k = i;k<depends->data.dependency.dependency_count;++k){
					depends->data.dependency.dependency_typenames[k] = depends->data.dependency.dependency_typenames[k+1];
					depends->data.dependency.typeclass_dependencies[k] = depends->data.dependency.typeclass_dependencies[k+1];
				}
				break;
			}
		}
	}
	if (arg_outer != NULL){
		if (arg->tag != NAMED_TYPE){
			return NULL;
		}
		for (uint64_t i = 0;i<arg_outer->data.dependency.dependency_count;++i){
			if (string_compare(&arg_outer->data.dependency.dependency_typenames[i].data.name, &arg->data.named.name.data.name) != 0){
				continue;
			}
			arg_outer->data.dependency.dependency_count -= 1;
			for (uint64_t k = i;k<arg_outer->data.dependency.dependency_count;++k){
				arg_outer->data.dependency.dependency_typenames[k] = arg_outer->data.dependency.dependency_typenames[k+1];
				arg_outer->data.dependency.typeclass_dependencies[k] = arg_outer->data.dependency.typeclass_dependencies[k+1];
			}
			break;
		}
	}
	return NULL;
}

void
push_map_stack(realias_walker* const walk){
	if (walk->relations == NULL){
		walk->relations = pool_request(walk->parse->mem, sizeof(map_stack));
		walk->relations->next = NULL;
		walk->relations->prev = NULL;
		walk->relations->map = token_map_init(walk->parse->temp_mem);
		walk->relations->deps = token_buffer_map_init(walk->parse->temp_mem);
		return;
	}
	if (walk->relations->next != NULL){
		walk->relations = walk->relations->next;
		token_map_clear(&walk->relations->map);
		token_buffer_map_clear(&walk->relations->deps);
		return;
	}
	walk->relations->next = pool_request(walk->parse->mem, sizeof(map_stack));
	walk->relations->next->prev = walk->relations;
	walk->relations = walk->relations->next;
	walk->relations->next = NULL;
	walk->relations->map = token_map_init(walk->parse->temp_mem);
	walk->relations->deps = token_buffer_map_init(walk->parse->temp_mem);
}

void
pop_map_stack(realias_walker* const walk){
	if (walk->relations->prev == NULL){
		walk->relations = NULL;
		return;
	}
	walk->relations = walk->relations->prev;
}

void
realias_type_expr(realias_walker* const walk, expr_ast* const expr){
	parser* parse = walk->parse;
	switch (expr->tag){
	case APPL_EXPR:
		realias_type_expr(walk, expr->data.appl.left);
		realias_type_expr(walk, expr->data.appl.right);
		return;
	case FAT_PTR_EXPR:
		realias_type_expr(walk, expr->data.fat_ptr.left);
		realias_type_expr(walk, expr->data.fat_ptr.right);
		return;
	case STRUCT_ACCESS_EXPR:
	case ARRAY_ACCESS_EXPR:
		realias_type_expr(walk, expr->data.access.left);
		realias_type_expr(walk, expr->data.access.right);
		return;
	case LAMBDA_EXPR:
		realias_type_expr(walk, expr->data.lambda.expression);
		if (expr->data.lambda.alt != NULL){
			realias_type_expr(walk, expr->data.lambda.alt);
		}
		return;
	case BLOCK_EXPR:
		for (uint64_t i = 0;i<expr->data.block.line_count;++i){
			realias_type_expr(walk, &expr->data.block.lines[i]);
		}
		return;
	case LIT_EXPR:
		return;
	case TERM_EXPR:
		realias_type_term(walk, expr->data.term);
		return;
	case STRING_EXPR:
		return;
	case LIST_EXPR:
		for (uint64_t i = 0;i<expr->data.list.line_count;++i){
			realias_type_expr(walk, &expr->data.list.lines[i]);
		}
		return;
	case STRUCT_EXPR:
		for (uint64_t i = 0;i<expr->data.constructor.member_count;++i){
			realias_type_expr(walk, &expr->data.constructor.members[i]);
		}
		return;
	case BINDING_EXPR:
		return;
	case MUTATION_EXPR:
		realias_type_expr(walk, expr->data.mutation.left);
		realias_type_expr(walk, expr->data.mutation.right);
		return;
	case RETURN_EXPR:
		realias_type_expr(walk, expr->data.ret);
		return;
	case SIZEOF_EXPR:
		realias_type(walk, expr->data.size_type);
		assert_prop();
		return;
	case REF_EXPR:
		realias_type_expr(walk, expr->data.ref);
		return;
	case DEREF_EXPR:
		realias_type_expr(walk, expr->data.deref);
		return;
	case IF_EXPR:
		realias_type_expr(walk, expr->data.if_statement.pred);
		realias_type_expr(walk, expr->data.if_statement.cons);
		if (expr->data.if_statement.alt != NULL){
			realias_type_expr(walk, expr->data.if_statement.alt);
		}
		return;
	case FOR_EXPR:
		realias_type_expr(walk, expr->data.for_statement.initial);
		realias_type_expr(walk, expr->data.for_statement.limit);
		realias_type_expr(walk, expr->data.for_statement.cons);
		return;
	case WHILE_EXPR:
		realias_type_expr(walk, expr->data.while_statement.pred);
		realias_type_expr(walk, expr->data.while_statement.cons);
		return;
	case MATCH_EXPR:
		realias_type_expr(walk, expr->data.match.pred);
		for (uint64_t i = 0;i<expr->data.match.count;++i){
			realias_type_expr(walk, &expr->data.match.cases[i]);
		}
		return;
	case CAST_EXPR:
		realias_type(walk, expr->data.cast.target);
		assert_prop();
		return;
	case BREAK_EXPR:
	case CONTINUE_EXPR:
	case NOP_EXPR:
		return;
	}
}

void
realias_type_term(realias_walker* const walk, term_ast* const term){
	parser* parse = walk->parse;
	push_map_stack(walk);
	realias_type(walk, term->type);
	assert_prop();
	term->type = sprinkle_deps(walk, term->type);
	scrape_deps(walk, term->type);
	if (term->expression != NULL){
		realias_type_expr(walk, term->expression);
	}
	pop_map_stack(walk);
}

void
realias_type(realias_walker* const walk, type_ast* const type){
	parser* parse = walk->parse;
	switch (type->tag){
	case DEPENDENCY_TYPE:
		for (uint64_t i = 0;i<type->data.dependency.dependency_count;++i){
			token new_token = type->data.dependency.dependency_typenames[i];
			new_token.data.name = walk->next_generic;
			uint8_t dup = token_map_insert(&walk->relations->map, type->data.dependency.dependency_typenames[i].data.name, new_token);
			assert_local(dup == 0, , "Duplicate generic");
			type->data.dependency.dependency_typenames[i] = new_token;
			generate_new_generic(walk);
		}
		realias_type(walk, type->data.dependency.type);
		assert_prop();
		return;
	case FUNCTION_TYPE:
		realias_type(walk, type->data.function.left);
		assert_prop();
		realias_type(walk, type->data.function.right);
		assert_prop();
		return;
	case LIT_TYPE:
		return;
	case PTR_TYPE:
		realias_type(walk, type->data.ptr);
		assert_prop();
		return;
	case FAT_PTR_TYPE:
		realias_type(walk, type->data.fat_ptr.ptr);
		assert_prop();
		return;
	case STRUCT_TYPE:
		realias_type_structure(walk, type->data.structure);
		return;
	case NAMED_TYPE:
		typedef_ast** istype = typedef_ptr_map_access(walk->parse->types, type->data.named.name.data.name);
		if (istype == NULL){
			alias_ast** alias = alias_ptr_map_access(walk->parse->aliases, type->data.named.name.data.name);
			if (alias == NULL){
				typedef_ast** isext = typedef_ptr_map_access(walk->parse->extern_types, type->data.named.name.data.name);
				if (isext == NULL){
					map_stack* relation = walk->relations;
					uint8_t found = 0;
					while (relation != NULL){
						token* exists = token_map_access(&relation->map, type->data.named.name.data.name);
						if (exists != NULL){
							type->data.named.name = *exists;
							found = 1;
							break;
						}
						relation = relation->prev;
					}
					if (found == 0){
						token new_token = type->data.named.name;
						new_token.data.name = walk->next_generic;
						token_map_insert(&walk->relations->map, type->data.named.name.data.name, new_token);
						type->data.named.name = new_token;
						generate_new_generic(walk);
					}
				}
			}
		}
		for (uint64_t i = 0;i<type->data.named.arg_count;++i){
			realias_type(walk, &type->data.named.args[i]);
			assert_prop();
		}
		return;
	}
}

void
realias_type_structure(realias_walker* const walk, structure_ast* const s){
	parser* parse = walk->parse;
	switch (s->tag){
	case STRUCT_STRUCT:
		for (uint64_t i = 0;i<s->data.structure.count;++i){
			realias_type(walk, &s->data.structure.members[i]);
			assert_prop();
		}
		return;
	case UNION_STRUCT:
		for (uint64_t i = 0;i<s->data.union_structure.count;++i){
			realias_type(walk, &s->data.union_structure.members[i]);
			assert_prop();
		}
		return;
	case ENUM_STRUCT:
		return;
	}
}

type_ast*
sprinkle_deps(realias_walker* const walk, type_ast* term_type){
	token_buffer_clear(&walk->generic_collection_buffer);
	collect_dependencies(walk, term_type);
	uint64_t capacity = 2;
	type_ast* outer = NULL;
	for (uint64_t i = 0;i<walk->generic_collection_buffer.count;++i){
		token generic = walk->generic_collection_buffer.buffer[i];
		map_stack* relation = walk->relations;
		while (relation != NULL){
			token_buffer* names = token_buffer_map_access(&relation->deps, generic.data.name);
			relation = relation->prev;
			if (names == NULL){
				continue;
			}
			if (names->count != 0){
				if (outer == NULL){
					outer = term_type;
					if (term_type->tag != DEPENDENCY_TYPE){
						outer = pool_request(walk->parse->mem, sizeof(type_ast));
						outer->tag = DEPENDENCY_TYPE;
						outer->data.dependency.dependency_count = 0;
						outer->data.dependency.type = term_type;
						outer->data.dependency.typeclass_dependencies = pool_request(walk->parse->mem, sizeof(token)*capacity);
						outer->data.dependency.dependency_typenames = pool_request(walk->parse->mem, sizeof(token)*capacity);
					}
					else {
						capacity = outer->data.dependency.dependency_count;
					}
					term_type = outer;
				}
			}
			for (uint64_t k = 0;k<names->count;++k){
				uint8_t found = 0;
				token classname = names->buffer[k];
				for (uint64_t t = 0;t<outer->data.dependency.dependency_count;++t){
					if (string_compare(&outer->data.dependency.typeclass_dependencies[t].data.name, &classname.data.name) == 0){
						if (string_compare(&outer->data.dependency.dependency_typenames[t].data.name, &generic.data.name) == 0){
							found = 1;
							break;
						}
					}
				}
				if (found == 1){
					continue;
				}
				if (outer->data.dependency.dependency_count == capacity){
					capacity *= 2;
					token* classes = pool_request(walk->parse->mem, sizeof(token)*capacity);
					token* typenames = pool_request(walk->parse->mem, sizeof(token)*capacity);
					for (uint64_t j = 0;j<outer->data.dependency.dependency_count;++j){
						classes[j] = outer->data.dependency.typeclass_dependencies[j];
						typenames[j] = outer->data.dependency.dependency_typenames[j];
					}
					outer->data.dependency.typeclass_dependencies = classes;
					outer->data.dependency.dependency_typenames = typenames;
				}
				outer->data.dependency.typeclass_dependencies[outer->data.dependency.dependency_count] = classname;
				outer->data.dependency.dependency_typenames[outer->data.dependency.dependency_count] = generic;
				outer->data.dependency.dependency_count += 1;
			}
		}
	}
	return term_type;
}

void
collect_dependencies(realias_walker* const walk, type_ast* const type){
	switch (type->tag){
	case DEPENDENCY_TYPE:
		collect_dependencies(walk, type->data.dependency.type);
		return;
	case FUNCTION_TYPE:
		collect_dependencies(walk, type->data.function.left);
		collect_dependencies(walk, type->data.function.right);
		return;
	case LIT_TYPE:
		return;
	case PTR_TYPE:
		collect_dependencies(walk, type->data.ptr);
		return;
	case FAT_PTR_TYPE:
		collect_dependencies(walk, type->data.fat_ptr.ptr);
		return;
	case STRUCT_TYPE:
		collect_dependencies_struct(walk, type->data.structure);
		return;
	case NAMED_TYPE:
		typedef_ast** istype = typedef_ptr_map_access(walk->parse->types, type->data.named.name.data.name);
		if (istype == NULL){
			alias_ast** alias = alias_ptr_map_access(walk->parse->aliases, type->data.named.name.data.name);
			if (alias == NULL){
				typedef_ast** isext = typedef_ptr_map_access(walk->parse->extern_types, type->data.named.name.data.name);
				if (isext == NULL){
					token_buffer_insert(&walk->generic_collection_buffer, type->data.named.name);
				}
			}
		}
		for (uint64_t i = 0;i<type->data.named.arg_count;++i){
			collect_dependencies(walk, &type->data.named.args[i]);
		}
		return;
	}
}

void
collect_dependencies_struct(realias_walker* const walk, structure_ast* const s){
	switch (s->tag){
	case STRUCT_STRUCT:
		for (uint64_t i = 0;i<s->data.structure.count;++i){
			collect_dependencies(walk, &s->data.structure.members[i]);
		}
		return;
	case UNION_STRUCT:
		for (uint64_t i = 0;i<s->data.union_structure.count;++i){
			collect_dependencies(walk, &s->data.union_structure.members[i]);
		}
		return;
	case ENUM_STRUCT:
		return;
	}
}

void
scrape_deps(realias_walker* const walk, type_ast* const term_type){
	if (term_type->tag != DEPENDENCY_TYPE){
		return;
	}
	for (uint64_t i = 0;i<term_type->data.dependency.dependency_count;++i){
		token name = term_type->data.dependency.typeclass_dependencies[i];
		token generic = term_type->data.dependency.dependency_typenames[i];
		token_buffer* names = token_buffer_map_access(&walk->relations->deps, generic.data.name);
		if (names == NULL){
			token_buffer new = token_buffer_init(walk->parse->mem);
			token_buffer_insert(&new, name);
			token_buffer_map_insert(&walk->relations->deps, generic.data.name, new);
			continue;
		}
		token_buffer_insert(names, name);
	}
}

clash_relation
clash_types_equiv(walker* const walk, type_ast* const left, type_ast* const right){
	type_ast_map* relation = pool_request(walk->parse->temp_mem, sizeof(type_ast_map));
	*relation = type_ast_map_init(walk->parse->temp_mem);
	type_ast_map* pointer_only = pool_request(walk->parse->temp_mem, sizeof(type_ast_map));
	*pointer_only = type_ast_map_init(walk->parse->temp_mem);
	if (clash_types_equiv_worker(walk, relation, pointer_only, left, right) == 0){
		return (clash_relation){
			.relation = NULL,
			.pointer_only = NULL
		};
	}
	return (clash_relation){
		.relation = relation,
		.pointer_only = pointer_only
	};
}

uint8_t
clash_types_equiv_worker(walker* const walk, type_ast_map* const relation, type_ast_map* const pointer_only, type_ast* const left, type_ast* const right){
	if (left->tag == NAMED_TYPE){
		if (is_generic(walk->parse, left) == 1){
			type_ast* exists = type_ast_map_access(relation, left->data.named.name.data.name);
			if (exists != NULL){
				if (exists->tag == NAMED_TYPE){
					if (is_generic(walk->parse, exists) == 1){
						if (is_generic(walk->parse, right) == 0){
							type_ast_map_insert(relation, left->data.named.name.data.name, *right);
							return 1;
						}
					}
				}
				if (type_equiv(walk, exists, right) == 0){
					return 0;
				}
				return 1;
			}
			type_ast_map_insert(relation, left->data.named.name.data.name, *right);
		}
		return 1;
	}
	if (left->tag == FAT_PTR_TYPE){
		if (left->data.fat_ptr.ptr->tag == NAMED_TYPE){
			if (right->tag == FUNCTION_TYPE){
				if (is_generic(walk->parse, left) == 1){
					type_ast* exists = type_ast_map_access(pointer_only, left->data.named.name.data.name);
					if (exists != NULL){
						if (type_equiv(walk, exists, right) == 0){
							return 0;
						}
						return 1;
					}
					type_ast_map_insert(pointer_only, left->data.named.name.data.name, *right);
					return 1;
				}
				return 0;
			}
		}
	}
	if (left->tag != right->tag){
		if (right->tag == NAMED_TYPE){
			if (is_generic(walk->parse, right) == 1){
				return 1;
			}
		}
		return 0;
	}
	switch (left->tag){
	case DEPENDENCY_TYPE:
		if (left->data.dependency.dependency_count != right->data.dependency.dependency_count){
			return 0;
		}
		return clash_types_equiv_worker(walk, relation, pointer_only, left->data.dependency.type, right->data.dependency.type);
	case FUNCTION_TYPE:
		if (clash_types_equiv_worker(walk, relation, pointer_only, left->data.function.left, right->data.function.left) == 0){
			return 0;
		}
		return clash_types_equiv_worker(walk, relation, pointer_only, left->data.function.right, right->data.function.right);
	case LIT_TYPE:
		if ((left->data.lit == INT_ANY && right->data.lit <= INT_ANY) || (right->data.lit == INT_ANY && left->data.lit <= INT_ANY)){
			return 1;
		}
		if (left->data.lit == F64_TYPE){
			return 1;
		}
		return (right->data.lit < left->data.lit + 1);
	case PTR_TYPE:
		return clash_types_equiv_worker(walk, relation, pointer_only, left->data.ptr, right->data.ptr);
	case FAT_PTR_TYPE:
		return clash_types_equiv_worker(walk, relation, pointer_only, left->data.fat_ptr.ptr, right->data.fat_ptr.ptr);
	case STRUCT_TYPE:
		return clash_struct_equiv_worker(walk, relation, pointer_only, left->data.structure, right->data.structure);
	case NAMED_TYPE:
		type_ast* reduce_left = reduce_alias(walk->parse, left);
		type_ast* reduce_right = reduce_alias(walk->parse, right);
		if (type_equal(walk->parse, reduce_left, reduce_right) == 0){
			return 0;
		}
		if (left->data.named.arg_count != right->data.named.arg_count){
			return 0;
		}
		for (uint64_t i = 0;i<left->data.named.arg_count;++i){
			if (clash_types_equiv_worker(walk, relation, pointer_only, &left->data.named.args[i], &right->data.named.args[i]) == 0){
				return 0;
			}
		}
		return 1;
	}
	return 0;
}

uint8_t
clash_struct_equiv_worker(walker* const walk, type_ast_map* relation, type_ast_map* pointer_only, structure_ast* const left, structure_ast* const right){
	if (left->tag != right->tag){
		return 0;
	}
	switch (left->tag){
	case STRUCT_STRUCT:
		if (left->data.structure.count != right->data.structure.count){
			return 0;
		}
		for (uint64_t i = 0;i<left->data.structure.count;++i){
			if (clash_types_equiv_worker(walk, relation, pointer_only, &left->data.structure.members[i], &right->data.structure.members[i]) == 0){
				return 0;
			}
		}
		return 1;
	case UNION_STRUCT:
		if (left->data.union_structure.count != right->data.union_structure.count){
			return 0;
		}
		for (uint64_t i = 0;i<left->data.union_structure.count;++i){
			if (clash_types_equiv_worker(walk, relation, pointer_only, &left->data.union_structure.members[i], &right->data.union_structure.members[i]) == 0){
				return 0;
			}
		}
		return 1;
	case ENUM_STRUCT:
		if (left->data.enumeration.count != right->data.enumeration.count){
			return 0;
		}
		for (uint64_t i = 0;i<left->data.enumeration.count;++i){
			if (left->data.enumeration.values[i] != right->data.enumeration.values[i]){
				return 0;
			}
		}
		return 1;
	}
	return 0;
}

uint8_t
type_equiv(walker* const walk, type_ast* left, type_ast* right){
	if (left->tag == DEPENDENCY_TYPE){
		left = left->data.dependency.type;
	}
	if (right->tag == DEPENDENCY_TYPE){
		right = right->data.dependency.type;
	}
	while (type_equal(walk->parse, left, right) == 0){
		type_ast* last_left = left;
		type_ast* last_right = right;
		clash_relation rel = clash_types_equiv(walk, left, right);
		if (rel.relation == NULL){
			return 0;
		}
		left = deep_copy_type_replace(walk->parse->temp_mem, &rel, left);
		if (type_equal(walk->parse, left, last_left) == 1){
			return 1;
		}
		rel = clash_types_equiv(walk, right, left);
		if (rel.relation == NULL){
			return 0;
		}
		right = deep_copy_type_replace(walk->parse->temp_mem, &rel, right);
		if (type_equal(walk->parse, right, last_right) == 1){
			return 1;
		}
	}
	return 1;
}

uint64_t
push_scope_ptr(walker* const walk){
	uint64_t item = walk->local_scope->binding_count;
	scope_ptr_stack* stack = walk->scope_ptrs;
	if (stack->count == stack->capacity){
		stack->capacity *= 2;
		uint64_t* ptrs = pool_request(stack->mem, sizeof(uint64_t)*stack->capacity);
		binding_buffer* scrapes = pool_request(stack->mem, sizeof(binding_buffer)*stack->capacity);
		for (uint64_t i = 0;i<stack->count;++i){
			ptrs[i] = stack->ptrs[i];
			scrapes[i] = stack->scraped_bindings[i];
		}
		for (uint64_t i = stack->count;i<stack->capacity;++i){
			scrapes[i] = binding_buffer_init(walk->parse->mem);
		}
		stack->ptrs = ptrs;
		stack->scraped_bindings = scrapes;
	}
	binding_buffer_clear(&stack->scraped_bindings[stack->count]);
	stack->ptrs[stack->count] = item;
	stack->count += 1;
	return stack->count - 1;
}

void
pop_scope_ptr(walker* const walk, uint64_t pos){
	walk->scope_ptrs->count = pos;
}

void
scrape_binding(walker* const walk, binding* bind){
	if (walk->scope_ptrs->count == 0){
		return;
	}
	binding_buffer* scrape = &walk->scope_ptrs->scraped_bindings[walk->scope_ptrs->count-1];
	for (uint64_t i = 0;i<scrape->count;++i){
		binding* candidate = &scrape->buffer[i];
		if (string_compare(&candidate->name->data.name, &bind->name->data.name) == 0){
			return;
		}
	}
	binding_buffer_insert(scrape, *bind);
}

void
scrape_lower_binding(walker* const walk, binding* bind){
	if (walk->scope_ptrs->count == 0 || walk->scope_ptrs->count-1 == 0){
		return;
	}
	binding_buffer* scrape = &walk->scope_ptrs->scraped_bindings[walk->scope_ptrs->count-2];
	for (uint64_t i = 0;i<scrape->count;++i){
		binding* candidate = &scrape->buffer[i];
		if (string_compare(&candidate->name->data.name, &bind->name->data.name) == 0){
			return;
		}
	}
	binding_buffer_insert(scrape, *bind);
}

void
lift_lambda(walker* const walk, expr_ast* const expr, type_ast* const type, token newname){
	type_ast* newtype = deep_copy_type(walk, type);
	binding_buffer* scrapes = &walk->scope_ptrs->scraped_bindings[walk->scope_ptrs->count-1];
	token top_level = token_stack_top(walk->term_stack);
	if (scrapes->count != 0){
		expr_ast* alt = expr;
		while (alt != NULL){
			pattern_ast* args = pool_request(walk->parse->mem, sizeof(pattern_ast)*(scrapes->count + alt->data.lambda.arg_count));
			uint64_t index = 0;
			uint8_t found = 0;
			for (uint64_t i = 0;i<scrapes->count;++i){
				binding* bind = &scrapes->buffer[i];
				if ((top_level.data.name.len != 0) && (string_compare(&top_level.data.name, &bind->name->data.name) == 0)){
					found = 1;
					continue;
				}
				args[index].tag = BINDING_PATTERN;
				args[index].data.binding = *bind->name;
				index += 1;
			}
			for (uint64_t i = scrapes->count;i<scrapes->count+alt->data.lambda.arg_count;++i){
				args[index] = alt->data.lambda.args[i-scrapes->count];
				index += 1;
			}
			alt->data.lambda.args = args;
			alt->data.lambda.arg_count += scrapes->count - found;
			alt = alt->data.lambda.alt;
		}
		for (uint64_t i = 0;i<scrapes->count;++i){
			binding* bind = &scrapes->buffer[i];
			if ((top_level.data.name.len != 0) && (string_compare(&top_level.data.name, &bind->name->data.name) == 0)){
				continue;
			}
			type_ast* shell = pool_request(walk->parse->mem, sizeof(type_ast));
			shell->tag = FUNCTION_TYPE;
			shell->data.function.right = newtype;
			shell->data.function.left = bind->type;
			newtype = shell;
		}
	}
	term_ast* newterm = pool_request(walk->parse->mem, sizeof(term_ast));
	newterm->type = newtype;
	newterm->name = newname;
	newterm->expression = pool_request(walk->parse->mem, sizeof(expr_ast));
	*newterm->expression = *expr;
	term_ast_buffer_insert(&walk->parse->term_list, *newterm);
	term_ptr_map_insert(walk->parse->terms, newterm->name.data.name, term_ast_buffer_top(&walk->parse->term_list));
	type_ast* type_view = newtype;
	expr->tag = BINDING_EXPR;
	expr->data.binding = newname;
	expr->type = type;
	uint8_t found = 0;
	for (uint64_t i = 0;i<scrapes->count;++i){
		binding* bind = &scrapes->buffer[i];
		if ((top_level.data.name.len != 0) && (string_compare(&top_level.data.name, &bind->name->data.name) == 0)){
			found = 1;
			continue;
		}
		expr_ast* func = pool_request(walk->parse->mem, sizeof(expr_ast));
		*func = *expr;
		expr->tag = APPL_EXPR;
		expr->data.appl.left = func;
		expr->type = type_view;
		expr_ast* binding = pool_request(walk->parse->mem, sizeof(expr_ast));
		binding->tag = BINDING_EXPR;
		binding->data.binding = *bind->name;
		binding->type = type_view->data.function.left;
		expr->data.appl.right = binding;
		type_view = type_view->data.function.right;
		for (uint64_t k = 0;k<walk->local_scope->binding_count;++k){
			if (string_compare(&bind->name->data.name, &walk->local_scope->bindings[k].name->data.name) == 0){
				if (k < walk->scope_ptrs->ptrs[walk->scope_ptrs->count-2]){
					scrape_lower_binding(walk, bind);
					break;
				}
			}
		}
	}
	if (found){
		replace_recursive_reference(newterm->expression, top_level, newname);
	}
}

void
replace_recursive_reference(expr_ast* const expr, token t, token newname){
	switch (expr->tag){
	case APPL_EXPR:
		replace_recursive_reference(expr->data.appl.right, t, newname);
		replace_recursive_reference(expr->data.appl.left, t, newname);
		return;
	case LAMBDA_EXPR:
		replace_recursive_reference(expr->data.lambda.expression, t, newname);
		if (expr->data.lambda.alt != NULL){
			replace_recursive_reference(expr->data.lambda.alt, t, newname);
		}
		return;
	case BLOCK_EXPR:
		for (uint64_t i = 0;i<expr->data.block.line_count;++i){
			replace_recursive_reference(&expr->data.block.lines[i], t, newname);
		}
		return;
	case LIT_EXPR:
		return;
	case TERM_EXPR:
		replace_recursive_reference(expr->data.term->expression, t, newname);
		return;
	case STRING_EXPR:
		return;
	case LIST_EXPR:
		for (uint64_t i = 0;i<expr->data.list.line_count;++i){
			replace_recursive_reference(&expr->data.list.lines[i], t, newname);
		}
		return;
	case STRUCT_EXPR:
		for (uint64_t i = 0;i<expr->data.constructor.member_count;++i){
			replace_recursive_reference(&expr->data.constructor.members[i], t, newname);
		}
		return;
	case BINDING_EXPR:
		if (string_compare(&expr->data.binding.data.name, &t.data.name) == 0){
			expr->data.binding = newname;
		}
		return;
	case MUTATION_EXPR:
		replace_recursive_reference(expr->data.mutation.right, t, newname);
		replace_recursive_reference(expr->data.mutation.left, t, newname);
		return;
	case RETURN_EXPR:
		replace_recursive_reference(expr->data.ret, t, newname);
		return;
	case SIZEOF_EXPR:
		return;
	case REF_EXPR:
		replace_recursive_reference(expr->data.ref, t, newname);
		return;
	case DEREF_EXPR:
		replace_recursive_reference(expr->data.deref, t, newname);
		return;
	case IF_EXPR:
		replace_recursive_reference(expr->data.if_statement.pred, t, newname);
		replace_recursive_reference(expr->data.if_statement.cons, t, newname);
		if (expr->data.if_statement.alt != NULL){
			replace_recursive_reference(expr->data.if_statement.alt, t, newname);
		}
		break;
	case FOR_EXPR:
		replace_recursive_reference(expr->data.for_statement.limit, t, newname);
		replace_recursive_reference(expr->data.for_statement.cons, t, newname);
		return;
	case WHILE_EXPR:
		replace_recursive_reference(expr->data.while_statement.pred, t, newname);
		replace_recursive_reference(expr->data.while_statement.cons, t, newname);
		return;
	case MATCH_EXPR:
		replace_recursive_reference(expr->data.match.pred, t, newname);
		for (uint64_t i = 0;i<expr->data.match.count;++i){
			replace_recursive_reference(&expr->data.match.cases[i], t, newname);
		}
		return;
	case CAST_EXPR:
		replace_recursive_reference(expr->data.cast.source, t, newname);
		return;
	case BREAK_EXPR:
	case CONTINUE_EXPR:
	case NOP_EXPR:
		return;
	case STRUCT_ACCESS_EXPR:
		replace_recursive_reference(expr->data.access.right, t, newname);
		replace_recursive_reference(expr->data.access.left, t, newname);
		return;
	case ARRAY_ACCESS_EXPR:
		replace_recursive_reference(expr->data.access.right, t, newname);
		replace_recursive_reference(expr->data.access.left, t, newname);
		return;
	case FAT_PTR_EXPR:
		replace_recursive_reference(expr->data.fat_ptr.right, t, newname);
		replace_recursive_reference(expr->data.fat_ptr.left, t, newname);
		return;
	}
}

uint64_t
token_stack_push(token_stack* const stack, token t){
	if (stack->count == stack->capacity){
		stack->capacity *= 2;
		token* tokens = pool_request(stack->mem, sizeof(token)*stack->capacity);
		for (uint64_t i = 0;i<stack->count;++i){
			tokens[i] = stack->tokens[i];
		}
		stack->tokens = tokens;
	}
	stack->tokens[stack->count] = t;
	stack->count += 1;
	return stack->count - 1;
}

void
token_stack_pop(token_stack* const stack, uint64_t pos){
	stack->count = pos;
}

token
token_stack_top(token_stack* const stack){
	assert(stack->count != 0);
	return stack->tokens[stack->count-1];
}

//NOTE this function should never return NULL
//NOTE lambdas only exist at the top level at this point
//NOTE Terms encountered during this function are not the same as top level terms anymore because they will basically always be applications or simple values
//NOTE Blocks should. in the general case, be entered with newlines set to NULL, unless they are in the middle of an expression
//NOTE This function generates uninitialized expressions in the form T f;
expr_ast*
transform_expr(walker* const walk, expr_ast* const expr, uint8_t is_outer, line_relay* const newlines, uint8_t top_level_lambda){
	try_structure_monomorph(walk, expr->type);
	switch (expr->tag){
	case APPL_EXPR:
		expr_ast* root = expr;
		uint64_t arg_count = 0;
		while (root->tag == APPL_EXPR){
			root->data.appl.right = transform_expr(walk, root->data.appl.right, 0, newlines, 1);
			walk_assert_prop();
			arg_count += 1;
			root = root->data.appl.left;
		}
		try_structure_monomorph(walk, root->type);
		if (root->tag == BINDING_EXPR){
			scope_info info = in_scope_transform(walk, &root->data.binding, root->type);
			if (info.top_level == 1){
				uint64_t farg_count = 0;
				if (info.term->type->tag == DEPENDENCY_TYPE){
					info.term->type = info.term->type->data.dependency.type;
				}
				type_ast* inner = info.term->type;
				while (inner->tag == FUNCTION_TYPE){
					inner = inner->data.function.right;
					farg_count += 1;
				}
				type_ast* partial_structured = deep_copy_type(walk, info.term->type);
				type_ast* save = info.term->type;
				info.term->type = partial_structured;
				function_to_structure_type(walk, info.term);
				partial_structured = info.term->type;
				info.term->type = save;
				type_ast* converted_inner = partial_structured;
				uint64_t convert_args = 0;
				while (converted_inner->tag == FUNCTION_TYPE){
					convert_args += 1;
					converted_inner = converted_inner->data.function.right;
				}
				if (farg_count == arg_count){
					if (convert_args == arg_count){
						return expr;
					}
				}
				type_ast* full_type_copy = deep_copy_type(walk, info.term->type);
				function_to_structure_recursive(walk, full_type_copy);
				expr_ast* term_binding = mk_binding(walk->parse->mem, &info.term->name);
				token wrapper_name = create_wrapper(walk, term_binding, full_type_copy->data.ptr, convert_args, farg_count);
				expr_ast* setter = pool_request(walk->parse->mem, sizeof(expr_ast));
				setter->tag = TERM_EXPR;
				setter->data.term = pool_request(walk->parse->mem, sizeof(term_ast));
				setter->data.term->type = full_type_copy->data.ptr;
				token setter_name = {
					.content_tag = STRING_TOKEN_TYPE,
					.tag = IDENTIFIER_TOKEN,
					.index = 0,
					.data.name = walk->next_lambda
				};
				generate_new_lambda( walk);
				setter->data.term->name = setter_name;
				setter->data.term->expression = pool_request(walk->parse->mem, sizeof(expr_ast));
				expr_ast* cons = setter->data.term->expression;
				cons->tag = STRUCT_EXPR;
				cons->data.constructor.member_count = 2;
				cons->data.constructor.names = pool_request(walk->parse->mem, sizeof(token)*2);
				cons->data.constructor.members = pool_request(walk->parse->mem, sizeof(expr_ast)*2);
				cons->data.constructor.names[0].data.name = string_init(walk->parse->mem, "func");
				cons->data.constructor.members[0].tag = BINDING_EXPR;
				cons->data.constructor.members[0].data.binding = wrapper_name;
				cons->data.constructor.names[1].data.name = string_init(walk->parse->mem, "size");
				cons->data.constructor.members[1].tag = LIT_EXPR;
				cons->data.constructor.members[1].data.literal.tag = UINT_LITERAL;
				uint64_t packed_size = 0;
				for (uint64_t i = 0;i<full_type_copy->data.ptr->data.structure->data.structure.count;++i){
					packed_size += sizeof_type(walk->parse, &full_type_copy->data.ptr->data.structure->data.structure.members[i]);
				}
				cons->data.constructor.members[1].data.literal.data.u = packed_size;
				line_relay_append(newlines, setter);
				expr_ast* setter_binding = mk_binding(walk->parse->mem, &setter_name);
				root = mk_fptr_cons(walk->parse->mem,
					mk_ref(walk->parse->mem, setter_binding),
					mk_sizeof(walk->parse->mem, full_type_copy->data.ptr)
				);
				root->type = mk_fat_ptr(walk->parse->mem, mk_lit(walk->parse->mem, U8_TYPE));
			}
		}
		token mem_cpy = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = string_init(walk->parse->mem, "memcpy")
		};
		expr_ast* memcpy_binding = mk_binding(walk->parse->mem, &mem_cpy);
		token plus = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = string_init(walk->parse->mem, "~add")
		};
		expr_ast* plus_binding = mk_binding(walk->parse->mem, &plus);
		token minus = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = string_init(walk->parse->mem, "~sub")
		};
		expr_ast* minus_binding = mk_binding(walk->parse->mem, &minus);
		token len_access = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = string_init(walk->parse->mem, "len")
		};
		expr_ast* len_access_binding = mk_binding(walk->parse->mem, &len_access);
		token ptr_access = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = string_init(walk->parse->mem, "ptr")
		};
		expr_ast* ptr_access_binding = mk_binding(walk->parse->mem, &ptr_access);
		token ref_name = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = walk->next_lambda
		};
		generate_new_lambda(walk);
		expr_ast* reference = mk_term(walk->parse->mem,
			mk_fat_ptr(walk->parse->mem, mk_lit(walk->parse->mem, U8_TYPE)),
			&ref_name,
			root
		);
		expr_ast* refind_root = expr;
		while (refind_root->tag == APPL_EXPR){
			refind_root = refind_root->data.appl.left;
		}
		type_ast* refind_fargs = refind_root->type;
		uint64_t farg_count = 0;
		while (refind_fargs->tag == FUNCTION_TYPE){
			refind_fargs = refind_fargs->data.function.right;
			farg_count += 1;
		}
		expr_ast* last_reference = mk_binding(walk->parse->mem, &ref_name);
		last_reference->type = reference->type;
		line_relay_append(newlines, reference);
		expr_ast* outer_arg = expr;
		expr_ast** arg_vars = pool_request(walk->parse->temp_mem, sizeof(expr_ast*)*arg_count);
		uint64_t arg_index = 0;
		while (outer_arg->tag == APPL_EXPR){
			token arg_name = {
				.content_tag = STRING_TOKEN_TYPE,
				.tag = IDENTIFIER_TOKEN,
				.index = 0,
				.data.name = walk->next_lambda
			};
			generate_new_lambda(walk);
			expr_ast* arg_set = mk_term(walk->parse->mem,
				NULL,
				&arg_name,
				outer_arg->data.appl.right
			);
			arg_vars[arg_index] = arg_set;
			arg_index += 1;
			outer_arg = outer_arg->data.appl.left;
		}
		type_ast* current_arg_type_info = refind_root->type;
		for (uint64_t i = arg_count;i>0;--i){
			expr_ast* arg_set = arg_vars[i-1];
			arg_set->data.term->type = current_arg_type_info->data.function.left;
			expr_ast* arg_binding = mk_binding(walk->parse->mem, &arg_set->data.term->name);
			line_relay_append(newlines, arg_set);
			expr_ast* copy_arg = mk_appl(walk->parse->mem,
				mk_appl(walk->parse->mem,
					mk_appl(walk->parse->mem,
						memcpy_binding,
						mk_struct_access(walk->parse->mem,
							last_reference,
							ptr_access_binding
						)
					),
					mk_ref(walk->parse->mem, arg_binding)
				),
				mk_sizeof(walk->parse->mem, arg_set->data.term->type)
			);
			line_relay_append(newlines, copy_arg);
			token new_arg_name = {
				.content_tag = STRING_TOKEN_TYPE,
				.tag = IDENTIFIER_TOKEN,
				.index = 0,
				.data.name = walk->next_lambda
			};
			generate_new_lambda(walk);
			expr_ast* new_binding = mk_binding(walk->parse->mem, &new_arg_name);
			expr_ast* new_set = mk_term(walk->parse->mem,
				mk_fat_ptr(walk->parse->mem, mk_lit(walk->parse->mem, U8_TYPE)),
				&new_arg_name,
				mk_fptr_cons(walk->parse->mem,
					mk_appl(walk->parse->mem,
						mk_appl(walk->parse->mem,
							plus_binding,
							mk_struct_access(walk->parse->mem,
								last_reference,
								ptr_access_binding
							)
						),
						mk_sizeof(walk->parse->mem, arg_set->data.term->type)
					),
					mk_appl(walk->parse->mem,
						mk_appl(walk->parse->mem,
							minus_binding,
							mk_struct_access(walk->parse->mem,
								last_reference,
								len_access_binding
							)
						),
						mk_sizeof(walk->parse->mem, arg_set->data.term->type)
					)
				)
			);
			line_relay_append(newlines, new_set);
			type_ast* old_ref_type = last_reference->type;
			last_reference = new_binding;
			last_reference->type = old_ref_type;
			current_arg_type_info = current_arg_type_info->data.function.right;
		}
		if (arg_count < farg_count){
			return last_reference;
		}
		type_ast* converted_root = deep_copy_type(walk, refind_root->type);
		function_to_structure_recursive(walk, converted_root);
		return closure_call(walk, last_reference, newlines, &converted_root->data.ptr->data.structure->data.structure.members[converted_root->data.ptr->data.structure->data.structure.count-2]);
	case STRUCT_ACCESS_EXPR:
		expr->data.access.left = transform_expr(walk, expr->data.access.left, 0, newlines, 1);
		return expr;
	case ARRAY_ACCESS_EXPR:
		expr->data.access.left = transform_expr(walk, expr->data.access.left, 0, newlines, 1);
		walk_assert_prop();
		expr->data.access.right->data.list.lines[0] = *transform_expr(walk, &expr->data.access.right->data.list.lines[0], 0, newlines, 1);
		return expr;
	case LAMBDA_EXPR:
		if (expr->data.lambda.expression->tag != BLOCK_EXPR){
			expr_ast* block = pool_request(walk->parse->mem, sizeof(expr_ast));
			block->tag = BLOCK_EXPR;
			block->type = expr->data.lambda.expression->type;
			block->data.block.line_count = 1;
			if (expr->data.lambda.expression->tag == RETURN_EXPR){
				block->data.block.lines = expr->data.lambda.expression;
			}
			else{
				block->data.block.lines = pool_request(walk->parse->mem, sizeof(expr_ast));
				block->data.block.lines[0].tag = RETURN_EXPR;
				block->data.block.lines[0].data.ret = expr->data.lambda.expression;
			}
			expr->data.lambda.expression = block;
		}
		uint64_t scope_pos = walk->local_scope->binding_count;
		for (uint64_t i = 0;i<expr->data.lambda.arg_count;++i){
			transform_pattern(walk, &expr->data.lambda.args[i], NULL);
		}
		transform_expr(walk, expr->data.lambda.expression, 0, NULL, 1);
		walk_assert_prop();
		pop_binding(walk->local_scope, scope_pos);
		if (expr->data.lambda.alt != NULL){
			transform_expr(walk, expr->data.lambda.alt, 0, NULL, 0);
		}
		if (top_level_lambda == 1){
			destructure_lambda_patterns(walk, expr);
		}
		return expr;
	case BLOCK_EXPR:
		if (newlines == NULL){
			line_relay outer_lines = line_relay_init(walk->parse->temp_mem);
			for (uint64_t i = 0;i<expr->data.block.line_count;++i){
				line_relay linelines = line_relay_init(walk->parse->temp_mem);
				if (expr->data.block.lines[i].tag == BLOCK_EXPR
				 || expr->data.block.lines[i].tag == IF_EXPR
				 || expr->data.block.lines[i].tag == MATCH_EXPR){
					expr_ast* line = transform_expr(walk, &expr->data.block.lines[i], 0, NULL, 1);
					walk_assert_prop();
					line_relay_append(&outer_lines, line);
					continue;
				}
				expr_ast* line = transform_expr(walk, &expr->data.block.lines[i], 0, &linelines, 1);
				walk_assert_prop();
				line_relay_append(&linelines, line);
				line_relay_concat(&outer_lines, &linelines);
			}
			expr_ast* lines = pool_request(walk->parse->mem, sizeof(expr_ast)*outer_lines.len);
			line_relay_node* first = outer_lines.first;
			uint64_t index = 0;
			while (first != NULL){
				lines[index] = *first->line;
				index += 1;
				first = first->next;
			}
			expr->data.block.line_count = outer_lines.len;
			expr->data.block.lines = lines;
			return expr;
		}
		token setter_name = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = walk->next_lambda
		};
		generate_new_lambda(walk);
		expr_ast* outer_setter = mk_term(walk->parse->mem, expr->type, &setter_name, NULL);
		line_relay_append(newlines, outer_setter);
		replace_return_with_setter(walk, expr, setter_name);
		expr_ast* walked = transform_expr(walk, expr, 0, NULL, 1);
		walk_assert_prop();
		line_relay_append(newlines, walked);
		expr_ast* setter_binding = mk_binding(walk->parse->mem, &setter_name);
		return setter_binding;
	case FAT_PTR_EXPR:
		expr->data.fat_ptr.left = transform_expr(walk, expr->data.fat_ptr.left, 0, newlines, 1);
		walk_assert_prop();
		expr->data.fat_ptr.right = transform_expr(walk, expr->data.fat_ptr.right, 0, newlines, 1);
		return expr;
	case LIT_EXPR:
		return expr;
	case TERM_EXPR:
		if (is_generic(walk->parse, expr->data.term->type) == 1){
			return expr;
		}
		if (expr->data.term->type->tag == FUNCTION_TYPE || expr->data.term->type->tag == DEPENDENCY_TYPE){
			expr->data.term->type = mk_closure_type(walk->parse->mem);
		}
		else{
			function_to_structure_recursive(walk, expr->data.term->type);
		}
		uint64_t pos = push_binding(walk, walk->local_scope, &expr->data.term->name, expr->data.term->type);
		expr->data.term->expression = transform_expr(walk, expr->data.term->expression, 0, newlines, 1);
		walk_assert_prop();
		pop_binding(walk->local_scope, pos);
		return expr;
	case STRING_EXPR:
		token stringname = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = walk->next_lambda
		};
		generate_new_lambda(walk);
		expr_ast* stringcopy = pool_request(walk->parse->mem, sizeof(expr_ast));
		*stringcopy = *expr;
		expr_ast* stringterm = mk_term(walk->parse->mem, expr->type, &stringname, stringcopy);
		line_relay_append(newlines, stringterm);
		expr_ast* stringbinding = mk_binding(walk->parse->mem, &stringname);
		stringbinding->type = expr->type;
		return stringbinding;
	case LIST_EXPR:
		for (uint64_t i = 0;i<expr->data.list.line_count;++i){
			expr->data.list.lines[i] = *transform_expr(walk, &expr->data.list.lines[i], 0, newlines, 1);
			walk_assert_prop();
		}
		return expr;
	case STRUCT_EXPR: // optimization possible for term = {}, can remain the same, theres also one where a mutation decomposes to a.x = ...; a.y = ....; etc
		for (uint64_t i = 0;i<expr->data.constructor.member_count;++i){
			expr->data.constructor.members[i] = *transform_expr(walk, &expr->data.constructor.members[i], 0, newlines, 1);
			walk_assert_prop();
		}
		expr_ast* struct_wrapper = new_term(walk, expr->type, expr);
		line_relay_append(newlines, struct_wrapper);
		return term_name(walk, struct_wrapper->data.term);
	case BINDING_EXPR:
		scope_info info = in_scope_transform(walk, &expr->data.binding, expr->type);
		if (info.top_level == 1){
			uint64_t arg_count = 0;
			uint64_t farg_count = 0;
			if (info.term->type->tag == DEPENDENCY_TYPE){
				info.term->type = info.term->type->data.dependency.type;
			}
			type_ast* inner = info.term->type;
			while (inner->tag == FUNCTION_TYPE){
				inner = inner->data.function.right;
				farg_count += 1;
			}
			type_ast* partial_structured = deep_copy_type(walk, info.term->type);
			type_ast* save = info.term->type;
			info.term->type = partial_structured;
			function_to_structure_type(walk, info.term);
			partial_structured = info.term->type;
			info.term->type = save;
			type_ast* converted_inner = partial_structured;
			uint64_t convert_args = 0;
			while (converted_inner->tag == FUNCTION_TYPE){
				convert_args += 1;
				converted_inner = converted_inner->data.function.right;
			}
			if (farg_count == arg_count){
				if (convert_args == arg_count){
					return expr;
				}
			}
			type_ast* full_type_copy = deep_copy_type(walk, info.term->type);
			function_to_structure_recursive(walk, full_type_copy);
			expr_ast* term_binding = mk_binding(walk->parse->mem, &info.term->name);
			token wrapper_name = create_wrapper(walk, term_binding, full_type_copy->data.ptr, convert_args, farg_count);
			expr_ast* setter = pool_request(walk->parse->mem, sizeof(expr_ast));
			setter->tag = TERM_EXPR;
			setter->data.term = pool_request(walk->parse->mem, sizeof(term_ast));
			setter->data.term->type = full_type_copy->data.ptr;
			token setter_name = {
				.content_tag = STRING_TOKEN_TYPE,
				.tag = IDENTIFIER_TOKEN,
				.index = 0,
				.data.name = walk->next_lambda
			};
			generate_new_lambda(walk);
			setter->data.term->name = setter_name;
			setter->data.term->expression = pool_request(walk->parse->mem, sizeof(expr_ast));
			expr_ast* cons = setter->data.term->expression;
			cons->tag = STRUCT_EXPR;
			cons->data.constructor.member_count = 2;
			cons->data.constructor.names = pool_request(walk->parse->mem, sizeof(token)*2);
			cons->data.constructor.members = pool_request(walk->parse->mem, sizeof(expr_ast)*2);
			cons->data.constructor.names[0].data.name = string_init(walk->parse->mem, "func");
			cons->data.constructor.members[0].tag = BINDING_EXPR;
			cons->data.constructor.members[0].data.binding = wrapper_name;
			cons->data.constructor.names[1].data.name = string_init(walk->parse->mem, "size");
			cons->data.constructor.members[1].tag = LIT_EXPR;
			cons->data.constructor.members[1].data.literal.tag = UINT_LITERAL;
			uint64_t packed_size = 0;
			for (uint64_t i = 0;i<full_type_copy->data.ptr->data.structure->data.structure.count;++i){
				packed_size += sizeof_type(walk->parse, &full_type_copy->data.ptr->data.structure->data.structure.members[i]);
			}
			cons->data.constructor.members[1].data.literal.data.u = packed_size;
			line_relay_append(newlines, setter);
			expr_ast* setter_binding = mk_binding(walk->parse->mem, &setter_name);
			expr_ast* final_ref = mk_fptr_cons(walk->parse->mem,
				mk_ref(walk->parse->mem, setter_binding),
				mk_sizeof(walk->parse->mem, full_type_copy->data.ptr)
			);
			final_ref->type = mk_fat_ptr(walk->parse->mem, mk_lit(walk->parse->mem, U8_TYPE));
			return final_ref;
		}
		return expr;
	case MUTATION_EXPR:
		expr->data.mutation.left = transform_expr(walk, expr->data.mutation.left, 0, newlines, 1);
		walk_assert_prop();
		expr->data.mutation.right = transform_expr(walk, expr->data.mutation.right, 0, newlines, 1);
		return expr;
	case RETURN_EXPR:
		expr->data.ret = transform_expr(walk, expr->data.ret, 0, newlines, 1);
		return expr;
	case SIZEOF_EXPR:
		try_structure_monomorph(walk, expr->data.size_type);
		walk_assert(type_valid(walk->parse, expr->data.size_type) == 1, nearest_token(expr), "Type invalid in sizeof expression");
		return expr;
	case REF_EXPR:
		expr->data.ref = transform_expr(walk, expr->data.ref, 0, newlines, 1);
		return expr;
	case DEREF_EXPR:
		expr->data.deref = transform_expr(walk, expr->data.deref, 0, newlines, 1);
		return expr;
	case IF_EXPR:
		if (newlines == NULL){
			line_relay outer_lines = line_relay_init(walk->parse->temp_mem);
			expr->data.if_statement.pred = transform_expr(walk, expr->data.if_statement.pred, 0, &outer_lines, 1);
			walk_assert_prop();
			expr->data.if_statement.cons = transform_expr(walk, expr->data.if_statement.cons, 0, NULL, 1);
			walk_assert_prop();
			if (expr->data.if_statement.alt != NULL){
				expr->data.if_statement.alt = transform_expr(walk, expr->data.if_statement.alt, 0, NULL, 1);
			}
			if (outer_lines.len > 0){
				expr_ast* block = pool_request(walk->parse->mem, sizeof(expr_ast));
				block->tag = BLOCK_EXPR;
				block->data.block.line_count = 1+outer_lines.len;
				block->data.block.lines = pool_request(walk->parse->mem, sizeof(expr_ast)*block->data.block.line_count);
				line_relay_node* first = outer_lines.first;
				uint64_t index = 0;
				while (first != NULL){
					block->data.block.lines[index] = *first->line;
					index += 1;
					first = first->next;
				}
				block->data.block.lines[index] = *expr;
				*expr = *block;
			}
			return expr;
		}
		token if_setter_name = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = walk->next_lambda
		};
		generate_new_lambda(walk);
		expr_ast* if_outer_setter = mk_term(walk->parse->mem, expr->type, &if_setter_name, NULL);
		line_relay_append(newlines, if_outer_setter);
		replace_return_with_setter(walk, expr, if_setter_name);
		expr_ast* if_walked = transform_expr(walk, expr, 0, NULL, 1);
		walk_assert_prop();
		line_relay_append(newlines, if_walked);
		expr_ast* if_setter_binding = mk_binding(walk->parse->mem, &if_setter_name);
		return if_setter_binding;
	case FOR_EXPR:
		expr->data.for_statement.initial = transform_expr(walk, expr->data.for_statement.initial, 0, newlines, 1);
		walk_assert_prop();
		uint64_t for_scope_pos = push_binding(walk, walk->local_scope, &expr->data.for_statement.initial->data.binding, expr->data.for_statement.initial->type);
		expr->data.for_statement.limit = transform_expr(walk, expr->data.for_statement.limit, 0, newlines, 1);
		walk_assert_prop();
		expr->data.for_statement.cons = transform_expr(walk, expr->data.for_statement.cons, 0, NULL, 1);
		walk_assert_prop();
		pop_binding(walk->local_scope, for_scope_pos-1);
		return expr;
	case WHILE_EXPR:
		expr->data.while_statement.pred = transform_expr(walk, expr->data.while_statement.pred, 0, newlines, 1);
		walk_assert_prop();
		expr->data.while_statement.cons = transform_expr(walk, expr->data.while_statement.cons, 0, NULL, 1);
		return expr;
	case MATCH_EXPR:
		for (uint64_t i = 0;i<expr->data.match.count;++i){
			expr_ast case_expr = expr->data.match.cases[i];
			if (case_expr.tag != BLOCK_EXPR){
				expr_ast* block = pool_request(walk->parse->mem, sizeof(expr_ast));
				block->tag = BLOCK_EXPR;
				block->type = case_expr.type;
				block->data.block.line_count = 1;
				if (case_expr.tag == RETURN_EXPR){
					block->data.block.lines = pool_request(walk->parse->mem, sizeof(expr_ast));
					*block->data.block.lines = case_expr;
				}
				else{
					block->data.block.lines = pool_request(walk->parse->mem, sizeof(expr_ast));
					block->data.block.lines[0].tag = RETURN_EXPR;
					block->data.block.lines[0].data.ret = pool_request(walk->parse->mem, sizeof(expr_ast));
					*block->data.block.lines[0].data.ret = case_expr;
				}
				expr->data.match.cases[i] = *block;
			}
		}
		if (newlines == NULL){
			line_relay outer_lines = line_relay_init(walk->parse->temp_mem);
			expr->data.match.pred = transform_expr(walk, expr->data.match.pred, 0, &outer_lines, 1);
			walk_assert_prop();
			for (uint64_t i = 0;i<expr->data.match.count;++i){
				uint64_t match_scope_pos = walk->local_scope->binding_count;
				transform_pattern(walk, &expr->data.match.patterns[i], NULL);
				expr->data.match.cases[i] = *transform_expr(walk, &expr->data.match.cases[i], 0, NULL, 1);
				walk_assert_prop();
				pop_binding(walk->local_scope, match_scope_pos);
			}
			destructure_match_patterns(walk, expr);
			if (outer_lines.len != 0){
				expr_ast* block = pool_request(walk->parse->mem, sizeof(expr_ast));
				block->tag = BLOCK_EXPR;
				block->data.block.line_count = 1+outer_lines.len;
				block->data.block.lines = pool_request(walk->parse->mem, sizeof(expr_ast)*block->data.block.line_count);
				line_relay_node* first = outer_lines.first;
				uint64_t index = 0;
				while (first != NULL){
					block->data.block.lines[index] = *first->line;
					index += 1;
					first = first->next;
				}
				block->data.block.lines[index] = *expr;
				*expr = *block;
			}
			return expr;
		}
		token match_setter_name = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = walk->next_lambda
		};
		generate_new_lambda(walk);
		expr_ast* match_outer_setter = mk_term(walk->parse->mem, expr->type, &match_setter_name, NULL);
		line_relay_append(newlines, match_outer_setter);
		replace_return_with_setter(walk, expr, match_setter_name);
		expr_ast* match_walked = transform_expr(walk, expr, 0, NULL, 1);
		walk_assert_prop();
		line_relay_append(newlines, match_walked);
		expr_ast* match_setter_binding = mk_binding(walk->parse->mem, &match_setter_name);
		return match_setter_binding;
	case CAST_EXPR:
		type_ast* reduced = reduce_alias_and_type(walk->parse, expr->data.cast.target);
		if (reduced->tag == FAT_PTR_TYPE){
			type_ast* rightreduced = reduce_alias_and_type(walk->parse, expr->data.cast.source->type);
			if (rightreduced->tag == PTR_TYPE){
				expr_ast* swrapper = pool_request(walk->parse->mem, sizeof(expr_ast));
				swrapper->tag = STRUCT_EXPR;
				swrapper->type = pool_request(walk->parse->mem, sizeof(type_ast));
				swrapper->type->tag = FAT_PTR_TYPE;
				swrapper->type->data.fat_ptr.ptr = expr->data.cast.source->type;
				swrapper->data.constructor.member_count = 2;
				swrapper->data.constructor.members = pool_request(walk->parse->mem, sizeof(expr_ast)*2);
				swrapper->data.constructor.members[0] = *expr->data.cast.source;
				swrapper->data.constructor.members[1].tag = LIT_EXPR;
				swrapper->data.constructor.members[1].data.literal.tag = UINT_LITERAL;
				if (expr->data.cast.source->tag == STRING_EXPR){
					swrapper->data.constructor.members[1].data.literal.data.u = expr->data.cast.source->data.str.data.name.len;
				}
				else if (expr->data.cast.source->tag == LIST_EXPR){
					swrapper->data.constructor.members[1].data.literal.data.u = expr->data.cast.source->data.list.line_count;
				}
				else{
					swrapper->data.constructor.members[1].data.literal.data.u = 1;
				}
				swrapper->data.constructor.names = pool_request(walk->parse->mem, sizeof(token)*2);
				token ptrname = {
					.content_tag = STRING_TOKEN_TYPE,
					.tag = IDENTIFIER_TOKEN,
					.index = 0,
					.data.name = string_init(walk->parse->mem, "ptr")
				};
				token lenname = {
					.content_tag = STRING_TOKEN_TYPE,
					.tag = IDENTIFIER_TOKEN,
					.index = 0,
					.data.name = string_init(walk->parse->mem, "len")
				};
				swrapper->data.constructor.names[0] = ptrname;
				swrapper->data.constructor.names[1] = lenname;
				expr->data.cast.source = swrapper;
			}
		}
		expr->data.cast.source = transform_expr(walk, expr->data.cast.source, 0, newlines, 1);
		walk_assert_prop();
		token termname = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = walk->next_lambda
		};
		generate_new_lambda(walk);
		expr_ast* newterm = mk_term(walk->parse->mem, expr->data.cast.target, &termname, NULL);
		line_relay_append(newlines, newterm);
		expr_ast* termbinding = mk_binding(walk->parse->mem, &termname);
		token cast_mem_cpy = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = string_init(walk->parse->mem, "memcpy")
		};
		expr_ast* cast_memcpy_binding = mk_binding(walk->parse->mem, &cast_mem_cpy);
		expr_ast* actual_cast_op = mk_appl(walk->parse->mem,
			mk_appl(walk->parse->mem,
				mk_appl(walk->parse->mem,
					cast_memcpy_binding,
					mk_ref(walk->parse->mem, termbinding)
				),
				mk_ref(walk->parse->mem, expr->data.cast.source)
			),
			mk_sizeof(walk->parse->mem, expr->data.cast.target)
		);
		line_relay_append(newlines, actual_cast_op);
		try_structure_monomorph(walk, expr->data.cast.target);
		walk_assert(type_valid(walk->parse, expr->data.cast.target) == 1, nearest_token(expr), "Cast target type invalid");
		return termbinding;
	case BREAK_EXPR:
		return expr;
	case CONTINUE_EXPR:
		return expr;
	case NOP_EXPR:
		return expr;
	}
	return expr;
}

void
transform_term(walker* const walk, term_ast* const term, uint8_t is_outer){
	uint64_t scope_pos = walk->local_scope->binding_count;
	if (term->type->tag != FUNCTION_TYPE){
		expr_ast* block = pool_request(walk->parse->mem, sizeof(expr_ast));
		block->tag = BLOCK_EXPR;
		block->data.block.line_count = 1;
		block->data.block.lines = mk_return(walk->parse->mem, term->expression);
		term->expression = block;
	}
	transform_expr(walk, term->expression, is_outer, NULL, 1);
	pop_binding(walk->local_scope, scope_pos);
}

void
transform_pattern(walker* const walk, pattern_ast* const pat, line_relay* const newlines){
	switch (pat->tag){
	case NAMED_PATTERN:
		push_binding(walk, walk->local_scope, &pat->data.named.name, pat->type);
		transform_pattern(walk, pat->data.named.inner, newlines);
		return;
	case STRUCT_PATTERN:
		for (uint64_t i = 0;i<pat->data.structure.count;++i){
			transform_pattern(walk, &pat->data.structure.members[i], newlines);
		}
		return;
	case FAT_PTR_PATTERN:
		transform_pattern(walk, pat->data.fat_ptr.ptr, newlines);
		transform_pattern(walk, pat->data.fat_ptr.len, newlines);
		return;
	case HOLE_PATTERN:
		return;
	case BINDING_PATTERN:
		push_binding(walk, walk->local_scope, &pat->data.binding, pat->type);
		return;
	case LITERAL_PATTERN:
		return;
	case STRING_PATTERN:
		return;
	case UNION_SELECTOR_PATTERN:
		transform_pattern(walk, pat->data.union_selector.nest, newlines);
		return;
	}
}

expr_ast*
new_term(walker* const walk, type_ast* const type, expr_ast* const expression){
	term_ast* term = pool_request(walk->parse->mem, sizeof(term_ast));
	term->type = type;
	term->expression = expression;
	token newname = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = walk->next_lambda
	};
	generate_new_lambda(walk);
	term->name = newname;
	expr_ast* wrapper = pool_request(walk->parse->mem, sizeof(expr_ast));
	wrapper->type = type;
	wrapper->tag = TERM_EXPR;
	wrapper->data.term = term;
	return wrapper;
}

expr_ast*
term_name(walker* const walk, term_ast* const term){
	expr_ast* bind = pool_request(walk->parse->mem, sizeof(expr_ast));
	bind->tag = BINDING_EXPR;
	bind->data.binding = term->name;
	bind->type = term->type;
	return bind;
}

//NOTE we begin dissolving dependencies here
void
function_to_structure_type(walker* const walk, term_ast* const term){
	if (term->type->tag != FUNCTION_TYPE && term->type->tag != DEPENDENCY_TYPE){
		return;
	}
	if (term->type->tag == DEPENDENCY_TYPE){
		term->type = term->type->data.dependency.type;
	}
	type_ast* focus = term->type;
	if (term->expression == NULL){
		return;
	}
	if (term->expression->tag == LAMBDA_EXPR){
		uint64_t arg_c = term->expression->data.lambda.arg_count;
		while (arg_c > 0){
			function_to_closure_ptr_recursive(walk, focus->data.function.left);
			focus = focus->data.function.right;
			arg_c -= 1;
		}
	}
	function_to_closure_ptr_recursive(walk, focus);
}

//NOTE we begin dissolving dependencies here
void
function_to_structure_recursive(walker* const walk, type_ast* const type){
	switch (type->tag){
	case DEPENDENCY_TYPE:
		*type = *type->data.dependency.type;
	case FUNCTION_TYPE:
		type_ast old = *type;
		type_ast* counter = type;
		uint64_t member_count = 2;
		while (counter->tag == FUNCTION_TYPE){
			counter = counter->data.function.right;
			member_count += 1;
		}
		counter = &old;
		type->tag = STRUCT_TYPE;
		type->data.structure = pool_request(walk->parse->mem, sizeof(structure_ast));
		structure_ast* s = type->data.structure;
		s->tag = STRUCT_STRUCT;
		s->data.structure.packed = 1;
		s->data.structure.names = pool_request(walk->parse->mem, sizeof(token)*member_count);
		s->data.structure.members = pool_request(walk->parse->mem, sizeof(type_ast)*member_count);
		s->data.structure.count = member_count;
		uint64_t member_index = 0;
		while (counter->tag == FUNCTION_TYPE){
			function_to_closure_ptr_recursive(walk, counter->data.function.left);
			s->data.structure.members[member_index] = *counter->data.function.left;
			s->data.structure.members[member_index].variable = 1;
			s->data.structure.names[member_index].data.name = string_init(walk->parse->mem, "arg_n");
			s->data.structure.names[member_index].data.name.str[4] = ((member_count-3)-member_index)+48;
			member_index += 1;
			counter = counter->data.function.right;
		}
		assert(member_index == member_count-2);
		type_ast* func_type = &s->data.structure.members[member_index];
		s->data.structure.names[member_index].data.name = string_init(walk->parse->mem, "func");
		member_index += 1;
		type_ast* size_type = &s->data.structure.members[member_index];
		s->data.structure.names[member_index].data.name = string_init(walk->parse->mem, "size");
		member_index += 1;
		func_type->tag = FUNCTION_TYPE;
		type_ast* u8ptr = pool_request(walk->parse->mem, sizeof(type_ast));
		u8ptr->tag = PTR_TYPE;
		u8ptr->data.ptr = pool_request(walk->parse->mem, sizeof(type_ast));
		u8ptr->data.ptr->tag = LIT_TYPE;
		u8ptr->data.ptr->data.lit = U8_TYPE;
		func_type->data.function.left = u8ptr;
		func_type->data.function.right = counter;
		size_type->tag = LIT_TYPE;
		size_type->data.lit = U64_TYPE;
		type_ast* in_wrap = pool_request(walk->parse->mem, sizeof(type_ast));
		*in_wrap = *type;
		type->tag = PTR_TYPE;
		type->data.ptr = in_wrap;
		return;
	case LIT_TYPE:
		return;
	case PTR_TYPE:
		function_to_closure_ptr_recursive(walk, type->data.ptr);
		return;
	case FAT_PTR_TYPE:
		function_to_closure_ptr_recursive(walk, type->data.fat_ptr.ptr);
		return;
	case STRUCT_TYPE:
		structure_function_to_closure_ptr_recursive(walk, type->data.structure);
		return;
	case NAMED_TYPE:
		for (uint64_t i = 0;i<type->data.named.arg_count;++i){
			function_to_closure_ptr_recursive(walk, &type->data.named.args[i]);
		}
		return;
	}
}

//NOTE we begin dissolving dependencies here
void
function_to_closure_ptr_recursive(walker* const walk, type_ast* const type){
	switch (type->tag){
	case DEPENDENCY_TYPE:
		*type = *type->data.dependency.type;
	case FUNCTION_TYPE:
		*type = *mk_closure_type(walk->parse->mem);
		return;
	case LIT_TYPE:
		return;
	case PTR_TYPE:
		function_to_closure_ptr_recursive(walk, type->data.ptr);
		return;
	case FAT_PTR_TYPE:
		function_to_closure_ptr_recursive(walk, type->data.fat_ptr.ptr);
		return;
	case STRUCT_TYPE:
		structure_function_to_closure_ptr_recursive(walk, type->data.structure);
		return;
	case NAMED_TYPE:
		for (uint64_t i = 0;i<type->data.named.arg_count;++i){
			function_to_closure_ptr_recursive(walk, &type->data.named.args[i]);
		}
		return;
	}
}

void
structure_function_to_closure_ptr_recursive(walker* const walk, structure_ast* const s){
	switch (s->tag){
	case STRUCT_STRUCT:
		for (uint64_t i = 0;i<s->data.structure.count;++i){
			function_to_closure_ptr_recursive(walk, &s->data.structure.members[i]);
		}
		return;
	case UNION_STRUCT:
		for (uint64_t i = 0;i<s->data.union_structure.count;++i){
			function_to_closure_ptr_recursive(walk, &s->data.union_structure.members[i]);
		}
		return;
	case ENUM_STRUCT:
		return;
	}
}

uint64_t
sizeof_type(parser* const parse, type_ast* const type){
	switch (type->tag){
	case DEPENDENCY_TYPE:
		return sizeof_type(parse, type->data.dependency.type);
	case FUNCTION_TYPE:
		return 8;
	case LIT_TYPE:
		if (type->data.lit == U8_TYPE) return 1;
		if (type->data.lit == U16_TYPE) return 2;
		if (type->data.lit == U32_TYPE) return 4;
		if (type->data.lit == U64_TYPE) return 8;
		if (type->data.lit == I8_TYPE) return 1;
		if (type->data.lit == I16_TYPE) return 2;
		if (type->data.lit == I32_TYPE) return 4;
		if (type->data.lit == I64_TYPE) return 8;
		if (type->data.lit == F32_TYPE) return 4;
		if (type->data.lit == F64_TYPE) return 8;
		return 8;
	case PTR_TYPE:
		return 8;
	case FAT_PTR_TYPE:
		return 16;
	case STRUCT_TYPE:
		return sizeof_struct(parse, type->data.structure);
	case NAMED_TYPE:
		return sizeof_type(parse, reduce_alias_and_type(parse, type));
	}
	return 0;
}

uint64_t
sizeof_struct(parser* const parse, structure_ast* const s){
	switch (s->tag){
	case STRUCT_STRUCT:
		uint64_t sum = 0;
		uint64_t padding = 0;
		for (uint64_t i = 0;i<s->data.structure.count;++i){
			uint64_t size = sizeof_type(parse, &s->data.structure.members[i]);
			if (padding == 0){
				padding = size;
				sum += size;
				continue;
			}
			if (sum % padding != 0){
				if (size >= padding){
					sum += padding - (sum % padding);
				}
			}
			if (size > padding){
				padding = size;
			}
			sum += size;
		}
		return sum;
	case UNION_STRUCT:
		uint64_t largest = 0;
		for (uint64_t i = 0;i<s->data.union_structure.count;++i){
			uint64_t size = sizeof_type(parse, &s->data.union_structure.members[i]);
			if (size > largest){
				largest = size;
			}
		}
		return largest;
	case ENUM_STRUCT:
		uint64_t highest_val = 0;
		for (uint64_t i = 0;i<s->data.enumeration.count;++i){
			if (s->data.enumeration.values[i] > highest_val){
				highest_val = s->data.enumeration.values[i];
			}
		}
		if (highest_val <= (1<<7)) return 1;
		if (highest_val <= (1<<15)) return 2;
		if (highest_val <= (1<<31)) return 4;
		return 8;
	}
	return 0;
}

uint8_t
type_recursive(parser* const parse, token name, type_ast* const type){
	switch (type->tag){
	case DEPENDENCY_TYPE:
		return type_recursive(parse, name, type->data.dependency.type);
	case FUNCTION_TYPE:
	case LIT_TYPE:
	case PTR_TYPE:
	case FAT_PTR_TYPE:
		return 0;
	case STRUCT_TYPE:
		return type_recursive_struct(parse, name, type->data.structure);
	case NAMED_TYPE:
		if (string_compare(&name.data.name, &type->data.named.name.data.name) == 0){
			return 1;
		}
		type_ast* reduced = reduce_alias_and_type(parse, type);
		return type_recursive(parse, name, reduced);
	}
	return 0;
}

uint8_t
type_recursive_struct(parser* const parse, token name, structure_ast* const s){
	switch (s->tag){
	case STRUCT_STRUCT:
		for (uint64_t i = 0;i<s->data.structure.count;++i){
			if (type_recursive(parse, name, &s->data.structure.members[i]) == 1){
				return 1;
			}
		}
		return 0;
	case UNION_STRUCT:
		for (uint64_t i = 0;i<s->data.union_structure.count;++i){
			if (type_recursive(parse, name, &s->data.union_structure.members[i]) == 1){
				return 1;
			}
		}
		return 0;
	case ENUM_STRUCT:
		return 0;
	}
	return 0;
}

line_relay
line_relay_init(pool* const mem){
	line_relay r = {
		.mem = mem,
		.first = NULL,
		.last = NULL,
		.len = 0
	};
	return r;
}

void
line_relay_append(line_relay* const lines, expr_ast* const line){
	line_relay_node* node = pool_request(lines->mem, sizeof(line_relay_node));
	node->line = line;
	node->next = NULL;
	if (lines->first == NULL){
		lines->first = node;
		lines->last = node;
		lines->len += 1;
		return;
	}
	line_relay_node* last = lines->last;
	lines->last = node;
	last->next = node;
	lines->len += 1;
}

void
line_relay_concat(line_relay* const left, line_relay* const right){
	if (left->first == NULL){
		*left = *right;
		return;
	}
	if (right->first == NULL){
		return;
	}
	left->last->next = right->first;
	left->last = right->last;
	left->len += right->len;
}

// NOTE doing it this way means we need to transform term types as we go, before we add them to the scope
scope_info
in_scope_transform(walker* const walk, token* const bind, type_ast* expected_type){
	if (expected_type != NULL){
		expected_type = reduce_alias(walk->parse, expected_type);
	}
	term_ast** term = term_ptr_map_access(walk->parse->terms, bind->data.name);
	if (term != NULL){
		scope_info ret = {
			.top_level = 1,
			.term = *term
		};
		return ret;
	}
	term = term_ptr_map_access(walk->parse->extern_terms, bind->data.name);
	if (term != NULL){
		scope_info ret = {
			.top_level = 1,
			.term = *term
		};
		return ret;
	}
	uint64_t* value = uint64_t_map_access(walk->parse->enumerated_values, bind->data.name);
	if (value != NULL){
		if (expected_type != NULL){
			if ((expected_type->tag == STRUCT_TYPE) && (expected_type->data.structure->tag == ENUM_STRUCT)){
				for (uint64_t i = 0;i<expected_type->data.structure->data.enumeration.count;++i){
					if (string_compare(&expected_type->data.structure->data.enumeration.names[i].data.name, &bind->data.name) == 0){
						scope_info ret = {
							.top_level = 0,
							.term = NULL,
						};
						return ret;
					}
				}
			}
		}
		type_ast* any = pool_request(walk->parse->mem, sizeof(type_ast));
		any->tag = LIT_TYPE;
		any->data.lit = INT_ANY;
		scope_info ret = {
			.top_level = 0,
			.term = NULL
		};
		return ret;
	}
	for (uint64_t i = 0;i<walk->local_scope->binding_count;++i){
		if (string_compare(&bind->data.name, &walk->local_scope->bindings[i].name->data.name) == 0){
			if (i < walk->scope_ptrs->ptrs[walk->scope_ptrs->count-1]){
				scrape_binding(walk, &walk->local_scope->bindings[i]);
			}
			scope_info ret = {
				.top_level = 0,
				.term = NULL
			};
			return ret;
		}
	}
	term_ptr_buffer* poly_funcs = term_ptr_buffer_map_access(walk->parse->implemented_terms, bind->data.name);
	if (poly_funcs != NULL){
		for (uint64_t i = 0;i<poly_funcs->count;++i){
			term_ast* term = poly_funcs->buffer[i];
			type_ast* type = term->type;
			if (expected_type == NULL){
				uint64_t index = walk->outer_exprs->expr_count-1;
				uint8_t broke = 0;
				while (type->tag == FUNCTION_TYPE){
					expr_ast* arg = walk->outer_exprs->exprs[index];
					type_ast* candidate = walk_expr(walk, arg, NULL, NULL, 0);
					if (candidate == NULL){
						broke = 1;
						break;
					}
					if (type_equal(walk->parse, candidate, type->data.function.left) == 0){
						broke = 1;
						break;
					}
					type = type->data.function.right;
					if (index == 0){
						break;
					}
				}
				if (broke == 0){
					scope_info ret = {
						.top_level = 1,
						.term = term
					};
					return ret;
				}
			}
			else{
				if (type_equal(walk->parse, expected_type, type) == 1){
					scope_info ret = {
						.top_level = 1,
						.term = term
					};
					return ret;
				}
			}
		}
	}
	scope_info ret = {
		.top_level = 0,
		.term = NULL
	};
	return ret;
}

expr_ast*
mk_appl(pool* const mem, expr_ast* const left, expr_ast* const right){
	expr_ast* appl = pool_request(mem, sizeof(expr_ast));
	appl->tag = APPL_EXPR;
	appl->data.appl.left = left;
	appl->data.appl.right = right;
	return appl;
}

expr_ast*
mk_struct_access(pool* const mem, expr_ast* const left, expr_ast* const right){
	expr_ast* appl = pool_request(mem, sizeof(expr_ast));
	appl->tag = STRUCT_ACCESS_EXPR;
	appl->data.appl.left = left;
	appl->data.appl.right = right;
	return appl;
}

expr_ast*
mk_ref(pool* const mem, expr_ast* const inner){
	expr_ast* ref = pool_request(mem, sizeof(expr_ast));
	ref->tag = REF_EXPR;
	ref->data.ref = inner;
	return ref;
}

expr_ast*
mk_cast(pool* const mem, expr_ast* const source, type_ast* const target){
	expr_ast* cast = pool_request(mem, sizeof(expr_ast));
	cast->tag = CAST_EXPR;
	cast->data.cast.target = target;
	cast->data.cast.source = source;
	return cast;
}

expr_ast*
mk_binding(pool* const mem, token* const tok){
	expr_ast* bind = pool_request(mem, sizeof(expr_ast));
	bind->tag = BINDING_EXPR;
	bind->data.binding = *tok;
	return bind;
}

expr_ast*
mk_term(pool* const mem, type_ast* const type, token* const name, expr_ast* const expr){
	expr_ast* term = pool_request(mem, sizeof(expr_ast));
	term->tag = TERM_EXPR;
	term->type = type;
	term->data.term = pool_request(mem, sizeof(term_ast));
	term->data.term->name = *name;
	term->data.term->type = type;
	term->data.term->expression = expr;
	return term;
}

expr_ast*
mk_mutation(pool* const mem, expr_ast* const left, expr_ast* const right){
	expr_ast* mut = pool_request(mem, sizeof(expr_ast));
	mut->tag = MUTATION_EXPR;
	mut->type = left->type;
	mut->data.mutation.left = left;
	mut->data.mutation.right = right;
	return mut;
}

expr_ast*
mk_return(pool* const mem, expr_ast* const expr){
	expr_ast* ret = pool_request(mem, sizeof(expr_ast));
	ret->tag = RETURN_EXPR;
	ret->data.ret = expr;
	return ret;
}

expr_ast*
mk_sizeof(pool* const mem, type_ast* const type){
	expr_ast* size = pool_request(mem, sizeof(expr_ast));
	size->tag = SIZEOF_EXPR;
	size->data.size_type = type;
	return size;
}

type_ast*
mk_func(pool* const mem, type_ast* const left, type_ast* const right){
	type_ast* func = pool_request(mem, sizeof(type_ast));
	func->tag = FUNCTION_TYPE;
	func->data.function.left = left;
	func->data.function.right = right;
	return func;
}

type_ast*
mk_lit(pool* const mem, uint8_t val){
	type_ast* lit = pool_request(mem, sizeof(type_ast));
	lit->tag = LIT_TYPE;
	lit->data.lit = val;
	return lit;
}

type_ast*
mk_ptr(pool* const mem, type_ast* const inner){
	type_ast* ptr = pool_request(mem, sizeof(type_ast));
	ptr->tag = PTR_TYPE;
	ptr->data.ptr = inner;
	return ptr;
}

expr_ast*
mk_fptr_cons(pool* const mem, expr_ast* left, expr_ast* right){
	expr_ast* fptr = pool_request(mem, sizeof(expr_ast));
	fptr->tag = FAT_PTR_EXPR;
	fptr->data.fat_ptr.left = left;
	fptr->data.fat_ptr.right = right;
	return fptr;
}

type_ast*
mk_fat_ptr(pool* const mem, type_ast* val){
	type_ast* fptr = pool_request(mem, sizeof(type_ast));
	fptr->tag = FAT_PTR_TYPE;
	fptr->data.fat_ptr.ptr = val;
	return fptr;
}

//NOTE assumed input_binding is a fat pointer to the function pointer of a closure
//NOTE result_type is the type of the function pointer at input_binding
expr_ast*
closure_call(walker* const walk, expr_ast* input_binding, line_relay* const newlines, type_ast* const result_type){
	token mem_cpy = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = string_init(walk->parse->mem, "memcpy")
	};
	token plus = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = string_init(walk->parse->mem, "~add")
	};
	token minus = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = string_init(walk->parse->mem, "~sub")
	};
	token ptr_accessor_name = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = string_init(walk->parse->mem, "ptr")
	};
	expr_ast* memcpy_binding = mk_binding(walk->parse->mem, &mem_cpy);
	expr_ast* plus_binding = mk_binding(walk->parse->mem, &plus);
	expr_ast* minus_binding = mk_binding(walk->parse->mem, &minus);
	expr_ast* ptr_accessor_binding = mk_binding(walk->parse->mem, &ptr_accessor_name);
	token f_name = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = walk->next_lambda
	};
	generate_new_lambda(walk);
	token size_name = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = walk->next_lambda
	};
	generate_new_lambda(walk);
	expr_ast* fbinding = mk_binding(walk->parse->mem, &f_name);
	expr_ast* sizebinding = mk_binding(walk->parse->mem, &size_name);
	type_ast* fptr_type = mk_func(walk->parse->mem,
		mk_ptr(walk->parse->mem, mk_lit(walk->parse->mem, U8_TYPE)),
		result_type
	);
	expr_ast* sizeof_fptr = mk_sizeof(walk->parse->mem, fptr_type);
	expr_ast* f = mk_term(walk->parse->mem,
		fptr_type,
		&f_name,
		NULL
	);
	type_ast* u64 = mk_lit(walk->parse->mem, U64_TYPE);
	line_relay_append(newlines, f);
	expr_ast* size = mk_term(walk->parse->mem,
		u64,
		&size_name,
		NULL
	);
	line_relay_append(newlines, size);
	expr_ast* ptr_accessor = mk_struct_access(walk->parse->mem,
		input_binding,
		ptr_accessor_binding
	);
	expr_ast* copy_func = mk_appl(walk->parse->mem,
		mk_appl(walk->parse->mem,
			mk_appl(walk->parse->mem, 
				memcpy_binding,
				mk_ref(walk->parse->mem, fbinding)
			),
			ptr_accessor
		),
		sizeof_fptr
	);
	line_relay_append(newlines, copy_func);
	expr_ast* copy_size = mk_appl(walk->parse->mem,
		mk_appl(walk->parse->mem,
			mk_appl(walk->parse->mem, 
				memcpy_binding,
				mk_ref(walk->parse->mem, sizebinding)
			),
			mk_appl(walk->parse->mem,
				mk_appl(walk->parse->mem,
					plus_binding,
					ptr_accessor
				),
				sizeof_fptr
			)
		),
		mk_sizeof(walk->parse->mem, u64)
	);
	line_relay_append(newlines, copy_size);
	expr_ast* call = mk_appl(walk->parse->mem,
		fbinding,
		mk_appl(walk->parse->mem,
			mk_appl(walk->parse->mem,
				minus_binding,
				ptr_accessor
			),
			sizebinding
		)
	);
	call->type = result_type->data.function.right;
	return call;
}

//NOTE converted type is the type of a full structure, not a pointer
//NOTE func_binding is the name of the origin function as a binding
token
create_wrapper(walker* const walk, expr_ast* func_binding, type_ast* const converted_type, uint64_t real_args, uint64_t args){
	token* wrapper_exists = token_map_access(walk->wrappers, func_binding->data.binding.data.name);
	if (wrapper_exists != NULL){
		return *wrapper_exists;
	}
	token newname = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = walk->next_lambda
	};
	generate_new_lambda(walk);
	token_map_insert(walk->wrappers, func_binding->data.binding.data.name, newname);
	type_ast* u8ptr = mk_ptr(walk->parse->mem, mk_lit(walk->parse->mem, U8_TYPE));
	type_ast* newtype = mk_func(walk->parse->mem,
		u8ptr,
		converted_type->data.structure->data.structure.members[converted_type->data.structure->data.structure.count-2].data.function.right
	);
	expr_ast* lambda = pool_request(walk->parse->mem, sizeof(expr_ast));
	token param_name = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = walk->next_lambda
	};
	generate_new_lambda(walk);
	lambda->tag = LAMBDA_EXPR;
	lambda->data.lambda.arg_count = 1;
	lambda->data.lambda.args = pool_request(walk->parse->mem, sizeof(pattern_ast));
	lambda->data.lambda.args->tag = BINDING_PATTERN;
	lambda->data.lambda.args->data.binding = param_name;
	lambda->data.lambda.expression = pool_request(walk->parse->mem, sizeof(expr_ast));
	expr_ast* block = lambda->data.lambda.expression;
	block->tag = BLOCK_EXPR;
	term_ast* wrapper = pool_request(walk->parse->mem, sizeof(term_ast));
	wrapper->type = newtype;
	wrapper->name = newname;
	wrapper->expression = lambda;
	term_ast_buffer_insert(&walk->parse->term_list, *wrapper);
	term_ptr_map_insert(walk->parse->terms, wrapper->name.data.name, term_ast_buffer_top(&walk->parse->term_list));
	token mem_cpy = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = string_init(walk->parse->mem, "memcpy")
	};
	token plus = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = string_init(walk->parse->mem, "~add")
	};
	token minus = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = string_init(walk->parse->mem, "~sub")
	};
	expr_ast* memcpy_binding = mk_binding(walk->parse->mem, &mem_cpy);
	expr_ast* plus_binding = mk_binding(walk->parse->mem, &plus);
	expr_ast* minus_binding = mk_binding(walk->parse->mem, &minus);
	expr_ast* last_ptr = NULL;
	if (args == real_args){
		uint64_t line_count = (args * 3 ) + 1;
		block->data.block.line_count = line_count;
		block->data.block.lines = pool_request(walk->parse->mem, sizeof(expr_ast)*line_count);
		expr_ast* call = &block->data.block.lines[line_count-1];
		expr_ast* func_call = standard_call_wrapper(walk, func_binding, u8ptr, converted_type, memcpy_binding, plus_binding, args, block, param_name, &last_ptr);
		call->tag = RETURN_EXPR;
		call->data.ret = func_call;
		return newname;
	}
	assert(args > real_args);
	uint64_t line_count = (real_args * 3) + 8;
	block->data.block.line_count = line_count;
	block->data.block.lines = pool_request(walk->parse->mem, sizeof(expr_ast)*line_count);
	expr_ast* initial_call = standard_call_wrapper(walk, func_binding, u8ptr, converted_type, memcpy_binding, plus_binding, real_args, block, param_name, &last_ptr);
	uint64_t line = (real_args * 3) + 1;
	expr_ast* initial_setter = &block->data.block.lines[line-1];
	initial_setter->tag = TERM_EXPR;
	initial_setter->data.term = pool_request(walk->parse->mem, sizeof(term_ast));
	initial_setter->data.term->type = u8ptr;
	initial_setter->data.term->expression = initial_call;
	token setter_name = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = walk->next_lambda
	};
	generate_new_lambda(walk);
	initial_setter->data.term->name = setter_name;
	expr_ast* setter_binding = mk_binding(walk->parse->mem, &setter_name);
	expr_ast* copy_args = &block->data.block.lines[line];
	line += 1;
	copy_args->tag = APPL_EXPR;
	copy_args->data.appl.left = mk_appl(walk->parse->mem, 
		mk_appl(walk->parse->mem,
			memcpy_binding,
			setter_binding
		),
		last_ptr
	);
	uint64_t remaining_size = 0;
	for (uint64_t i = real_args;i<args;++i){
		remaining_size += sizeof_type(walk->parse, &converted_type->data.structure->data.structure.members[i]);
	}
	expr_ast* total_size = pool_request(walk->parse->mem, sizeof(expr_ast));
	total_size->tag = LIT_EXPR;
	total_size->data.literal.tag = UINT_LITERAL;
	total_size->data.literal.data.u = remaining_size;
	copy_args->data.appl.right = total_size;
	token func_offset_name = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = walk->next_lambda
	};
	generate_new_lambda(walk);
	expr_ast* func_offset_binding = mk_binding(walk->parse->mem, &func_offset_name);
	expr_ast* func_offset = &block->data.block.lines[line];
	line += 1;
	func_offset->tag = TERM_EXPR;
	func_offset->data.term = pool_request(walk->parse->mem, sizeof(term_ast));
	func_offset->data.term->name = func_offset_name;
	func_offset->data.term->type = u8ptr;
	func_offset->data.term->expression = mk_appl(walk->parse->mem,
		mk_appl(walk->parse->mem,
			plus_binding,
			setter_binding
		),
		total_size
	);
	expr_ast* inner_func = &block->data.block.lines[line];
	line += 1;
	inner_func->tag = TERM_EXPR;
	inner_func->data.term = pool_request(walk->parse->mem, sizeof(term_ast));
	token inner_func_name = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = walk->next_lambda
	};
	generate_new_lambda(walk);
	expr_ast* inner_func_binding = mk_binding(walk->parse->mem, &inner_func_name);
	inner_func->data.term->name = inner_func_name;
	inner_func->data.term->expression = NULL;
	inner_func->data.term->type = newtype;
	expr_ast* func_copy = &block->data.block.lines[line];
	line += 1;
	func_copy->tag = APPL_EXPR;
	func_copy->data.appl.left = mk_appl(walk->parse->mem, 
		mk_appl(walk->parse->mem,
			memcpy_binding,
			mk_ref(walk->parse->mem, inner_func_binding)
		),
		func_offset_binding
	);
	func_copy->data.appl.right = mk_sizeof(walk->parse->mem, newtype);
	token size_name = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = walk->next_lambda
	};
	generate_new_lambda(walk);
	expr_ast* size_binding = mk_binding(walk->parse->mem, &size_name);
	expr_ast* size = &block->data.block.lines[line];
	line += 1;
	size->tag = TERM_EXPR;
	size->data.term = pool_request(walk->parse->mem, sizeof(term_ast));
	size->data.term->name = size_name;
	size->data.term->type = mk_lit(walk->parse->mem, U64_TYPE);
	size->data.term->expression = NULL;
	expr_ast* copy_size = &block->data.block.lines[line];
	line += 1;
	copy_size->tag = APPL_EXPR;
	copy_size->data.appl.left = mk_appl(walk->parse->mem,
		mk_appl(walk->parse->mem,
			memcpy_binding,
			mk_ref(walk->parse->mem, size_binding)
		),
		mk_appl(walk->parse->mem,
			mk_appl(walk->parse->mem,
				plus_binding,
				func_offset_binding
			),
			mk_sizeof(walk->parse->mem, newtype)
		)
	);
	copy_size->data.appl.right = mk_sizeof(walk->parse->mem, mk_lit(walk->parse->mem, U64_TYPE));
	expr_ast* ret = &block->data.block.lines[line];
	line += 1;
	ret->tag = RETURN_EXPR;
	ret->data.ret = mk_appl(walk->parse->mem,
		inner_func_binding,
		mk_appl(walk->parse->mem,
			mk_appl(walk->parse->mem,
				minus_binding,
				func_offset_binding
			),
			size_binding
		)
	);
	return newname;
}

expr_ast*
standard_call_wrapper(walker* const walk, expr_ast* const func_binding, type_ast* const u8ptr, type_ast* const converted_type, expr_ast* memcpy_binding, expr_ast* plus_binding, uint64_t args, expr_ast* const block, token param_name, expr_ast** const last_ptr){
	uint64_t line = 0;
	expr_ast* current_binding = mk_binding(walk->parse->mem, &param_name);
	expr_ast** arg_bindings = pool_request(walk->parse->temp_mem, sizeof(expr_ast*)*args);
	for (uint64_t i = 0;i<args;++i){
		expr_ast* argterm = &block->data.block.lines[line];
		line += 1;
		argterm->tag = TERM_EXPR;
		argterm->type = &converted_type->data.structure->data.structure.members[i];
		argterm->data.term = pool_request(walk->parse->mem, sizeof(term_ast));
		token argname = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = walk->next_lambda
		};
		generate_new_lambda(walk);
		argterm->data.term->name = argname;
		expr_ast* current_arg_binding = mk_binding(walk->parse->mem, &argname);
		arg_bindings[i] = current_arg_binding;
		argterm->data.term->type = &converted_type->data.structure->data.structure.members[i];
		argterm->data.term->expression = NULL;
		expr_ast* copy = &block->data.block.lines[line];
		line += 1;
		copy->tag = APPL_EXPR;
		copy->data.appl.left = mk_appl(walk->parse->mem,
			mk_appl(walk->parse->mem,
				memcpy_binding,
				mk_ref(walk->parse->mem, current_arg_binding)
			),
			current_binding
		);
		copy->data.appl.right = mk_sizeof(walk->parse->mem, &converted_type->data.structure->data.structure.members[i]);
		expr_ast* increment = &block->data.block.lines[line];
		line += 1;
		increment->tag = TERM_EXPR;
		increment->type = u8ptr;
		increment->data.term = pool_request(walk->parse->mem, sizeof(term_ast));
		increment->data.term->type = u8ptr;
		token new_param_name = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = walk->next_lambda
		};
		generate_new_lambda(walk);
		increment->data.term->name = new_param_name;
		increment->data.term->expression = mk_appl(walk->parse->mem,
			mk_appl(walk->parse->mem,
				plus_binding,
				current_binding
			),
			copy->data.appl.right
		);
		current_binding = mk_binding(walk->parse->mem, &new_param_name);
	}
	*last_ptr = current_binding;
	expr_ast* func_call = func_binding;
	for (uint64_t i = 0;i<args;++i){
		expr_ast* appl = mk_appl(walk->parse->mem,
			func_call,
			arg_bindings[i]
		);
		func_call = appl;
	}
	return func_call;
}

type_ast*
mk_closure_type(pool* const mem){
	return mk_fat_ptr(mem, mk_lit(mem, U8_TYPE));
}

uint8_t
is_generic(parser* const parse, type_ast* const type){
	switch (type->tag){
	case DEPENDENCY_TYPE:
		if (type->data.dependency.dependency_count > 0){
			return 1;
		}
		return is_generic(parse, type->data.dependency.type);
	case FUNCTION_TYPE:
		return is_generic(parse, type->data.function.left) |
		       is_generic(parse, type->data.function.right);
	case LIT_TYPE:
		return 0;
	case PTR_TYPE:
		return is_generic(parse, type->data.ptr);
	case FAT_PTR_TYPE:
		return is_generic(parse, type->data.fat_ptr.ptr);
	case STRUCT_TYPE:
		return is_generic_struct(parse, type->data.structure);
	case NAMED_TYPE:
		for (uint64_t i = 0;i<type->data.named.arg_count;++i){
			if (is_generic(parse, &type->data.named.args[i]) == 1){
				return 1;
			}
		}
		type_ast* reduced = reduce_alias(parse, type);
		if (reduced->tag == NAMED_TYPE){
			typedef_ast** istypedef = typedef_ptr_map_access(parse->types, reduced->data.named.name.data.name);
			if (istypedef != NULL){
				if (type->data.named.arg_count < (*istypedef)->param_count){
					return 1;
				}
				return 0;
			}
			istypedef = typedef_ptr_map_access(parse->extern_types, reduced->data.named.name.data.name);
			if (istypedef != NULL){
				return 0;
			}
			return 1;
		}
		return is_generic(parse, reduced);
	}
	return 0;
}

uint8_t
is_generic_struct(parser* const parse, structure_ast* const s){
	switch (s->tag){
	case STRUCT_STRUCT:
		for (uint64_t i = 0;i<s->data.structure.count;++i){
			if (is_generic(parse, &s->data.structure.members[i]) == 1){
				return 1;
			}
		}
		return 0;
	case UNION_STRUCT:
		for (uint64_t i = 0;i<s->data.union_structure.count;++i){
			if (is_generic(parse, &s->data.union_structure.members[i]) == 1){
				return 1;
			}
		}
		return 0;
	case ENUM_STRUCT:
		return 0;
	}
	return 0;
}

uint64_t
term_map_stack_push(term_map_stack* const stack){
	if (stack->count == stack->capacity){
		stack->capacity *= 2;
		term_ast_map* maps = pool_request(stack->mem, sizeof(term_ast_map)*stack->capacity);
		for (uint64_t i = 0;i<stack->count;++i){
			maps[i] = stack->map[i];
		}
		stack->map = maps;
		for (uint64_t i = stack->count;i<stack->capacity;++i){
			stack->map[i] = term_ast_map_init(stack->mem);
		}
	}
	term_ast_map_clear(&stack->map[stack->count]);
	stack->count += 1;
	return stack->count-1;
}

void
term_map_stack_push_relation(term_map_stack* const stack, string name, term_ast* term){
	term_ast_map_insert(&stack->map[stack->count-1], name, *term);
}

void
term_map_stack_pop(term_map_stack* const stack, uint64_t pos){
	stack->count = pos;
}

expr_ast*
deep_copy_expr_type_replace_prevent_recursion(walker* const walk, expr_ast* source, clash_relation* const relation, token* const rec_name, type_ast* const rec_type){
	token_map realias = token_map_init(walk->parse->temp_mem);
	return deep_copy_expr_type_replace_worker(walk, source, relation, &realias, rec_name, rec_type);
}

expr_ast*
deep_copy_expr_type_replace_worker(walker* const walk, expr_ast* source, clash_relation* const relation, token_map* const realias, token* const rec_name, type_ast* const rec_type){
	expr_ast* new = pool_request(walk->parse->mem, sizeof(expr_ast));
	*new = *source;
	switch (source->tag){
	case APPL_EXPR:
		new->data.appl.left = deep_copy_expr_type_replace_worker(walk, source->data.appl.left, relation, realias, rec_name, rec_type);
		new->data.appl.right = deep_copy_expr_type_replace_worker(walk, source->data.appl.right, relation, realias, rec_name, rec_type);
		return new;
	case LAMBDA_EXPR:
		new->data.lambda.args = pool_request(walk->parse->mem, sizeof(pattern_ast)*new->data.lambda.arg_count);
		for (uint64_t i = 0;i<new->data.lambda.arg_count;++i){
			new->data.lambda.args[i] = *deep_copy_pattern_replace(walk, &source->data.lambda.args[i], realias);
		}
		new->data.lambda.expression = deep_copy_expr_type_replace_worker(walk, source->data.lambda.expression, relation, realias, rec_name, rec_type);
		if (new->data.lambda.alt != NULL){
			new->data.lambda.alt = deep_copy_expr_type_replace_worker(walk, source->data.lambda.alt, relation, realias, rec_name, rec_type);
		}
		return new;
	case BLOCK_EXPR:
		new->data.block.lines = pool_request(walk->parse->mem, sizeof(expr_ast)*new->data.block.line_count);
		for (uint64_t i = 0;i<new->data.block.line_count;++i){
			new->data.block.lines[i] = *deep_copy_expr_type_replace_worker(walk, &source->data.block.lines[i], relation, realias, rec_name, rec_type);
		}
		return new;
	case LIT_EXPR:
		return new;
	case TERM_EXPR:
		new->data.term = pool_request(walk->parse->mem, sizeof(term_ast));
		*new->data.term = *source->data.term;
		new->data.term->type = deep_copy_type_replace(walk->parse->mem, relation, source->data.term->type);
		new->data.term->expression = deep_copy_expr_type_replace_worker(walk, source->data.term->expression, relation, realias, rec_name, rec_type);
		return new;
	case STRING_EXPR:
		return new;
	case LIST_EXPR:
		new->data.list.lines = pool_request(walk->parse->mem, sizeof(expr_ast)*new->data.list.line_count);
		for (uint64_t i = 0;i<new->data.list.line_count;++i){
			new->data.list.lines[i] = *deep_copy_expr_type_replace_worker(walk, &source->data.list.lines[i], relation, realias, rec_name, rec_type);
		}
		return new;
	case STRUCT_EXPR:
		new->data.constructor.members = pool_request(walk->parse->mem, sizeof(expr_ast)*new->data.constructor.member_count);
		for (uint64_t i = 0;i<new->data.constructor.member_count;++i){
			new->data.constructor.members[i] = *deep_copy_expr_type_replace_worker(walk, &source->data.constructor.members[i], relation, realias, rec_name, rec_type);
		}
		return new;
	case BINDING_EXPR:
		if (rec_name != NULL){
			if (string_compare(&source->data.binding.data.name, &rec_name->data.name) == 0){
				new->type = rec_type;
			}
		}
		token* alias = token_map_access(realias, new->data.binding.data.name);
		if (alias != NULL){
			new->data.binding = *alias;
		}
		return new;
	case MUTATION_EXPR:
		new->data.mutation.left = deep_copy_expr_type_replace_worker(walk, source->data.mutation.left, relation, realias, rec_name, rec_type);
		new->data.mutation.right = deep_copy_expr_type_replace_worker(walk, source->data.mutation.right, relation, realias, rec_name, rec_type);
		return new;
	case RETURN_EXPR:
		new->data.ret = deep_copy_expr_type_replace_worker(walk, source->data.ret, relation, realias, rec_name, rec_type);
		return new;
	case SIZEOF_EXPR:
		new->data.size_type = deep_copy_type_replace(walk->parse->mem, relation, source->data.size_type);
		return new;
	case REF_EXPR:
		new->data.ref = deep_copy_expr_type_replace_worker(walk, source->data.ref, relation, realias, rec_name, rec_type);
		return new;
	case DEREF_EXPR:
		new->data.deref = deep_copy_expr_type_replace_worker(walk, source->data.deref, relation, realias, rec_name, rec_type);
		return new;
	case IF_EXPR:
		new->data.if_statement.pred = deep_copy_expr_type_replace_worker(walk, source->data.if_statement.pred, relation, realias, rec_name, rec_type);
		new->data.if_statement.cons = deep_copy_expr_type_replace_worker(walk, source->data.if_statement.cons, relation, realias, rec_name, rec_type);
		if (new->data.if_statement.alt != NULL){
			new->data.if_statement.alt = deep_copy_expr_type_replace_worker(walk, source->data.if_statement.alt, relation, realias, rec_name, rec_type);
		}
		return new;
	case FOR_EXPR:
		token new_binding = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = walk->next_lambda
		};
		generate_new_lambda(walk);
		token_map_insert(realias, new->data.for_statement.binding.data.name, new_binding);
		new->data.for_statement.binding = new_binding;
		new->data.for_statement.initial = deep_copy_expr_type_replace_worker(walk, source->data.for_statement.initial, relation, realias, rec_name, rec_type);
		new->data.for_statement.limit = deep_copy_expr_type_replace_worker(walk, source->data.for_statement.limit, relation, realias, rec_name, rec_type);
		new->data.for_statement.cons = deep_copy_expr_type_replace_worker(walk, source->data.for_statement.cons, relation, realias, rec_name, rec_type);
		return new;
	case WHILE_EXPR:
		new->data.while_statement.pred = deep_copy_expr_type_replace_worker(walk, source->data.while_statement.pred, relation, realias, rec_name, rec_type);
		new->data.while_statement.cons = deep_copy_expr_type_replace_worker(walk, source->data.while_statement.cons, relation, realias, rec_name, rec_type);
		return new;
	case MATCH_EXPR:
		new->data.match.patterns = pool_request(walk->parse->mem, sizeof(pattern_ast)*new->data.match.count);
		for (uint64_t i = 0;i<new->data.match.count;++i){
			new->data.match.patterns[i] = *deep_copy_pattern_replace(walk, &source->data.match.patterns[i], realias);
		}
		new->data.match.pred = deep_copy_expr_type_replace_worker(walk, source->data.match.pred, relation, realias, rec_name, rec_type);
		new->data.match.cases = pool_request(walk->parse->mem, sizeof(expr_ast)*new->data.match.count);
		for (uint64_t i = 0;i<new->data.match.count;++i){
			new->data.match.cases[i] = *deep_copy_expr_type_replace_worker(walk, &source->data.match.cases[i], relation, realias, rec_name, rec_type);
		}
	case CAST_EXPR:
		new->data.cast.source = deep_copy_expr_type_replace_worker(walk, source->data.cast.source, relation, realias, rec_name, rec_type);
		new->data.cast.target = deep_copy_type_replace(walk->parse->mem, relation, source->data.cast.target);
		return new;
	case BREAK_EXPR:
	case CONTINUE_EXPR:
	case NOP_EXPR:
		return new;
	case STRUCT_ACCESS_EXPR:
	case ARRAY_ACCESS_EXPR:
		new->data.access.left = deep_copy_expr_type_replace_worker(walk, source->data.access.left, relation, realias, rec_name, rec_type);
		new->data.access.right = deep_copy_expr_type_replace_worker(walk, source->data.access.right, relation, realias, rec_name, rec_type);
		return new;
	case FAT_PTR_EXPR:
		new->data.fat_ptr.left = deep_copy_expr_type_replace_worker(walk, source->data.fat_ptr.left, relation, realias, rec_name, rec_type);
		new->data.fat_ptr.right = deep_copy_expr_type_replace_worker(walk, source->data.fat_ptr.right, relation, realias, rec_name, rec_type);
		return new;
	}
	return new;
}

pattern_ast*
deep_copy_pattern_replace(walker* const walk, pattern_ast* const pattern, token_map* const realias){
	pattern_ast* new = pool_request(walk->parse->mem, sizeof(pattern_ast));
	*new = *pattern;
	switch (pattern->tag){
	case NAMED_PATTERN:
		token* alias = token_map_access(realias, pattern->data.named.name.data.name);
		if (alias != NULL){
			new->data.named.name = *alias;
		}
		token newname = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = walk->next_lambda
		};
		generate_new_lambda(walk);
		token_map_insert(realias, pattern->data.named.name.data.name, newname);
		new->data.named.name = newname;
		new->data.named.inner = deep_copy_pattern_replace(walk, pattern->data.named.inner, realias);
		return new;
	case STRUCT_PATTERN:
		new->data.structure.members = pool_request(walk->parse->mem, sizeof(pattern_ast)*new->data.structure.count);
		for (uint64_t i = 0;i<new->data.structure.count;++i){
			new->data.structure.members[i] = *deep_copy_pattern_replace(walk, &pattern->data.structure.members[i], realias);
		}
		return new;
	case FAT_PTR_PATTERN:
		new->data.fat_ptr.ptr = deep_copy_pattern_replace(walk, pattern->data.fat_ptr.ptr, realias);
		new->data.fat_ptr.len = deep_copy_pattern_replace(walk, pattern->data.fat_ptr.len, realias);
		return new;
	case HOLE_PATTERN:
		return new;
	case BINDING_PATTERN:
		token* balias = token_map_access(realias, pattern->data.binding.data.name);
		if (balias != NULL){
			new->data.binding = *balias;
		}
		token newbinding = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = walk->next_lambda
		};
		generate_new_lambda(walk);
		token_map_insert(realias, pattern->data.binding.data.name, newbinding);
		new->data.binding = newbinding;
		return new;
	case LITERAL_PATTERN:
	case STRING_PATTERN:
		return new;
	case UNION_SELECTOR_PATTERN:
		new->data.union_selector.nest = deep_copy_pattern_replace(walk, pattern->data.union_selector.nest, realias);
		return new;
	}
	return new;
}

term_ast*
is_tracked_generic(walker* const walk, token* const name, type_ast* const expected_type){
	for (uint64_t i = 0;i<walk->replacements->count;++i){
		term_ast_map* replacements = &walk->replacements->map[i];
		term_ast* replace = term_ast_map_access(replacements, name->data.name);
		if (replace != NULL){
			if (replace->expression->tag == BINDING_EXPR){
				return is_tracked_generic(walk, &replace->expression->data.binding, expected_type);
			}
			return replace;
		}
	}
	term_ast** term = term_ptr_map_access(walk->parse->terms, name->data.name);
	if (term != NULL){
		if (is_generic(walk->parse, (*term)->type) == 1){
			return *term;
		}
	}
	term_ptr_buffer* poly_funcs = term_ptr_buffer_map_access(walk->parse->implemented_terms, name->data.name);
	if (poly_funcs != NULL){
		for (uint64_t i = 0;i<poly_funcs->count;++i){
			term_ast* term = poly_funcs->buffer[i];
			type_ast* type = term->type;
			if (expected_type == NULL){
				uint64_t index = walk->outer_exprs->expr_count-1;
				uint8_t broke = 0;
				while (type->tag == FUNCTION_TYPE){
					expr_ast* arg = walk->outer_exprs->exprs[index];
					type_ast* candidate = walk_expr(walk, arg, NULL, NULL, 0);
					if (candidate == NULL){
						broke = 1;
						break;
					}
					if (type_equal(walk->parse, candidate, type->data.function.left) == 0){
						broke = 1;
						break;
					}
					type = type->data.function.right;
					if (index == 0){
						break;
					}
					index -= 1;
				}
				if (broke == 0){
					if (is_generic(walk->parse, term->type) == 1){
						return term;
					}
				}
			}
			else{
				if (type_equal(walk->parse, expected_type, type) == 1){
					if (is_generic(walk->parse, term->type) == 1){
						return term;
					}
				}
			}
		}
	}
	return NULL;
}

//NOTE this function assumes all semantic stuff has been checked about the passed arguments, except for the monomorph target expression
//NOTE left and expected are already deep copies
type_ast*
try_monomorph(walker* const walk, expr_ast* expr, expr_ast* const right, type_ast* left, type_ast* expected){
	if (left->tag == DEPENDENCY_TYPE){
		left = left->data.dependency.type;
	}
	type_ast_map relation = type_ast_map_init(walk->parse->temp_mem);
	type_ast_map pointer_only = type_ast_map_init(walk->parse->temp_mem);
	if (expected == NULL){
		uint64_t index = walk->outer_exprs->expr_count;
		type_ast* focus = left;
		if (focus->tag == DEPENDENCY_TYPE){
			focus = focus->data.dependency.type;
		}
		expected = mk_func(walk->parse->mem, NULL, NULL);
		type_ast* exp_focus = expected;
		{
			expr_ast* arg = right;
			exp_focus->data.function.left = arg->type;
			exp_focus->data.function.right = mk_func(walk->parse->mem, NULL, NULL);
			exp_focus = exp_focus->data.function.right;
			focus = focus->data.function.right;
			if (focus->tag == DEPENDENCY_TYPE){
				focus = focus->data.dependency.type;
			}
		}
		if (index != 0){
			while (focus->tag == FUNCTION_TYPE){
				type_ast_map_clear(&relation);
				type_ast_map_clear(&pointer_only);
				expr_ast* arg = walk->outer_exprs->exprs[index-1];
				exp_focus->data.function.left = arg->type;
				exp_focus->data.function.right = mk_func(walk->parse->mem, NULL, NULL);
				exp_focus = exp_focus->data.function.right;
				focus = focus->data.function.right;
				if (focus->tag == DEPENDENCY_TYPE){
					focus = focus->data.dependency.type;
				}
				if (index-1 == 0){
					break;
				}
				index -= 1;
			}
		}
		*exp_focus = *focus;
	}
	clash_relation clash = {
		.relation = &relation,
		.pointer_only = &pointer_only
	};
	while (is_generic(walk->parse, left) == 1){
		type_ast_map_clear(&relation);
		type_ast_map_clear(&pointer_only);
		clash_types_priority(walk, &relation, &pointer_only, left, expected);
		type_ast* last = left;
		left = deep_copy_type_replace(walk->parse->mem, &clash, left);
		if (type_equal(walk->parse, last, left) == 1){
			break;
		}
		type_ast_map_clear(&relation);
		type_ast_map_clear(&pointer_only);
		clash_types_priority(walk, &relation, &pointer_only, expected, left);
		expected = deep_copy_type_replace(walk->parse->mem, &clash, expected);
	}
	walk_assert(is_generic(walk->parse, left) == 0, nearest_token(expr), "Not enough type information to monmorphize expression");
	uint64_t index = walk->outer_exprs->expr_count;
	type_ast* focus = left;
	if (focus->tag == DEPENDENCY_TYPE){
		focus = focus->data.dependency.type;
	}
	{
		expr_ast* arg = right;
		if (is_generic(walk->parse, arg->type)){
			monomorph(walk, arg, &relation, &pointer_only, focus->data.function.left);
			walk_assert_prop();
		}
		focus = focus->data.function.right;
		if (focus->tag == DEPENDENCY_TYPE){
			focus = focus->data.dependency.type;
		}
	}
	if (index != 0){
		while (focus->tag == FUNCTION_TYPE){
			expr_ast* arg = walk->outer_exprs->exprs[index-1];
			if (is_generic(walk->parse, arg->type)){
				monomorph(walk, arg, &relation, &pointer_only, focus->data.function.left);
				walk_assert_prop();
			}
			focus = focus->data.function.right;
			if (focus->tag == DEPENDENCY_TYPE){
				focus = focus->data.dependency.type;
			}
			if (index-1 == 0){
				break;
			}
			index -= 1;
		}
	}
	monomorph(walk, expr, &relation, &pointer_only, left);
	if (left->tag == FUNCTION_TYPE){
		return left->data.function.right;
	}
	return left;
}

type_ast*
monomorph(walker* const walk, expr_ast* const expr, type_ast_map* const relation, type_ast_map* const pointer_only, type_ast* left){
	if (expr->tag == BINDING_EXPR){
		term_ast* is_generic = is_tracked_generic(walk, &expr->data.binding, left);
		if (is_generic != NULL){
			*expr = *is_generic->expression;
			expr->type = is_generic->type;
			clash_relation clash = {
				.relation = relation,
				.pointer_only = pointer_only
			};
			type_ast_map_clear(relation);
			type_ast_map_clear(pointer_only);
			clash_types_priority(walk, relation, pointer_only, expr->type, left);
			*expr = *deep_copy_expr_type_replace_prevent_recursion(walk, expr, &clash, &is_generic->name, left);
			expr->type = NULL;
			uint64_t pos = token_stack_push(walk->term_stack, is_generic->name);
			type_ast* correct_type = walk_expr(walk, expr, left, left, 0);
			walk_assert_prop();
			walk_assert(correct_type != NULL, nearest_token(expr), "Could not monomorphize generic expression");
			token_stack_pop(walk->term_stack, pos);
			return correct_type;
		}
	}
	clash_relation clash = {
		.relation = relation,
		.pointer_only = pointer_only
	};
	type_ast_map_clear(relation);
	type_ast_map_clear(pointer_only);
	clash_types_priority(walk, relation, pointer_only, expr->type, left);
	*expr = *deep_copy_expr_type_replace_prevent_recursion(walk, expr, &clash, NULL, NULL);
	expr->type = NULL;
	type_ast* correct_type = walk_expr(walk, expr, left, left, 0);
	walk_assert_prop();
	walk_assert(correct_type != NULL, nearest_token(expr), "Could not monomorphize generic expression");
	return correct_type;
}

void
replace_return_with_setter(walker* const walk, expr_ast* const expr, token setter){
	switch (expr->tag){
	case APPL_EXPR:
	case LAMBDA_EXPR:
		return;
	case BLOCK_EXPR:
		for (uint64_t i = 0;i<expr->data.block.line_count;++i){
			replace_return_with_setter(walk, &expr->data.block.lines[i], setter);
		}
		return;
	case LIT_EXPR:
	case TERM_EXPR:
	case STRING_EXPR:
	case LIST_EXPR:
	case STRUCT_EXPR:
	case BINDING_EXPR:
	case MUTATION_EXPR:
		return;
	case RETURN_EXPR:
		expr_ast* old = expr->data.ret;
		expr_ast* replacement = mk_mutation(walk->parse->mem,
			mk_binding(walk->parse->mem, &setter),
			old
		);
		*expr = *replacement;
		return;
	case SIZEOF_EXPR:
	case REF_EXPR:
	case DEREF_EXPR:
		return;
	case IF_EXPR:
		replace_return_with_setter(walk, expr->data.if_statement.cons, setter);
		if (expr->data.if_statement.alt != NULL){
			replace_return_with_setter(walk, expr->data.if_statement.alt, setter);
		}
		return;
	case FOR_EXPR:
		replace_return_with_setter(walk, expr->data.for_statement.cons, setter);
		return;
	case WHILE_EXPR:
		replace_return_with_setter(walk, expr->data.while_statement.cons, setter);
		return;
	case MATCH_EXPR:
		for (uint64_t i = 0;i<expr->data.match.count;++i){
			replace_return_with_setter(walk, &expr->data.match.cases[i], setter);
		}
		return;
	case CAST_EXPR:
	case BREAK_EXPR:
	case CONTINUE_EXPR:
	case NOP_EXPR:
	case STRUCT_ACCESS_EXPR:
	case ARRAY_ACCESS_EXPR:
	case FAT_PTR_EXPR:
		return;
	}
}

void
try_structure_monomorph(walker* const walk, type_ast* const type){
	if (type == NULL){
		return ;
	}
	type_ast* reduced = NULL;
	switch (type->tag){
	case DEPENDENCY_TYPE:
		*type = *type->data.dependency.type;
		try_structure_monomorph(walk, type);
		return;
	case FUNCTION_TYPE:
		try_structure_monomorph(walk, type->data.function.left);
		try_structure_monomorph(walk, type->data.function.right);
		return;
	case LIT_TYPE:
		return;
	case PTR_TYPE:
		try_structure_monomorph(walk, type->data.ptr);
		return;
	case FAT_PTR_TYPE:
		try_structure_monomorph(walk, type->data.fat_ptr.ptr);
		return;
	case STRUCT_TYPE:
		if (is_generic(walk->parse, type) == 1){
			return;
		}
		reduced = type;
		break;
	case NAMED_TYPE:
		if (is_generic(walk->parse, type) == 1){
			return;
		}
		if (type->data.named.arg_count == 0){
			return;
		}
		reduced = reduce_alias_and_type(walk->parse, type);
		break;
	}
	structure_ast* nested = reduced->data.structure;
	switch (nested->tag){
	case STRUCT_STRUCT:
		for (uint64_t i = 0;i<nested->data.structure.count;++i){
			try_structure_monomorph(walk, &nested->data.structure.members[i]);
		}
		break;
	case UNION_STRUCT:
		for (uint64_t i = 0;i<nested->data.union_structure.count;++i){
			try_structure_monomorph(walk, &nested->data.union_structure.members[i]);
		}
		break;
	case ENUM_STRUCT:
		break;
	}
	token newname = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = generate_mono_struct_name(walk, type)
	};
	typedef_ast** olddef = typedef_ptr_map_access(walk->parse->types, newname.data.name);
	if (olddef != NULL){
		type->tag = NAMED_TYPE;
		type->data.named.name = newname;
		type->data.named.args = NULL;
		type->data.named.arg_count = 0;
		return;
	}
	typedef_ast newdef = {
		.name = newname,
		.params = NULL,
		.param_count = 0,
		.type = deep_copy_type(walk, reduced)
	};
	typedef_ast_buffer_insert(&walk->parse->type_list, newdef);
	typedef_ptr_map_insert(walk->parse->types, newdef.name.data.name, typedef_ast_buffer_top(&walk->parse->type_list));
	type->tag = NAMED_TYPE;
	type->data.named.name = newname;
	type->data.named.args = NULL;
	type->data.named.arg_count = 0;
}

string
generate_mono_struct_name(walker* const walk, type_ast* const type){
	string val = string_init(walk->parse->mem, "!");
	stringify_type(walk->parse->mem, &val, type);
	string* memname = string_map_access(walk->struct_mono_names, val);
	if (memname != NULL){
		return *memname;
	}
	string name = walk->next_lambda;
	generate_new_lambda(walk);
	string_map_insert(walk->struct_mono_names, val, name);
	return name;
}

void
stringify_type(pool* const mem, string* const acc, type_ast* const x){
	string lval = string_init(mem, " ");
	switch (x->tag){
	case DEPENDENCY_TYPE:
		if (x->data.dependency.dependency_count > 0){
			string_set(mem, &lval, "(");
			string_cat(mem, acc, &lval);
			for (uint64_t i = 0;i<x->data.dependency.dependency_count;++i){
				string_cat(mem, acc, &x->data.dependency.typeclass_dependencies[i].data.name);
				string_set(mem, &lval, " ");
				string_cat(mem, acc, &lval);
				string_cat(mem, acc, &x->data.dependency.dependency_typenames[i].data.name);
				string_set(mem, &lval, ".");
				string_cat(mem, acc, &lval);
			}
			string_set(mem, &lval, ")=>");
			string_cat(mem, acc, &lval);
		}
		stringify_type(mem, acc, x->data.dependency.type);
		return;
	case FUNCTION_TYPE:
		string_set(mem, &lval, "(");
		string_cat(mem, acc, &lval);
		stringify_type(mem, acc, x->data.function.left);
		string_set(mem, &lval, ":");
		string_cat(mem, acc, &lval);
		stringify_type(mem, acc, x->data.function.right);
		string_set(mem, &lval, ")");
		string_cat(mem, acc, &lval);
		return;
	case LIT_TYPE:
		if (x->data.lit == U8_TYPE)       string_set(mem, &lval,"u8");
		else if (x->data.lit == U16_TYPE) string_set(mem, &lval,"u16");
		else if (x->data.lit == U32_TYPE) string_set(mem, &lval,"u32");
		else if (x->data.lit == U64_TYPE) string_set(mem, &lval,"u64");
		else if (x->data.lit == I8_TYPE)  string_set(mem, &lval,"i8");
		else if (x->data.lit == I16_TYPE) string_set(mem, &lval,"i16");
		else if (x->data.lit == I32_TYPE) string_set(mem, &lval,"i32");
		else if (x->data.lit == I64_TYPE) string_set(mem, &lval,"i64");
		else if (x->data.lit == INT_ANY)  string_set(mem, &lval,"int");
		else if (x->data.lit == F32_TYPE) string_set(mem, &lval,"f32");
		else if (x->data.lit == F64_TYPE) string_set(mem, &lval,"f64");
		string_cat(mem, acc, &lval);
		return;
	case PTR_TYPE:
		stringify_type(mem, acc, x->data.ptr);
		string_set(mem, &lval, "^");
		string_cat(mem, acc, &lval);
		return;
	case FAT_PTR_TYPE:
		string_set(mem, &lval, "[");
		string_cat(mem, acc, &lval);
		stringify_type(mem, acc, x->data.fat_ptr.ptr);
		string_set(mem, &lval, "]");
		string_cat(mem, acc, &lval);
		return;
	case STRUCT_TYPE:
		stringify_struct(mem, acc, x->data.structure);
		return;
	case NAMED_TYPE:
		string_set(mem, &lval, "<");
		string_cat(mem, acc, &lval);
		string_cat(mem, acc, &x->data.named.name.data.name);
		if (x->data.named.arg_count > 0){
			string_set(mem, &lval, ",");
			for (uint64_t i = 0;i<x->data.named.arg_count;++i){
				string_cat(mem, acc, &lval);
				stringify_type(mem, acc, &x->data.named.args[i]);
			}
		}
		string_set(mem, &lval, ">");
		string_cat(mem, acc, &lval);
		return;
	}
}

void
stringify_struct(pool* const mem, string* const acc, structure_ast* const x){
	string lval = string_init(mem, " ");
	switch (x->tag){
	case STRUCT_STRUCT:
		string_set(mem, &lval, "struct{");
		string_cat(mem, acc, &lval);
		for (uint64_t i = 0;i<x->data.structure.count;++i){
			stringify_type(mem, acc, &x->data.structure.members[i]);
			string_set(mem, &lval, " ");
			string_cat(mem, acc, &lval);
			string_cat(mem, acc, &x->data.structure.names[i].data.name);
			string_set(mem, &lval, ";");
			string_cat(mem, acc, &lval);
		}
		string_set(mem, &lval, "}");
		string_cat(mem, acc, &lval);
		return;
	case UNION_STRUCT:
		string_set(mem, &lval, "union{");
		string_cat(mem, acc, &lval);
		for (uint64_t i = 0;i<x->data.union_structure.count;++i){
			stringify_type(mem, acc, &x->data.union_structure.members[i]);
			string_set(mem, &lval, " ");
			string_cat(mem, acc, &lval);
			string_cat(mem, acc, &x->data.union_structure.names[i].data.name);
			string_set(mem, &lval, ";");
			string_cat(mem, acc, &lval);
		}
		string_set(mem, &lval, "}");
		string_cat(mem, acc, &lval);
		return;
	case ENUM_STRUCT:
		string_set(mem, &lval, "enum{");
		string_cat(mem, acc, &lval);
		for (uint64_t i = 0;i<x->data.enumeration.count;++i){
			string_cat(mem, acc, &x->data.enumeration.names[i].data.name);
			string_set(mem, &lval, ",");
			string_cat(mem, acc, &lval);
		}
		string_set(mem, &lval, "}");
		string_cat(mem, acc, &lval);
		return;
	}
}

void
destructure_lambda_patterns(walker* const walk, expr_ast* const expr){
	uint64_t arg_count = expr->data.lambda.arg_count;
	uint8_t found = 0;
	for (uint64_t i = 0;i<arg_count;++i){
		if (expr->data.lambda.args[i].tag != BINDING_PATTERN){
			found = 1;
		}
	}
	if (found == 0){
		return;
	}
	pattern_ast* realiased = pool_request(walk->parse->mem, sizeof(pattern_ast)*arg_count);
	for (uint64_t i = 0;i<arg_count;++i){
		realiased[i] = (pattern_ast){
			.tag = BINDING_PATTERN,
			.data.binding = {
				.content_tag = STRING_TOKEN_TYPE,
				.tag = IDENTIFIER_TOKEN,
				.index = 0,
				.data.name = walk->next_lambda
			}
		};
		generate_new_lambda(walk);
	}
	expr_ast* lateral_walker = expr;
	expr_ast* prev_walker = NULL;
	expr_ast* host = expr;
	while (lateral_walker != NULL){
		if (prev_walker == NULL){
			expr_ast* prev_inner = NULL;
			expr_ast* outer_dispatch = NULL;
			for (uint64_t i = 0;i<arg_count;++i){
				expr_ast* binding = mk_binding(walk->parse->mem, &realiased[i].data.binding);
				expr_ast* inner;
				expr_ast* line = destructure_pattern(walk, &lateral_walker->data.lambda.args[i], host->data.lambda.args[i].type, binding, &inner);
				if (prev_inner != NULL){
					*prev_inner = *line;
				}
				else{
					outer_dispatch = line;
				}
				prev_inner = inner;
			}
			*prev_inner = *lateral_walker->data.lambda.expression;
			lateral_walker->data.lambda.expression = outer_dispatch;
			prev_walker = lateral_walker;
			lateral_walker = lateral_walker->data.lambda.alt;
			continue;
		}
		expr_ast* location = host->data.lambda.expression;
		uint64_t i = 0;
		for (;i<arg_count;++i){
			if (pattern_equal(&prev_walker->data.lambda.args[i], &lateral_walker->data.lambda.args[i]) == 1){
				if (location->tag == BLOCK_EXPR){
					location = &location->data.block.lines[location->data.block.line_count-1];
				}
				assert(location->tag == IF_EXPR);
				location = location->data.if_statement.cons;
				continue;
			}
			break;
		}
		pattern_ast* arg_pos = &lateral_walker->data.lambda.args[i];
		expr_ast* binding = mk_binding(walk->parse->mem, &realiased[i].data.binding);
		type_ast* target_type = host->data.lambda.args[i].type;
		uint8_t binding_changed = 0;
		find_pattern_branch(walk, &prev_walker->data.lambda.args[i], &arg_pos, &location, &binding, &target_type, &binding_changed);
		expr_ast* prev_inner = NULL;
		expr_ast* outer_dispatch = NULL;
		{
			expr_ast* inner;
			expr_ast* line = destructure_pattern(walk, arg_pos, target_type, binding, &inner);
			outer_dispatch = line;
			prev_inner = inner;
			i += 1;
		}
		for (;i<arg_count;++i){
			expr_ast* inner;
			binding = mk_binding(walk->parse->mem, &realiased[i].data.binding);
			expr_ast* line = destructure_pattern(walk, &lateral_walker->data.lambda.args[i], host->data.lambda.args[i].type, binding, &inner);
			*prev_inner = *line;
			prev_inner = inner;
		}
		*prev_inner = *lateral_walker->data.lambda.expression;
		if (location->tag == IF_EXPR){
			while (location->data.if_statement.alt != NULL){
				location = location->data.if_statement.alt;
			}
			location->data.if_statement.alt = outer_dispatch;
		}
		else{
			if (binding_changed == 0){
				expr_ast* outer_block = pool_request(walk->parse->mem, sizeof(expr_ast));
				outer_block->tag = BLOCK_EXPR;
				outer_block->data.block.line_count = location->data.block.line_count+1;
				outer_block->data.block.lines = pool_request(walk->parse->mem, sizeof(expr_ast)*outer_block->data.block.line_count);
				for (uint64_t k = 0;k<location->data.block.line_count;++k){
					outer_block->data.block.lines[k] = location->data.block.lines[k];
				}
				outer_block->data.block.lines[outer_block->data.block.line_count-1] = *outer_dispatch;
				*location = *outer_block;
			}
			else {
				if (outer_dispatch->tag == BLOCK_EXPR){
					expr_ast* outer_block = pool_request(walk->parse->mem, sizeof(expr_ast));
					outer_block->tag = BLOCK_EXPR;
					outer_block->data.block.line_count = outer_dispatch->data.block.line_count+1;
					outer_block->data.block.lines = pool_request(walk->parse->mem, sizeof(expr_ast)*outer_block->data.block.line_count);
					outer_block->data.block.lines[0] = *location;
					for (uint64_t k = 1;k<outer_block->data.block.line_count;++k){
						outer_block->data.block.lines[k] = outer_dispatch->data.block.lines[k-1];
					}
					*location = *outer_block;
				}
				else{
					expr_ast* outer_block = pool_request(walk->parse->mem, sizeof(expr_ast));
					outer_block->tag = BLOCK_EXPR;
					outer_block->data.block.line_count = 2;
					outer_block->data.block.lines = pool_request(walk->parse->mem, sizeof(expr_ast)*2);
					outer_block->data.block.lines[0] = *location;
					outer_block->data.block.lines[1] = *outer_dispatch;
					*location = *outer_block;
				}
			}
		}
		prev_walker = lateral_walker;
		lateral_walker = lateral_walker->data.lambda.alt;
	}
	for (uint64_t i = 0;i<arg_count;++i){
		expr->data.lambda.args[i] = realiased[i];
	}
	expr->data.lambda.alt = NULL;
}

void
destructure_match_patterns(walker* const walk, expr_ast* const expr){
	assert(expr->data.match.pred->tag == BINDING_EXPR);
	expr_ast* binding = expr->data.match.pred;
	expr_ast* first = NULL;
	for (uint64_t i = 0;i<expr->data.match.count;++i){
		if (i == 0){
			expr_ast* inner;
			first = destructure_pattern(walk, &expr->data.match.patterns[i], expr->data.match.patterns[i].type, binding, &inner);
			*inner = expr->data.match.cases[i];
			continue;
		}
		expr_ast* location = first;
		pattern_ast* arg_pos = &expr->data.match.patterns[i];
		type_ast* target_type = expr->data.match.patterns[i].type;
		uint8_t binding_changed = 0;
		find_pattern_branch(walk, &expr->data.match.patterns[i-1], &arg_pos, &location, &binding, &target_type, &binding_changed);
		expr_ast* inner;
		expr_ast* outer_dispatch = destructure_pattern(walk, arg_pos, target_type, binding, &inner);
		*inner = expr->data.match.cases[i];
		if (location->tag == IF_EXPR){
			while (location->data.if_statement.alt != NULL){
				location = location->data.if_statement.alt;
			}
			location->data.if_statement.alt = outer_dispatch;
		}
		else{
			if (binding_changed == 0){
				expr_ast* outer_block = pool_request(walk->parse->mem, sizeof(expr_ast));
				outer_block->tag = BLOCK_EXPR;
				outer_block->data.block.line_count = location->data.block.line_count+1;
				outer_block->data.block.lines = pool_request(walk->parse->mem, sizeof(expr_ast)*outer_block->data.block.line_count);
				for (uint64_t k = 0;k<location->data.block.line_count;++k){
					outer_block->data.block.lines[k] = location->data.block.lines[k];
				}
				outer_block->data.block.lines[outer_block->data.block.line_count-1] = *outer_dispatch;
				*location = *outer_block;
			}
			else {
				if (outer_dispatch->tag == BLOCK_EXPR){
					expr_ast* outer_block = pool_request(walk->parse->mem, sizeof(expr_ast));
					outer_block->tag = BLOCK_EXPR;
					outer_block->data.block.line_count = outer_dispatch->data.block.line_count+1;
					outer_block->data.block.lines = pool_request(walk->parse->mem, sizeof(expr_ast)*outer_block->data.block.line_count);
					outer_block->data.block.lines[0] = *location;
					for (uint64_t k = 1;k<outer_block->data.block.line_count;++k){
						outer_block->data.block.lines[k] = outer_dispatch->data.block.lines[k-1];
					}
					*location = *outer_block;
				}
				else{
					expr_ast* outer_block = pool_request(walk->parse->mem, sizeof(expr_ast));
					outer_block->tag = BLOCK_EXPR;
					outer_block->data.block.line_count = 2;
					outer_block->data.block.lines = pool_request(walk->parse->mem, sizeof(expr_ast)*2);
					outer_block->data.block.lines[0] = *location;
					outer_block->data.block.lines[1] = *outer_dispatch;
					*location = *outer_block;
				}
			}
		}
	}
	*expr = *first;
}

expr_ast*
destructure_pattern(walker* const walk, pattern_ast* const pat, type_ast* target_type, expr_ast* const target_walk, expr_ast** const inner){
	expr_ast* block;
	expr_ast* cond;
	target_type = reduce_alias_and_type(walk->parse, target_type);
	switch (pat->tag){
	case NAMED_PATTERN:
		block = pool_request(walk->parse->mem, sizeof(expr_ast));
		block->tag = BLOCK_EXPR;
		block->data.block.line_count = 2;
		block->data.block.lines = pool_request(walk->parse->mem, sizeof(expr_ast)*2);
		block->data.block.lines[0] = *mk_term(walk->parse->mem,
			target_type,
			&pat->data.named.name,
			target_walk
		);
		block->data.block.lines[1] = *destructure_pattern(walk, pat->data.named.inner, target_type, target_walk, inner);
		return block;
	case STRUCT_PATTERN:
		expr_ast* struct_outer = NULL;
		expr_ast* struct_interm = NULL;
		expr_ast* next_interm;
		for (uint64_t i = 0;i<pat->data.structure.count;++i){
			type_ast* new_type = &target_type->data.structure->data.structure.members[i];
			expr_ast* new_expr = pool_request(walk->parse->mem, sizeof(expr_ast));
			new_expr->tag = STRUCT_ACCESS_EXPR;
			new_expr->data.access.left = target_walk;
			new_expr->data.access.left->type = target_type;
			new_expr->data.access.right = mk_binding(walk->parse->mem, &target_type->data.structure->data.structure.names[i]);
			if (struct_outer == NULL){
				if (pat->data.structure.count-1 == i){
					struct_outer = destructure_pattern(walk, &pat->data.structure.members[i], new_type, new_expr, inner);
					continue;
				}
				struct_outer = destructure_pattern(walk, &pat->data.structure.members[i], new_type, new_expr, &struct_interm);
				continue;
			}
			if (pat->data.structure.count-1 == i){
				*struct_interm = *destructure_pattern(walk, &pat->data.structure.members[i], new_type, new_expr, inner);
				continue;
			}
			*struct_interm = *destructure_pattern(walk, &pat->data.structure.members[i], new_type, new_expr, &next_interm);
			struct_interm = next_interm;
		}
		return struct_outer;
	case FAT_PTR_PATTERN:
		expr_ast* interm;
		token ptr_token = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = string_init(walk->parse->mem, "len")
		};
		token len_token = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = string_init(walk->parse->mem, "len")
		};
		expr_ast* ptr_expr = pool_request(walk->parse->mem, sizeof(expr_ast));
		ptr_expr->tag = STRUCT_ACCESS_EXPR;
		ptr_expr->data.access.left = target_walk;
		ptr_expr->data.access.left->type = target_type;
		ptr_expr->data.access.right = mk_binding(walk->parse->mem, &ptr_token);
		expr_ast* len_expr = pool_request(walk->parse->mem, sizeof(expr_ast));
		len_expr->tag = STRUCT_ACCESS_EXPR;
		len_expr->data.access.left = target_walk;
		ptr_expr->data.access.left->type = target_type;
		len_expr->data.access.right = mk_binding(walk->parse->mem, &len_token);
		expr_ast* outer = destructure_pattern(walk, pat->data.fat_ptr.ptr, target_type->data.fat_ptr.ptr, ptr_expr, &interm);
		type_ast* len = pool_request(walk->parse->mem, sizeof(type_ast));
		len->tag = LIT_TYPE;
		len->data.lit = U64_TYPE;
		*interm = *destructure_pattern(walk, pat->data.fat_ptr.len, len, len_expr, inner);
		return outer;
	case HOLE_PATTERN:
		block = pool_request(walk->parse->mem, sizeof(expr_ast));
		block->tag = BLOCK_EXPR;
		block->data.block.line_count = 1;
		block->data.block.lines = pool_request(walk->parse->mem, sizeof(expr_ast));
		*inner = block->data.block.lines;
		return block;
	case BINDING_PATTERN:
		block = pool_request(walk->parse->mem, sizeof(expr_ast));
		block->tag = BLOCK_EXPR;
		block->data.block.line_count = 2;
		block->data.block.lines = pool_request(walk->parse->mem, sizeof(expr_ast)*2);
		block->data.block.lines[0] = *mk_term(walk->parse->mem,
			target_type,
			&pat->data.binding,
			target_walk
		);
		*inner = &block->data.block.lines[1];
		return block;
	case LITERAL_PATTERN:
		cond = pool_request(walk->parse->mem, sizeof(expr_ast));
		token eq_token = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = string_init(walk->parse->mem, "==")
		};
		expr_ast* eq_binding = mk_binding(walk->parse->mem, &eq_token);
		cond->tag = IF_EXPR;
		expr_ast* lit_expr = pool_request(walk->parse->mem, sizeof(expr_ast));
		lit_expr->tag = LIT_EXPR;
		lit_expr->data.literal = pat->data.literal;
		cond->data.if_statement.pred = mk_appl(walk->parse->mem,
			mk_appl(walk->parse->mem,
				eq_binding,
				lit_expr
			),
			target_walk
		);
		cond->data.if_statement.cons = pool_request(walk->parse->mem, sizeof(expr_ast));
		cond->data.if_statement.alt = NULL;
		*inner = cond->data.if_statement.cons;
		return cond;
	case STRING_PATTERN:
		cond = pool_request(walk->parse->mem, sizeof(expr_ast));
		token string_eq_token = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = string_init(walk->parse->mem, "==")//TODO what do for this, builtin ord typeclass with ==? or just strncmp call here
		};
		expr_ast* string_eq_binding = mk_binding(walk->parse->mem, &string_eq_token);
		cond->tag = IF_EXPR;
		expr_ast* string_expr = pool_request(walk->parse->mem, sizeof(expr_ast));
		string_expr->tag = STRING_EXPR;
		string_expr->data.str = pat->data.str;
		cond->data.if_statement.pred = mk_appl(walk->parse->mem,
			mk_appl(walk->parse->mem,
				string_eq_binding,
				string_expr	
			),
			target_walk
		);
		cond->data.if_statement.cons = pool_request(walk->parse->mem, sizeof(expr_ast));
		cond->data.if_statement.alt = NULL;
		*inner = cond->data.if_statement.cons;
		return cond;
	case UNION_SELECTOR_PATTERN:
		expr_ast* selector_binding = mk_binding(walk->parse->mem, &pat->data.union_selector.member);
		expr_ast* selector_access = pool_request(walk->parse->mem, sizeof(expr_ast));
		selector_access->tag = STRUCT_ACCESS_EXPR;
		selector_access->data.access.left = target_walk;
		selector_access->data.access.left->type = target_type;
		selector_access->data.access.right = selector_binding;
		type_ast* next_target_type = NULL;
		for (uint64_t i = 0;i<target_type->data.structure->data.union_structure.count;++i){
			if (string_compare(&pat->data.union_selector.member.data.name, &target_type->data.structure->data.union_structure.names[i].data.name) == 0){
				next_target_type = &target_type->data.structure->data.union_structure.members[i];
				break;
			}
		}
		assert(next_target_type != NULL);
		return destructure_pattern(walk, pat->data.union_selector.nest, next_target_type, selector_access, inner);
	}
	return NULL;
}

//NOTE left is the pattern for which location is walking, right is the new one to compare with
uint8_t
find_pattern_branch(walker* const walk, pattern_ast* const left, pattern_ast** const right, expr_ast** const location, expr_ast** const binding, type_ast** target_type, uint8_t* binding_changed){
	if (left->tag != (*right)->tag){
		return 1;
	}
	*target_type = reduce_alias_and_type(walk->parse, *target_type);
	switch (left->tag){
	case NAMED_PATTERN:
		if (string_compare(&left->data.named.name.data.name, &(*right)->data.named.name.data.name) != 0){
			*binding_changed = 1;
			return 1;
		}
		*location = &(*location)->data.block.lines[(*location)->data.block.line_count-1];
		*right = (*right)->data.named.inner;
		return find_pattern_branch(walk, left->data.named.inner, right, location, binding, target_type, binding_changed);
	case STRUCT_PATTERN:
		pattern_ast* outer = *right;
		expr_ast* bind_outer = *binding;
		type_ast* outer_type = *target_type;
		for (uint64_t i = 0;i<left->data.structure.count;++i){
			*right = &outer->data.structure.members[i];
			expr_ast* new_expr = pool_request(walk->parse->mem, sizeof(expr_ast));
			new_expr->tag = STRUCT_ACCESS_EXPR;
			new_expr->data.access.left = bind_outer;
			new_expr->data.access.left->type = outer_type;
			new_expr->data.access.right = mk_binding(walk->parse->mem, &outer_type->data.structure->data.structure.names[i]);
			*binding = new_expr;
			*target_type = &outer_type->data.structure->data.structure.members[i];
			if (find_pattern_branch(walk, &left->data.structure.members[i], right, location, binding, target_type, binding_changed) == 1){
				*binding = bind_outer;
				*target_type = outer_type;
				*right = outer;
				return 1;
			}
		}
		return 0;
	case FAT_PTR_PATTERN:
		pattern_ast* fat_outer = *right;
		expr_ast* fat_bind_outer = *binding;
		type_ast* fat_type_outer = *target_type;
		*right = fat_outer->data.fat_ptr.ptr;
		*target_type = fat_type_outer->data.fat_ptr.ptr;
		token ptr_token = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = string_init(walk->parse->mem, "len")
		};
		expr_ast* ptr_expr = pool_request(walk->parse->mem, sizeof(expr_ast));
		ptr_expr->tag = STRUCT_ACCESS_EXPR;
		ptr_expr->data.access.left = fat_bind_outer;
		ptr_expr->data.access.left->type = fat_type_outer;
		ptr_expr->data.access.right = mk_binding(walk->parse->mem, &ptr_token);
		*binding = ptr_expr;
		if (find_pattern_branch(walk, left->data.fat_ptr.ptr, right, location, binding, target_type, binding_changed) == 1){
			*binding = fat_bind_outer;
			*target_type = fat_type_outer;
			*right = fat_outer;
			return 1;
		}
		*right = fat_outer->data.fat_ptr.len;
		type_ast* len = pool_request(walk->parse->mem, sizeof(type_ast));
		len->tag = LIT_TYPE;
		len->data.lit = U64_TYPE;
		*target_type = len;
		token len_token = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = string_init(walk->parse->mem, "len")
		};
		expr_ast* len_expr = pool_request(walk->parse->mem, sizeof(expr_ast));
		len_expr->tag = STRUCT_ACCESS_EXPR;
		len_expr->data.access.left = fat_bind_outer;
		len_expr->data.access.left->type = fat_type_outer;
		len_expr->data.access.right = mk_binding(walk->parse->mem, &len_token);
		*binding = len_expr;
		if (find_pattern_branch(walk, left->data.fat_ptr.len, right, location, binding, target_type, binding_changed) == 1){
			return 1;
		}
		return 0;
	case HOLE_PATTERN:
		*location = &(*location)->data.block.lines[(*location)->data.block.line_count-1];
		return 0;
	case BINDING_PATTERN:
		if (string_compare(&left->data.binding.data.name, &(*right)->data.binding.data.name) != 0){
			*binding_changed = 1;
			return 1;
		}
		*location = &(*location)->data.block.lines[(*location)->data.block.line_count-1];
		return 0;
	case LITERAL_PATTERN:
		if (left->data.literal.tag != (*right)->data.literal.tag){
			return 1;
		}
		if (left->data.literal.tag == INT_LITERAL){
			if (left->data.literal.data.i != (*right)->data.literal.data.i) return 1;
		}
		if (left->data.literal.tag == UINT_LITERAL){
			if (left->data.literal.data.u != (*right)->data.literal.data.u) return 1;
		}
		if (left->data.literal.tag == FLOAT_LITERAL){
			if (left->data.literal.data.f != (*right)->data.literal.data.f) return 1;
		}
		if (left->data.literal.tag == DOUBLE_LITERAL){
			if (left->data.literal.data.d != (*right)->data.literal.data.d) return 1;
		}
		*location = (*location)->data.if_statement.cons;
		return 0;
	case STRING_PATTERN:
		if (string_compare(&left->data.str.data.name, &(*right)->data.str.data.name) != 0){
			return 1;
		}
		*location = (*location)->data.if_statement.cons;
		return 0;
	case UNION_SELECTOR_PATTERN:
		if (string_compare(&left->data.union_selector.member.data.name, &(*right)->data.union_selector.member.data.name) != 0){
			return 1;
		}
		expr_ast* selector_binding = mk_binding(walk->parse->mem, &left->data.union_selector.member);
		expr_ast* selector_access = pool_request(walk->parse->mem, sizeof(expr_ast));
		selector_access->tag = STRUCT_ACCESS_EXPR;
		selector_access->data.access.left = *binding;
		selector_access->data.access.left->type = *target_type;
		selector_access->data.access.right = selector_binding;
		*right = (*right)->data.union_selector.nest;
		*binding = selector_access;
		for (uint64_t i = 0;i<(*target_type)->data.structure->data.union_structure.count;++i){
			if (string_compare(&left->data.union_selector.member.data.name, &(*target_type)->data.structure->data.union_structure.names[i].data.name) == 0){
				*target_type = &(*target_type)->data.structure->data.union_structure.members[i];
				break;
			}
		}
		return find_pattern_branch(walk, left->data.union_selector.nest, right, location, binding, target_type, binding_changed);
	}
	return 0;
}

uint8_t
pattern_equal(pattern_ast* const left, pattern_ast* const right){
	if (left->tag != right->tag){
		return 0;
	}
	switch (left->tag){
	case NAMED_PATTERN:
		if (string_compare(&left->data.named.name.data.name, &right->data.named.name.data.name) != 0){
			return 0;
		}
		return pattern_equal(left->data.named.inner, right->data.named.inner);
	case STRUCT_PATTERN:
		for (uint64_t i = 0;i<left->data.structure.count;++i){
			if (pattern_equal(&left->data.structure.members[i], &right->data.structure.members[i]) == 0){
				return 0;
			}
		}
		return 1;
	case FAT_PTR_PATTERN:
		if (pattern_equal(left->data.fat_ptr.ptr, right->data.fat_ptr.ptr) == 0){
			return 0;
		}
		return pattern_equal(left->data.fat_ptr.len, right->data.fat_ptr.ptr);
	case HOLE_PATTERN:
		return 1;
	case BINDING_PATTERN:
		if (string_compare(&left->data.binding.data.name, &right->data.binding.data.name) == 0){
			return 1;
		}
		return 0;
	case LITERAL_PATTERN:
		if (left->data.literal.tag != right->data.literal.tag){
			return 0;
		}
		if (left->data.literal.tag == INT_LITERAL){
			return left->data.literal.data.i == right->data.literal.data.i;
		}
		if (left->data.literal.tag == UINT_LITERAL){
			return left->data.literal.data.u == right->data.literal.data.u;
		}
		if (left->data.literal.tag == FLOAT_LITERAL){
			return left->data.literal.data.f == right->data.literal.data.f;
		}
		if (left->data.literal.tag == DOUBLE_LITERAL){
			return left->data.literal.data.d == right->data.literal.data.d;
		}
		return 0;
	case STRING_PATTERN:
		if (string_compare(&left->data.str.data.name, &right->data.str.data.name) == 0){
			return 1;
		}
		return 0;
	case UNION_SELECTOR_PATTERN:
		if (string_compare(&left->data.union_selector.member.data.name, &right->data.union_selector.member.data.name) != 0){
			return 0;
		}
		return pattern_equal(left->data.union_selector.nest, right->data.union_selector.nest);
	}
	return 0;
}

void
generate_c(parser* const parse, const char* input, const char* output){
	token_map translated_names = token_map_init(parse->temp_mem);
	token_map func_names = token_map_init(parse->temp_mem);
	genc generator = {
		.mem = parse->temp_mem,
		.translated_names = &translated_names,
		.func_names = &func_names,
		.func_types = typedef_ast_buffer_init(parse->temp_mem),
		.next_func_name = string_init(parse->temp_mem, "$A"),
		.parse = parse
	};
	char* cfile = pool_request(parse->mem, ERROR_STRING_MAX+3);
	strncpy(cfile, input, ERROR_STRING_MAX);
	strncat(cfile, ".c", 3);
	char* hfile = pool_request(parse->mem, ERROR_STRING_MAX+3);
	strncpy(hfile, input, ERROR_STRING_MAX);
	strncat(hfile, ".h", 3);
	{
		FILE* cfd = fopen(cfile, "w");
		if (cfd == NULL){
			fprintf(stderr, "File '%s' could not be opened for writing\n", cfile);
			return;
		}
		fprintf(cfd, "#include<unistd.h>\n#include<string.h>\n#include \"%s\"\n", hfile);
		//function implementations
		for (uint64_t i = 0;i<parse->implementation_list.count;++i){
			implementation_ast* impl = &parse->implementation_list.buffer[i];
			for (uint64_t t = 0;t<impl->member_count;++t){
				if (is_generic(parse, impl->members[t].type) == 1){
					continue;
				}
				write_term_impl(&generator, cfd, &impl->members[t]);
			}
		}
		for (uint64_t i = 0;i<parse->term_list.count;++i){
			if (is_generic(parse, parse->term_list.buffer[i].type) == 1){
				continue;
			}
			write_term_impl(&generator, cfd, &parse->term_list.buffer[i]);
		}
		generate_main(&generator, cfd);
		fclose(cfd);
	}
	{
		FILE* hfd = fopen(hfile, "w");
		if (hfd == NULL){
			fprintf(stderr, "File '%s' could not be opened for writing\n", hfile);
			return;
		}
		fprintf(hfd, "#ifndef _INK_HEADER_\n#define _INK_HEADER_\n#include <inttypes.h>\n");
		//function typedefs
		for (uint64_t i = 0;i<generator.func_types.count;++i){
			write_func_typedef(&generator, hfd, &generator.func_types.buffer[i]);
		}
		//forward declarations for structures
		for (uint64_t i = 0;i<parse->alias_list.count;++i){
			write_alias_forward(&generator, hfd, &parse->alias_list.buffer[i]);
		}
		for (uint64_t i = 0;i<parse->type_list.count;++i){
			if (parse->type_list.buffer[i].param_count > 0){
				continue;
			}
			write_typedef_forward(&generator, hfd, &parse->type_list.buffer[i]);
		}
		//actual declarations
		for (uint64_t i = 0;i<parse->alias_list.count;++i){
			write_alias(&generator, hfd, &parse->alias_list.buffer[i]);
		}
		for (uint64_t i = 0;i<parse->type_list.count;++i){
			if (parse->type_list.buffer[i].param_count > 0){
				continue;
			}
			write_typedef(&generator, hfd, &parse->type_list.buffer[i]);
		}
		//function declarations
		for (uint64_t i = 0;i<parse->implementation_list.count;++i){
			implementation_ast* impl = &parse->implementation_list.buffer[i];
			for (uint64_t t = 0;t<impl->member_count;++t){
				if (is_generic(parse, impl->members[t].type) == 1){
					continue;
				}
				write_term_decl(&generator, hfd, &impl->members[t]);
			}
		}
		for (uint64_t i = 0;i<parse->term_list.count;++i){
			if (is_generic(parse, parse->term_list.buffer[i].type) == 1){
				continue;
			}
			write_term_decl(&generator, hfd, &parse->term_list.buffer[i]);
		}
		fprintf(hfd, "#endif\n");
		fclose(hfd);
	}
	pid_t pid = fork();
	if (pid == 0){
		execlp("gcc", "gcc", cfile, "-g", "-w", "-o", output, NULL);
		fprintf(stderr, "code gen failed\n");
		_exit(1);
	}
	else{
		wait(NULL);
	}
}

void
generate_new_func_name(genc* const generator){
	string old = generator->next_func_name;
	uint64_t i = 1;
	for (;i<old.len;++i){ // 1 because 0 is #
		if (old.str[i] < 'Z'){
			break;
		}
	}
	if (i < old.len){
		old = string_copy(generator->mem, &generator->next_func_name);
		for (uint64_t k = 1;k<i;++k){
			old.str[k] = 'A';
		}
		old.str[i] += 1;
	}
	else{
		old.str = pool_request(generator->mem, old.len+1);
		old.len += 1;
		old.str[0] = '#';
		for (uint64_t k = 1;k<old.len;++k){
			old.str[k] = 'A';
		}
	}
	generator->next_func_name = old;
}

void
write_alias_forward(genc* const generator, FILE* hfd, alias_ast* const def){
	if (def->type->tag != STRUCT_TYPE){
		return;
	}
	switch (def->type->data.structure->tag){
	case STRUCT_STRUCT:
		fprintf(hfd, "typedef struct ");
		break;
	case UNION_STRUCT:
		fprintf(hfd, "typedef union ");
		break;
	case ENUM_STRUCT:
		fprintf(hfd, "typedef enum ");
		break;
	}
	token* memoized = token_map_access(generator->translated_names, def->name.data.name);
	if (memoized != NULL){
		write_name(generator, hfd, *memoized);
		fprintf(hfd, " ");
		write_name(generator, hfd, *memoized);
		fprintf(hfd, ";\n");
		return;
	}
	token newname = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = ink_prefix(generator, &def->name.data.name)
	};
	token_map_insert(generator->translated_names, def->name.data.name, newname);
	write_name(generator, hfd, newname);
	fprintf(hfd, " ");
	write_name(generator, hfd, newname);
	fprintf(hfd, ";\n");
}

void
write_typedef_forward(genc* const generator, FILE* hfd, typedef_ast* const def){
	if (def->type->tag != STRUCT_TYPE){
		return;
	}
	switch (def->type->data.structure->tag){
	case STRUCT_STRUCT:
		fprintf(hfd, "typedef struct ");
		break;
	case UNION_STRUCT:
		fprintf(hfd, "typedef union ");
		break;
	case ENUM_STRUCT:
		fprintf(hfd, "typedef enum ");
		break;
	}
	token* memoized = token_map_access(generator->translated_names, def->name.data.name);
	if (memoized != NULL){
		write_name(generator, hfd, *memoized);
		fprintf(hfd, " ");
		write_name(generator, hfd, *memoized);
		fprintf(hfd, ";\n");
		return;
	}
	token newname = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = ink_prefix(generator, &def->name.data.name)
	};
	token_map_insert(generator->translated_names, def->name.data.name, newname);
	write_name(generator, hfd, newname);
	fprintf(hfd, " ");
	write_name(generator, hfd, newname);
	fprintf(hfd, ";\n");
}

void
write_alias(genc* const generator, FILE* hfd, alias_ast* const def){
	fprintf(hfd, "typedef ");
	token* memoized = token_map_access(generator->translated_names, def->name.data.name);
	if (memoized != NULL){
		uint8_t save = def->type->variable;
		def->type->variable = 1;
		write_type(generator, hfd, def->type, memoized);
		def->type->variable = save;
		fprintf(hfd, " ");
		write_name(generator, hfd, *memoized);
		fprintf(hfd, ";\n");
		return;
	}
	token newname = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = ink_prefix(generator, &def->name.data.name)
	};
	token_map_insert(generator->translated_names, def->name.data.name, newname);
	uint8_t save = def->type->variable;
	def->type->variable = 1;
	write_type(generator, hfd, def->type, &newname);
	def->type->variable = save;
	fprintf(hfd, " ");
	write_name(generator, hfd, newname);
	fprintf(hfd, ";\n");
}

void
write_typedef(genc* const generator, FILE* hfd, typedef_ast* const def){
	fprintf(hfd, "typedef ");
	token* memoized = token_map_access(generator->translated_names, def->name.data.name);
	if (memoized != NULL){
		uint8_t save = def->type->variable;
		def->type->variable = 1;
		write_type(generator, hfd, def->type, memoized);
		def->type->variable = save;
		fprintf(hfd, " ");
		write_name(generator, hfd, *memoized);
		fprintf(hfd, ";\n");
		return;
	}
	token newname = {
		.content_tag = STRING_TOKEN_TYPE,
		.tag = IDENTIFIER_TOKEN,
		.index = 0,
		.data.name = ink_prefix(generator, &def->name.data.name)
	};
	token_map_insert(generator->translated_names, def->name.data.name, newname);
	uint8_t save = def->type->variable;
	def->type->variable = 1;
	write_type(generator, hfd, def->type, &newname);
	def->type->variable = save;
	fprintf(hfd, " ");
	write_name(generator, hfd, newname);
	fprintf(hfd, ";\n");
}

void
write_func_typedef(genc* const generator, FILE* hfd, typedef_ast* const def){
	fprintf(hfd, "typedef ");
	type_ast* last = def->type;
	while (last->tag == FUNCTION_TYPE){
		last = last->data.function.right;
	}
	write_type(generator, hfd, last, NULL);
	fprintf(hfd, "(*");
	write_name(generator, hfd, def->name);
	fprintf(hfd, ")(");
	type_ast* walk = def->type;
	uint64_t arg_index = 0;
	while (walk->tag == FUNCTION_TYPE){
		if (arg_index != 0){
			fprintf(hfd, ",");
		}
		write_type(generator, hfd, walk->data.function.left, NULL);
		arg_index += 1;
		walk = walk->data.function.right;
	}
	fprintf(hfd, ");\n");
}

void
write_term_decl(genc* const generator, FILE* hfd, term_ast* const term){
	type_ast* last = term->type;
	while (last->tag == FUNCTION_TYPE){
		last = last->data.function.right;
	}
	write_type(generator, hfd, last, NULL);
	fprintf(hfd, " ");
	token* memoized = token_map_access(generator->translated_names, term->name.data.name);
	if (memoized != NULL){
		write_name(generator, hfd, *memoized);
	}
	else{
		token newname = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = ink_prefix(generator, &term->name.data.name)
		};
		token_map_insert(generator->translated_names, term->name.data.name, newname);
		write_name(generator, hfd, newname);
	}
	write_type_args(generator, hfd, term->type, term->expression);
	fprintf(hfd, ";\n");
}

void
write_type_args(genc* const generator, FILE* fd, type_ast* const arg_types, expr_ast* const lam){
	fprintf(fd, "(");
	type_ast* walk = arg_types;
	uint64_t arg_index = 0;
	while (walk->tag == FUNCTION_TYPE){
		if (arg_index != 0){
			fprintf(fd, ",");
		}
		token newname = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = ink_prefix(generator, &lam->data.lambda.args[arg_index].data.binding.data.name)
		};
		write_type(generator, fd, walk->data.function.left, NULL);
		fprintf(fd, " ");
		write_name(generator, fd, newname);
		arg_index += 1;
		walk = walk->data.function.right;
	}
	fprintf(fd, ")");
}

void
write_type(genc* const generator, FILE* fd, type_ast* const type, token* const structname){
	switch (type->tag){
	case DEPENDENCY_TYPE:
		write_type(generator, fd, type->data.dependency.type, structname);
		return;
	case FUNCTION_TYPE:
		string stringified = string_init(generator->mem, "!");
		stringify_type(generator->mem, &stringified, type);
		token* funcname = token_map_access(generator->func_names, stringified);
		if (funcname != NULL){
			write_name(generator, fd, *funcname);
		}
		else{
			token newname = {
				.content_tag = STRING_TOKEN_TYPE,
				.tag = IDENTIFIER_TOKEN,
				.index = 0,
				.data.name = ink_prefix(generator, &generator->next_func_name)
			};
			generate_new_func_name(generator);
			token_map_insert(generator->func_names, stringified, newname);
			typedef_ast newdef = {
				.name = newname,
				.params = NULL,
				.param_count = 0,
				.type = type
			};
			typedef_ast_buffer_insert(&generator->func_types, newdef);
			write_name(generator, fd, newname);
		}
		return;
	case LIT_TYPE:
		if (type->data.lit == U8_TYPE)       fprintf(fd, "uint8_t");
		else if (type->data.lit == U16_TYPE) fprintf(fd, "uint16_t");
		else if (type->data.lit == U32_TYPE) fprintf(fd, "uint32_t");
		else if (type->data.lit == U64_TYPE) fprintf(fd, "uint64_t");
		else if (type->data.lit == I8_TYPE)  fprintf(fd, "int8_t");
		else if (type->data.lit == I16_TYPE) fprintf(fd, "int16_t");
		else if (type->data.lit == I32_TYPE) fprintf(fd, "int32_t");
		else if (type->data.lit == I64_TYPE) fprintf(fd, "int64_t");
		else if (type->data.lit == INT_ANY)  fprintf(fd, "int");
		else if (type->data.lit == F32_TYPE) fprintf(fd, "float");
		else if (type->data.lit == F64_TYPE) fprintf(fd, "double");
		return;
	case PTR_TYPE:
		write_type(generator, fd, type->data.ptr, structname);
		fprintf(fd, "*");
		return;
	case FAT_PTR_TYPE:
		fprintf(fd, "struct {");
		write_type(generator, fd, type->data.fat_ptr.ptr, structname);
		fprintf(fd, "* ptr;uint64_t len;}");
		return;
	case STRUCT_TYPE:
		write_structure_type(generator, fd, type->data.structure, structname);
		return;
	case NAMED_TYPE:
		token* memoized = token_map_access(generator->translated_names, type->data.named.name.data.name);
		if (memoized != NULL){
			write_name(generator, fd, *memoized);
			return;
		}
		token newname = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = ink_prefix(generator, &type->data.named.name.data.name)
		};
		token_map_insert(generator->translated_names, type->data.named.name.data.name, newname);
		write_name(generator, fd, newname);
		return;
	}
}

string
ink_prefix(genc* const generator, string* const name){
	string new;
	if (name->str[0] == '#'){
		new = string_init(generator->mem, "lam_ink_");
		string copy = string_copy(generator->mem, name);
		copy.str += 1;
		copy.len -= 1;
		string_cat(generator->mem, &new, &copy);
	}
	else if (name->str[0] == '$'){
		new = string_init(generator->mem, "fun_ink_");
		string copy = string_copy(generator->mem, name);
		copy.str += 1;
		copy.len -= 1;
		string_cat(generator->mem, &new, &copy);
	}
	else if(name->str[0] == '?'){
		new = string_init(generator->mem, "sym_ink_");
		string copy = string_copy(generator->mem, name);
		copy.str += 1;
		copy.len -= 1;
		string_cat(generator->mem, &new, &copy);
	}
	else{
		new = string_init(generator->mem, "usr_ink_");
		string_cat(generator->mem, &new, name);
	}
	return new;
}

void
write_structure_type(genc* const generator, FILE* fd, structure_ast* const s, token* const structname){
	switch (s->tag){
	case STRUCT_STRUCT:
		if (s->data.structure.packed == 1){
			fprintf(fd, "struct __attribute__((packed, aligned(1)))");
		}
		else{
			fprintf(fd, "struct ");
		}
		if (structname != NULL){
			write_name(generator, fd, *structname);
		}
		fprintf(fd, "{");
		for (uint64_t i = 0;i<s->data.structure.count;++i){
			write_type(generator, fd, &s->data.structure.members[i], structname);
			fprintf(fd, " ");
			write_name(generator, fd, s->data.structure.names[i]);
			fprintf(fd, ";");
		}
		fprintf(fd, "}");
		return;
	case UNION_STRUCT:
		fprintf(fd, "union ");
		if (structname != NULL){
			write_name(generator, fd, *structname);
		}
		fprintf(fd, "{");
		for (uint64_t i = 0;i<s->data.union_structure.count;++i){
			write_type(generator, fd, &s->data.union_structure.members[i], structname);
			fprintf(fd, " ");
			write_name(generator, fd, s->data.union_structure.names[i]);
			fprintf(fd, ";");
		}
		fprintf(fd, "}");
		return;
	case ENUM_STRUCT:
		fprintf(fd, "enum ");
		if (structname != NULL){
			write_name(generator, fd, *structname);
		}
		fprintf(fd, "{");
		for (uint64_t i = 0;i<s->data.enumeration.count;++i){
			token newname = {
				.content_tag = STRING_TOKEN_TYPE,
				.tag = IDENTIFIER_TOKEN,
				.index = 0,
				.data.name = ink_prefix(generator, &s->data.enumeration.names[i].data.name)
			};
			write_name(generator, fd, newname);
			fprintf(fd, "=%lu,", s->data.enumeration.values[i]);
		}
		fprintf(fd, "}");
		return;
	}
}

void
write_name(genc* const generator, FILE* fd, token name){
	char save = name.data.name.str[name.data.name.len];
	name.data.name.str[name.data.name.len] = '\0';
	fprintf(fd, "%s", name.data.name.str);
	name.data.name.str[name.data.name.len] = save;
}

void
write_term_impl(genc* const generator, FILE* fd, term_ast* const term){
	type_ast* last = term->type;
	while (last->tag == FUNCTION_TYPE){
		last = last->data.function.right;
	}
	write_type(generator, fd, last, NULL);
	fprintf(fd, " ");
	token* memoized = token_map_access(generator->translated_names, term->name.data.name);
	if (memoized != NULL){
		write_name(generator, fd, *memoized);
	}
	else{
		token newname = {
			.content_tag = STRING_TOKEN_TYPE,
			.tag = IDENTIFIER_TOKEN,
			.index = 0,
			.data.name = ink_prefix(generator, &term->name.data.name)
		};
		token_map_insert(generator->translated_names, term->name.data.name, newname);
		write_name(generator, fd, newname);
	}
	write_type_args(generator, fd, term->type, term->expression);
	write_expression(generator, fd, term->expression, 0, 1, 0);
	fprintf(fd, "\n");
}

void
ink_indent(FILE* fd, uint64_t indent){
	for (uint64_t i = 0;i<indent;++i){
		fprintf(fd, "\t");
	}
}

void
write_call(genc* const generator, FILE* fd, expr_ast* const expr, expr_ast* const first){
	if (expr->tag == APPL_EXPR){
		write_call(generator, fd, expr->data.appl.left, first);
		write_expression(generator, fd, expr->data.appl.right, 0, 1, 0);
		if (expr != first){
			fprintf(fd, ",");
		}
		return;
	}
	write_expression(generator, fd, expr, 0, 0, 0);
	fprintf(fd, "(");
}

void
write_expression(genc* const generator, FILE* fd, expr_ast* const expr, uint64_t indent, uint8_t free, uint8_t from_fat){
	switch (expr->tag){
	case APPL_EXPR:
		ink_indent(fd, indent);
		expr_ast* first = expr;
		expr_ast* prev_0 = NULL;
		expr_ast* prev_1 = NULL;
		while (first->tag == APPL_EXPR){
			prev_1 = prev_0;
			prev_0 = first;
			first = first->data.appl.left;
		}
		uint64_t builtin = 0;
		if (first->tag == BINDING_EXPR){
			if (cstring_compare(&first->data.binding.data.name, "~add") == 0){
				fprintf(fd, "(");
				write_expression(generator, fd, prev_0->data.appl.right, 0, 1, 0);
				fprintf(fd, ")+(");
				write_expression(generator, fd, prev_1->data.appl.right, 0, 1, 0);
				fprintf(fd, ")");
				builtin = 1;
			}
			else if (cstring_compare(&first->data.binding.data.name, "~sub") == 0){
				fprintf(fd, "(");
				write_expression(generator, fd, prev_0->data.appl.right, 0, 1, 0);
				fprintf(fd, ")-(");
				write_expression(generator, fd, prev_1->data.appl.right, 0, 1, 0);
				fprintf(fd, ")");
				builtin = 1;
			}
			else if (cstring_compare(&first->data.binding.data.name, "~mul") == 0){
				fprintf(fd, "(");
				write_expression(generator, fd, prev_0->data.appl.right, 0, 1, 0);
				fprintf(fd, ")*(");
				write_expression(generator, fd, prev_1->data.appl.right, 0, 1, 0);
				fprintf(fd, ")");
				builtin = 1;
			}
			else if (cstring_compare(&first->data.binding.data.name, "~div") == 0){
				fprintf(fd, "(");
				write_expression(generator, fd, prev_0->data.appl.right, 0, 1, 0);
				fprintf(fd, ")/(");
				write_expression(generator, fd, prev_1->data.appl.right, 0, 1, 0);
				fprintf(fd, ")");
				builtin = 1;
			}
			else if (cstring_compare(&first->data.binding.data.name, "~mod") == 0){
				fprintf(fd, "(");
				write_expression(generator, fd, prev_0->data.appl.right, 0, 1, 0);
				fprintf(fd, ")%%(");
				write_expression(generator, fd, prev_1->data.appl.right, 0, 1, 0);
				fprintf(fd, ")");
				builtin = 1;
			}
			else if (cstring_compare(&first->data.binding.data.name, "~and") == 0){
				fprintf(fd, "(");
				write_expression(generator, fd, prev_0->data.appl.right, 0, 1, 0);
				fprintf(fd, ")&&(");
				write_expression(generator, fd, prev_1->data.appl.right, 0, 1, 0);
				fprintf(fd, ")");
				builtin = 1;
			}
			else if (cstring_compare(&first->data.binding.data.name, "~or") == 0){
				fprintf(fd, "(");
				write_expression(generator, fd, prev_0->data.appl.right, 0, 1, 0);
				fprintf(fd, ")||(");
				write_expression(generator, fd, prev_1->data.appl.right, 0, 1, 0);
				fprintf(fd, ")");
				builtin = 1;
			}
			else if (cstring_compare(&first->data.binding.data.name, "~bitor") == 0){
				fprintf(fd, "(");
				write_expression(generator, fd, prev_0->data.appl.right, 0, 1, 0);
				fprintf(fd, ")|(");
				write_expression(generator, fd, prev_1->data.appl.right, 0, 1, 0);
				fprintf(fd, ")");
				builtin = 1;
			}
			else if (cstring_compare(&first->data.binding.data.name, "~bitand") == 0){
				fprintf(fd, "(");
				write_expression(generator, fd, prev_0->data.appl.right, 0, 1, 0);
				fprintf(fd, ")&(");
				write_expression(generator, fd, prev_1->data.appl.right, 0, 1, 0);
				fprintf(fd, ")");
				builtin = 1;
			}
			else if (cstring_compare(&first->data.binding.data.name, "~bitxor") == 0){
				fprintf(fd, "(");
				write_expression(generator, fd, prev_0->data.appl.right, 0, 1, 0);
				fprintf(fd, ")^(");
				write_expression(generator, fd, prev_1->data.appl.right, 0, 1, 0);
				fprintf(fd, ")");
				builtin = 1;
			}
			else if (cstring_compare(&first->data.binding.data.name, "~lt") == 0){
				fprintf(fd, "(");
				write_expression(generator, fd, prev_0->data.appl.right, 0, 1, 0);
				fprintf(fd, ")<(");
				write_expression(generator, fd, prev_1->data.appl.right, 0, 1, 0);
				fprintf(fd, ")");
				builtin = 1;
			}
			else if (cstring_compare(&first->data.binding.data.name, "~gt") == 0){
				fprintf(fd, "(");
				write_expression(generator, fd, prev_0->data.appl.right, 0, 1, 0);
				fprintf(fd, ")>(");
				write_expression(generator, fd, prev_1->data.appl.right, 0, 1, 0);
				fprintf(fd, ")");
				builtin = 1;
			}
			else if (cstring_compare(&first->data.binding.data.name, "~le") == 0){
				fprintf(fd, "(");
				write_expression(generator, fd, prev_0->data.appl.right, 0, 1, 0);
				fprintf(fd, ")<=(");
				write_expression(generator, fd, prev_1->data.appl.right, 0, 1, 0);
				fprintf(fd, ")");
				builtin = 1;
			}
			else if (cstring_compare(&first->data.binding.data.name, "~ge") == 0){
				fprintf(fd, "(");
				write_expression(generator, fd, prev_0->data.appl.right, 0, 1, 0);
				fprintf(fd, ")>=(");
				write_expression(generator, fd, prev_1->data.appl.right, 0, 1, 0);
				fprintf(fd, ")");
				builtin = 1;
			}
			else if (cstring_compare(&first->data.binding.data.name, "~eq") == 0){
				fprintf(fd, "(");
				write_expression(generator, fd, prev_0->data.appl.right, 0, 1, 0);
				fprintf(fd, ")==(");
				write_expression(generator, fd, prev_1->data.appl.right, 0, 1, 0);
				fprintf(fd, ")");
				builtin = 1;
			}
			else if (cstring_compare(&first->data.binding.data.name, "~neq") == 0){
				fprintf(fd, "(");
				write_expression(generator, fd, prev_0->data.appl.right, 0, 1, 0);
				fprintf(fd, ")!=(");
				write_expression(generator, fd, prev_1->data.appl.right, 0, 1, 0);
				fprintf(fd, ")");
				builtin = 1;
			}
			else if (cstring_compare(&first->data.binding.data.name, "~bitcomp") == 0){
				fprintf(fd, "~(");
				write_expression(generator, fd, prev_0->data.appl.right, 0, 1, 0);
				fprintf(fd, ")");
				builtin = 1;
			}
			else if (cstring_compare(&first->data.binding.data.name, "~not") == 0){
				fprintf(fd, "!(");
				write_expression(generator, fd, prev_0->data.appl.right, 0, 1, 0);
				fprintf(fd, ")");
				builtin = 1;
			}
		}
		if (builtin == 0){
			write_call(generator, fd, expr, expr);
			fprintf(fd, ")");
		}
		break;
	case LAMBDA_EXPR:
		write_expression(generator, fd, expr->data.lambda.expression, indent, 1, 0);
		break;
	case BLOCK_EXPR:
		ink_indent(fd, indent);
		fprintf(fd, "{\n");
		for (uint64_t i = 0;i<expr->data.block.line_count;++i){
			write_expression(generator, fd, &expr->data.block.lines[i], indent+1, 1, 0);
			fprintf(fd, ";\n");
		}
		ink_indent(fd, indent);
		fprintf(fd, "}");
		break;
	case LIT_EXPR:
		ink_indent(fd, indent);
		if (expr->data.literal.tag == INT_LITERAL) fprintf(fd, "%ld", expr->data.literal.data.i);
		if (expr->data.literal.tag == UINT_LITERAL) fprintf(fd, "%lu", expr->data.literal.data.u);
		if (expr->data.literal.tag == FLOAT_LITERAL) fprintf(fd, "%f", expr->data.literal.data.f);
		if (expr->data.literal.tag == DOUBLE_LITERAL) fprintf(fd, "%lf", expr->data.literal.data.d);
		break;
	case TERM_EXPR:
		if (is_generic(generator->parse, expr->data.term->type) == 1){
			return;
		}
		ink_indent(fd, indent);
		write_type(generator, fd, expr->data.term->type, NULL);
		fprintf(fd, " ");
		token* term_memoized = token_map_access(generator->translated_names, expr->data.term->name.data.name);
		if (term_memoized != NULL){
			write_name(generator, fd, *term_memoized);
		}
		else{
			token newname = {
				.content_tag = STRING_TOKEN_TYPE,
				.tag = IDENTIFIER_TOKEN,
				.index = 0,
				.data.name = ink_prefix(generator, &expr->data.term->name.data.name)
			};
			token_map_insert(generator->translated_names, expr->data.term->name.data.name, newname);
			write_name(generator, fd, newname);
		}
		if (expr->data.term->expression != NULL){
			fprintf(fd, " = ");
			write_expression(generator, fd, expr->data.term->expression, 0, 1, 0);
		}
		break;
	case STRING_EXPR:
		ink_indent(fd, indent);
		write_name(generator, fd, expr->data.str);
		break;
	case LIST_EXPR:
		ink_indent(fd, indent);
		fprintf(fd, "{");
		for (uint64_t i = 0;i<expr->data.list.line_count;++i){
			if (i != 0){
				fprintf(fd, ",");
			}
			write_expression(generator, fd, &expr->data.list.lines[i], 0, 1, 0);
		}
		fprintf(fd, "}");
		break;
	case STRUCT_EXPR:
		ink_indent(fd, indent);
		fprintf(fd, "{\n");
		for (uint64_t i = 0;i<expr->data.constructor.member_count;++i){
			if (i != 0){
				fprintf(fd, ",\n");
			}
			if (expr->data.constructor.names[i].data.name.str != NULL){
				ink_indent(fd, indent+1);
				fprintf(fd,".");
				write_name(generator, fd, expr->data.constructor.names[i]);
				fprintf(fd,"=");
			}
			write_expression(generator, fd, &expr->data.constructor.members[i], 0, 1, 0);
		}
		fprintf(fd, "\n}");
		break;
	case BINDING_EXPR:
		replace_with_poly_binding(generator, &expr->data.binding, expr->type);
		ink_indent(fd, indent);
		if (term_ptr_map_access(generator->parse->extern_terms, expr->data.binding.data.name) != NULL){
			write_name(generator, fd, expr->data.binding);
			if (free == 1){
				fprintf(fd, "()");
			}
			return;
		}
		if (typedef_ptr_map_access(generator->parse->extern_types, expr->data.binding.data.name) != NULL){
			write_name(generator, fd, expr->data.binding);
			return;
		}
		if (from_fat == 1){
			if (cstring_compare(&expr->data.binding.data.name, "ptr") == 0){
				write_name(generator, fd, expr->data.binding);
				return;
			}
			if (cstring_compare(&expr->data.binding.data.name, "len") == 0){
				write_name(generator, fd, expr->data.binding);
				return;
			}
		}
		token* memoized = token_map_access(generator->translated_names, expr->data.binding.data.name);
		if (memoized != NULL){
			write_name(generator, fd, *memoized);
		}
		else{
			token newname = {
				.content_tag = STRING_TOKEN_TYPE,
				.tag = IDENTIFIER_TOKEN,
				.index = 0,
				.data.name = ink_prefix(generator, &expr->data.binding.data.name)
			};
			token_map_insert(generator->translated_names, expr->data.binding.data.name, newname);
			write_name(generator, fd, newname);
		}
		if (term_ptr_map_access(generator->parse->terms, expr->data.binding.data.name) != NULL){
			if (free == 1){
				fprintf(fd, "()");
			}
		}
		break;
	case MUTATION_EXPR:
		ink_indent(fd, indent);
		write_expression(generator, fd, expr->data.mutation.left, 0, 1, 0);
		fprintf(fd, " = ");
		write_expression(generator, fd, expr->data.mutation.right, 0, 1, 0);
		break;
	case RETURN_EXPR:
		ink_indent(fd, indent);
		fprintf(fd, "return ");
		write_expression(generator, fd, expr->data.ret, 0, 1, 0);
		break;
	case SIZEOF_EXPR:
		ink_indent(fd, indent);
		fprintf(fd, "sizeof(");
		write_type(generator, fd, expr->data.size_type, NULL);
		fprintf(fd, ")");
		break;
	case REF_EXPR:
		ink_indent(fd, indent);
		fprintf(fd, "&(");
		write_expression(generator, fd, expr->data.ref, 0, 1, 0);
		fprintf(fd, ")");
		break;
	case DEREF_EXPR:
		ink_indent(fd, indent);
		fprintf(fd, "*(");
		write_expression(generator, fd, expr->data.deref, 0, 1, 0);
		fprintf(fd, ")");
		break;
	case IF_EXPR:
		ink_indent(fd, indent);
		fprintf(fd, "if (");
		write_expression(generator, fd, expr->data.if_statement.pred, 0, 1, 0);
		fprintf(fd, ")");
		write_expression(generator, fd, expr->data.if_statement.cons, indent, 1, 0);
		if (expr->data.if_statement.alt != NULL){
			fprintf(fd, "else\n");
			write_expression(generator, fd, expr->data.if_statement.cons, indent, 1, 0);
		}
		break;
	case FOR_EXPR:
		ink_indent(fd, indent);
		fprintf(fd, "for (");
		fprintf(fd, ";;");//TODO uh oh
		fprintf(fd, ")");
		write_expression(generator, fd, expr->data.for_statement.cons, indent, 1, 0);
		break;
	case WHILE_EXPR:
		ink_indent(fd, indent);
		fprintf(fd, "while (");
		write_expression(generator, fd, expr->data.if_statement.pred, 0, 1, 0);
		fprintf(fd, ")");
		write_expression(generator, fd, expr->data.if_statement.cons, indent, 1, 0);
		break;
	case MATCH_EXPR:
		assert(0);
		break;
	case CAST_EXPR:
		ink_indent(fd, indent);
		fprintf(fd, "(");
		write_type(generator, fd, expr->data.cast.target, NULL);
		fprintf(fd, ")(");
		write_expression(generator, fd, expr->data.cast.source, 0, 1, 0);
		fprintf(fd, ")");
		break;
	case BREAK_EXPR:
		ink_indent(fd, indent);
		fprintf(fd, "break");
		break;
	case CONTINUE_EXPR:
		ink_indent(fd, indent);
		fprintf(fd, "continue");
		break;
	case NOP_EXPR:
		break;
	case STRUCT_ACCESS_EXPR:
		ink_indent(fd, indent);
		write_expression(generator, fd, expr->data.access.left, 0, 1, 0);
		if (expr->data.access.left->type->tag == PTR_TYPE){
			fprintf(fd, "->");
		}
		else if (expr->data.access.left->type->tag == FAT_PTR_TYPE){
			if (cstring_compare(&expr->data.access.right->data.binding.data.name, "ptr") == 0){
				fprintf(fd, ".ptr");
				break;
			}
			else if (cstring_compare(&expr->data.access.right->data.binding.data.name, "len") == 0){
				fprintf(fd, ".len");
				break;
			}
			else{
				fprintf(fd, ".ptr->");
			}
		}
		else{
			fprintf(fd, ".");
		}
		write_expression(generator, fd, expr->data.access.right, 0, 0, 1);
		break;
	case ARRAY_ACCESS_EXPR:
		ink_indent(fd, indent);
		write_expression(generator, fd, expr->data.access.left, indent, 1, 0);
		if (expr->data.access.left->type->tag == FAT_PTR_TYPE){
			fprintf(fd, ".ptr");
		}
		fprintf(fd, "[");
		write_expression(generator, fd, &expr->data.access.right->data.list.lines[0], 0, 1, 0);
		fprintf(fd, "]");
		break;
	case FAT_PTR_EXPR:
		ink_indent(fd, indent);
		fprintf(fd, "{\n");
		ink_indent(fd, indent+1);
		fprintf(fd, ".ptr=");
		write_expression(generator, fd, expr->data.fat_ptr.left, 0, 1, 0);
		fprintf(fd, ",\n");
		ink_indent(fd, indent+1);
		fprintf(fd, ".len=");
		write_expression(generator, fd, expr->data.fat_ptr.right, 0, 1, 0);
		ink_indent(fd, indent+1);
		fprintf(fd, "\n}");
		break;
	}
}

void
replace_with_poly_binding(genc* const generator, token* const bind, type_ast* const expected_type){
	if (expected_type == NULL){
		return;
	}
	term_ptr_buffer* poly_funcs = term_ptr_buffer_map_access(generator->parse->implemented_terms, bind->data.name);
	if (poly_funcs != NULL){
		for (uint64_t i = 0;i<poly_funcs->count;++i){
			term_ast* term = poly_funcs->buffer[i];
			type_ast* type = term->type;
			if (type_equal(generator->parse, expected_type, type) == 1){
				*bind = term->name;
				return;
			}
		}
	}
}

void
generate_main(genc* const generator, FILE* fd){
	fprintf(fd, "int main(){\n\treturn usr_ink_main();\n}\n");
}

/* TODO
 * -ERROR REPORTING-----------------------------------------
 * error reporting as logging rather than single report
		 nearest type token function?
 * -CODE GENERATION-----------------------------------------
 * c code generation pass
 * 		I dont know what to do with for
 * 			for ; ; {
 *				will requires a whole rework
 * 			}
 * 		may need to do dependency resolution for the order the header file is generated in
 * 		more builtins, < > <= >= == != 
 * 		polyfunc should check if types are aliased or typedefs
 * 		all function calls should check if literal types are aliased or typedefs
 * 		constants to global definition so null works
 * 		test closures / partial application
 */

int
main(int argc, char** argv){
	if (argc <= 1){
		printf(" -h for help\n");
		return 0;
	}
	if (strncmp(argv[1], "-h", ERROR_STRING_MAX) == 0){
		printf(" compile program : ink infile.ink -o outfile\n");
		return 0;
	}
	if (argc < 4){
		printf(" not enough arguments, -h for help");
		return 0;
	}
	if (strncmp(argv[1], "-o", ERROR_STRING_MAX) == 0){
		compile_file(argv[3], argv[2]);
		return 0;
	}
	if (strncmp(argv[2], "-o", ERROR_STRING_MAX) != 0){
		printf("Expected -o to specify output file");
		return 0;
	}
	compile_file(argv[1], argv[3]);
	return 0;
}
