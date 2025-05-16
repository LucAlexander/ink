#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "ink.h"

MAP_IMPL(TOKEN);
MAP_IMPL(typedef_ast);
MAP_IMPL(alias_ast);
MAP_IMPL(const_ast);
MAP_IMPL(typeclass_ast);
MAP_IMPL(implementation_ast);
MAP_IMPL(implementation_ast_map);
MAP_IMPL(term_ast);
MAP_IMPL(uint64_t);

GROWABLE_BUFFER_IMPL(typedef_ast);
GROWABLE_BUFFER_IMPL(alias_ast);
GROWABLE_BUFFER_IMPL(const_ast);
GROWABLE_BUFFER_IMPL(typeclass_ast);
GROWABLE_BUFFER_IMPL(implementation_ast);
GROWABLE_BUFFER_IMPL(term_ast);

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
		parse->err.len = ERROR_STRING_MAX;\
		parse->err_token = i;\
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
	typedef_ast_map types = typedef_ast_map_init(&mem);
	alias_ast_map aliases = alias_ast_map_init(&mem);
	const_ast_map constants = const_ast_map_init(&mem);
	typeclass_ast_map typeclasses = typeclass_ast_map_init(&mem);
	implementation_ast_map_map implementations = implementation_ast_map_map_init(&mem);
	term_ast_map terms = term_ast_map_init(&mem);
	uint64_t_map imported = uint64_t_map_init(&mem);
	uint64_t_map enum_vals = uint64_t_map_init(&mem);
	parser parse = {
		.mem = &mem,
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
		.enumerated_values = &enum_vals
	};
	parse.tokens = pool_request(parse.token_mem, sizeof(token));
	lex_string(&parse);
	if (parse.err.len != 0){
		printf("\033[1m[!] Failed to lex, \033[0m");
		string_print(&parse.err);
		printf("\n");
	}
#ifdef DEBUG
	show_tokens(parse.tokens, parse.token_count);
	printf("\n");
#endif
	parse_program(&parse);
	if (parse.err.len != 0){
		printf("\033[1m[!] Failed to parse, \033[0m");
		show_error(&parse);
	}
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
}

uint8_t
issymbol(char c){
	return (
		(c > ' ' && c < '0') ||
		(c > ';' && c < 'A') ||
		(c > '[' && c < '_') ||
		(c == '~') ||
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
		case AMPERSAND_TOKEN:
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
			pool_request(parse->token_mem, sizeof(token));
			parse->token_count += 1;
			t = &parse->tokens[parse->token_count];
			continue;
		}
		else if (isdigit(c) || c == '-'){ // TODO floats
			t->tag = INTEGER_TOKEN;
			t->content_tag = UINT_TOKEN_TYPE;
			t->data.pos = 0;
			uint8_t neg = 0;
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
			while (parse->text_index < parse->text.len){
				if (isdigit(c) == 0){
					parse->text_index -= 1;
					break;
				}
				t->data.pos *= 10;
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
		assert_local(0, , "Unknown symbol");
		return;
	}
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
		base->data.fat_ptr.len = 0;//TODO
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
			case STRUCT_TOKEN:
			case UNION_TOKEN:
			case ENUM_TOKEN:
				arg->tag = STRUCT_TYPE;
				arg->data.structure = parse_struct_type(parse);
				parse->token_index -= 1;
				base->data.named.arg_count += 1;
				break;
			case PAREN_OPEN_TOKEN:
				*arg = *parse_type_worker(parse, 0, PAREN_CLOSE_TOKEN);
				assert_prop(NULL);
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
		case CONSTANT_TOKEN:
			const_ast* constant = parse_constant(parse);
			if (parse->err.len == 0){
				uint8_t dup = const_ast_map_insert(parse->constants, constant->name.data.name, *constant);
				assert_local(dup == 0, , "Duplicate constant definition");
				const_ast_buffer_insert(&parse->const_list, *constant);
#ifdef DEBUG
				show_constant(constant);
				printf("\n");
#endif
			}
			break;
		case ALIAS_TOKEN:
			alias_ast* alias = parse_alias(parse);
			if (parse->err.len == 0){
				uint8_t dup = alias_ast_map_insert(parse->aliases, alias->name.data.name, *alias);
				assert_local(dup==0, , "Duplicate alias definition");
				parse->token_index += 1;
				alias_ast_buffer_insert(&parse->alias_list, *alias);
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
				uint8_t dup = typedef_ast_map_insert(parse->types, type->name.data.name, *type);
				assert_local(dup==0, , "Duplicate type definition");
				parse->token_index += 1;
				typedef_ast_buffer_insert(&parse->type_list, *type);
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
				uint8_t dup = typeclass_ast_map_insert(parse->typeclasses, class->name.data.name, *class);
				assert_local(dup==0, , "Duplicate typeclass definition");
				parse->token_index += 1;
				typeclass_ast_buffer_insert(&parse->typeclass_list, *class);
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
					implementation_ast_map* map = implementation_ast_map_map_access(parse->implementations, impl->type.data.name);
					if (map == NULL){
						implementation_ast_map init = implementation_ast_map_init(parse->mem);
						implementation_ast_map_insert(&init, impl->typeclass.data.name, *impl);
						uint8_t dup = implementation_ast_map_map_insert(parse->implementations, impl->type.data.name, init);
						assert_local(dup == 0, , "Duplicate implementation definition");
						implementation_ast_buffer_insert(&parse->implementation_list, *impl);
#ifdef DEBUG
						show_implementation(impl);
						printf("\n");
#endif
						continue;
					}
					uint8_t dup = implementation_ast_map_insert(map, impl->typeclass.data.name, *impl);
					assert_local(dup==0, , "Duplicate implementation definition");
					implementation_ast_buffer_insert(&parse->implementation_list, *impl);
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
					uint8_t dup = term_ast_map_insert(parse->terms, term->name.data.name, *term);
					assert_local(dup==0, , "Duplicate term definition");
					term_ast_buffer_insert(&parse->term_list, *term);
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
	printf(" = ");
	show_expression(term->expression);
}

void
show_expression(expr_ast* expr){
	switch(expr->tag){
	case APPL_EXPR:
		printf("(");
		show_expression(expr->data.appl.left);
		printf(" ");
		show_expression(expr->data.appl.right);
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
		break;
	case DEREF_EXPR:
		printf("^");
		break;
	case IF_EXPR:
		printf("if ");
		show_expression(expr->data.if_statement.pred);
		show_expression(expr->data.if_statement.cons);
		if (expr->data.if_statement.alt != NULL){
			show_expression(expr->data.if_statement.alt);
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
		named->data.named.name = *outer;
		parse->token_index += 1;
		named->data.named.inner = parse_pattern(parse);
		return named;
	}
	if (t->tag == EQUAL_TOKEN){ // left=x
		assert_local(outer->tag == IDENTIFIER_TOKEN, NULL, "expected identifier for union selector name");
		pattern_ast* union_select = pool_request(parse->mem, sizeof(pattern_ast));
		union_select->tag = UNION_SELECTOR_PATTERN;
		union_select->data.union_selector.member = *outer;
		parse->token_index += 1;
		union_select->data.union_selector.nest = parse_pattern(parse);
		return union_select;
	}
	pattern_ast* pat = pool_request(parse->mem, sizeof(pattern_ast));
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
	}
}

expr_ast*
parse_expr(parser* const parse, TOKEN end){
	token* t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	expr_ast* expr = pool_request(parse->mem, sizeof(expr_ast));
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
			break;
		case AS_TOKEN:
			assert_local(outer->tag == APPL_EXPR, NULL, "Expected expression as source of cast");
			expr_ast* source = outer->data.appl.left;
			outer->tag = CAST_EXPR;
			outer->data.cast.source = source;
			outer->data.cast.target = parse_type(parse, 0, end);
			assert_prop(NULL);
			parse->token_index += 1;
			return outer;
		case SYMBOL_TOKEN:
		case COMPOSE_TOKEN:
			expr->tag = BINDING_EXPR;
			expr->data.binding = *t;
			if (outer->tag == APPL_EXPR){
				expr_ast* swap = outer->data.appl.left;
				outer->data.appl.left = outer->data.appl.right;
				outer->data.appl.right = swap;
			}
			break;
		case BREAK_TOKEN:
		case CONTINUE_TOKEN:
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
			break;
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
						save = parse->token_index;
						parse->token_index += 2;
						expr_ast* temp = parse_expr(parse, COMMA_TOKEN);
						assert_prop(NULL);
						expr->data.constructor.members[expr->data.constructor.member_count] = *temp;
						if (parse->err.len != 0){
							parse->token_index = save;
							parse->err.len = 0;
							temp = parse_expr(parse, BRACK_CLOSE_TOKEN);
							assert_prop(NULL);
							expr->data.constructor.members[expr->data.constructor.member_count] = *temp;
							expr->data.constructor.member_count += 1;
							break;
						}
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
			break;
		case AMPERSAND_TOKEN:
			expr->tag = REF_EXPR;
			expr->data.ref = parse_expr(parse, end);
			break;
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
				assert_local(t->tag == BRACE_OPEN_TOKEN, NULL, "expected { for pattern case in match");
				expr_ast* case_expr = parse_expr(parse, BRACE_CLOSE_TOKEN);
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
			}
			else if (t->content_tag == INT_TOKEN_TYPE){
				expr->data.literal.data.i = t->data.neg;
			}
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
		temp->data.appl.left = outer;
		temp->data.appl.right = pool_request(parse->mem, sizeof(expr_ast));
		expr = temp->data.appl.right;
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
		case AMPERSAND_TOKEN:
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
		else if (isdigit(c) || c == '-'){ // TODO floats
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
type_ast*
walk_expr(walker* const walk, expr_ast* const expr, type_ast* expected_type){
	uint64_t scope_pos = walk->local_scope->binding_count;
	structure_ast* inner;
	type_ast* inner_struct
	if (expected_type != NULL){
		inner_struct = expected_type;
		if (expr->tag != BINDING_EXPR){
			expected_type = reduce_alias_and_type(walk->parse, expected_type);
		}
		if (inner_struct->tag == STRUCT_TYPE){
			inner = inner_struct->data.structure;
			if (inner->tag == UNION_STRUCT){
				for (uint64_t k = 0;k<inner->data.union_structure.count;++k){
					type_ast* match_inference = walk_expr(walk, expr, inner->data.union_structure.members[k]);
					if (match_inference == NULL){
						walk->parse->err.len = 0;
						continue;
					}
					expr->type = expected_type;
					pop_binding(walk->local_scope, pos);
					expr->type = expected_type;
					return expected_type;
				}
				pop_binding(walk->local_scope, pos);
				expr->type = NULL;
				return NULL;
			}
		}
	}
	switch (expr->tag){
	case APPL_EXPR: // TODO template type application, type dependency, . handling
		type_ast* right = walk_expr(walk, expr->data.appl.right, NULL);
		walk_assert_prop();
		walk_assert(right != NULL, nearest_token(expr->data.appl.right), "Could not discern type");
		if (expected_type != NULL){
			type_ast* left = pool_request(walk->parse->mem, sizeof(type_ast));
			left->tag = FUNCTION_TYPE;
			left->data.function.left = right;
			left->data.function.right = expected_type;
			type_ast* confirm = walk_expr(walk, expr->data.appl.left, left);
			walk_assert_prop();
			walk_assert(confirm != NULL, nearest_token(expr->data.appl.left), "Left type of application expression did not match expected type inferred from right of application");
			pop_binding(walk->local_scope, pos);
			expr->type = expected_type;
			return expected_type;
		}
		type_ast* left = walk_expr(walk, expr->data.appl.left, NULL);
		walk_assert_prop();
		walk_assert(left != NULL, nearest_token(expr->data.appl.left), "Unable to infer type of left of application");
		walk_assert(left->tag == FUNCTION_TYPE, nearest_token(expr->data.appl.left), "Left of application type was needs to be function");
		walk_assert(type_equal(left->data.function.left, right), nearest_token(expr->data.appl.left), "First argument of left side of application did not match right side of application");
		pop_binding(walk->local_scope, pos);
		expr->type = left->data.function.right;
		return left->data.function.right;
	case LAMBDA_EXPR: // TODO
		walk_expr(walk, expr->data.lambda.expression);
		walk_expr(walk, expr->data.lambda.alt);
		break;
	case BLOCK_EXPR:
		for (uint64_t i = 0;i<expr->data.block.line_count;++i){
			if (expr->data.block.lines[i].tag == RETURN_EXPR){
				type_ast* line_type = walk_expr(walk, &expr->data.block.lines[i], expected_type);
				walk_assert_prop();
				if (expected_type != NULL){
					walk_assert(line_type != NULL, nearest_token(&expr->data.block.lines[i]), "Return expression did not resolve to correct type");
				}
				continue;
			}
			walk_expr(walk, &expr->data.block.lines[i], NULL); // TODO test what happens for nested returns, do they get validated or are their types ignored
			walk_assert_prop();
		}
		if (expected_type != NULL){
			walk_assert(expr->data.block.lines[expr->data.block.line_count-1].tag == RETURN_EXPR);
		}
		pop_binding(walk->local_scope, pos);
		expr->type = expected_type;
		return expected_type;
	case LIT_EXPR:
		if (expected_type != NULL){
			type_ast lit_type = {
				.tag = LIT_TYPE,
				.data.lit = INT_ANY
			};
			walk_assert(type_equal(expected_type, &lit_type), nearest_token(expr), "Literal integer type assigned to non matching type");
			pop_binding(walk->local_scope, pos);
			expr->type = expected_type;
			return expected_type;
		}
		type_ast* lit_type = pool_request(walk->parse->mem, sizeof(type_ast));i
		lit_type->tag = LIT_TYPE;
		lit_type->data.lit = INT_ANY;
		pop_binding(walk->local_scope, pos);
		expr->type = lit_type;
		return lit_type;
	case TERM_EXPR:
		type_ast* term_type = walk_term(walk, expr->data.term, expected_type);
		expr->type = term_type;
		return term_type;
	case STRING_EXPR:
		if (expected_type == NULL){
			type_ast* string_type = pool_request(walk->parse->mem, sizeof(type_ast));
			string_type->tag = PTR_TYPE;
			string_type->data.ptr = pool_request(walk->parse->mem, sizeof(type_ast));
			string_type->data.ptr->tag = LIT_TYPE;
			string_type->data.ptr->data.lit = U8_TYPE;
			pop_binding(walk->local_scope, pos);
			expr->type = string_type;
			return string_type;
		}
		walk_assert(expected_type->tag == PTR_TYPE || expected_type->tag == FAT_PTR_TYPE, nearest_token(expr), "String must be assigned to [u8] or u8^");
		if (expected_type->tag == FAT_PTR_TYPE){
			walk_assert(expected_type->data.fat_ptr.ptr->tag == LIT_TYPE && expected_type->data.fat_ptr.ptr->data.lit = U8_TYPE, nearest_token(expr), "String must be assigned to [u8] or u8^");
			pop_binding(walk->local_scope, pos);
			expr->type = expected_type;
			return expected_type;
		}
		walk_assert(expected_type->data.ptr->tag == LIT_TYPE && expected_type->data.ptr->data.lit = U8_TYPE, nearest_token(expr), "String must be assigned to [u8] or u8^");
		pop_binding(walk->local_scope, pos);
		expr->type = expected_type;
		return expected_type;
	case LIST_EXPR:
		if (expected_type == NULL){
			type_ast* first;
			for (uint64_t i = 0;i<expr->data.block.line_count;++i){
				if (i == 0){
					first = walk_expr(walk, &expr->data.block.lines[i], NULL);
					walk_assert_prop();
					walk_assert(first != NULL, nearest_token(expr), "List element not able to resolve to type");
					continue;
				}
				type_ast* rest = walk_expr(walk, &expr->data.block.lines[i], first);
				walk_assert_prop();
				walk_assert(rest != NULL, nearest_token(expr), "List element not able to resolve to type");
			}
			pop_binding(walk->local_scope, pos);
			expr->type = first;
			return first;
		}
		walk_assert(expected_type->tag == FAT_PTR_TYPE || expected_type->tag == PTR_TYPE, nearest_token(expr), "List assignment to non pointer type");
		if (expected_type->tag == FAT_PTR_TYPE){
			for (uint64_t i = 0;i<expr->data.block.line_count;++i){
				type_ast* rest walk_expr(walk, &expr->data.block.lines[i], expected_type->data.fat_ptr.ptr);
				walk_assert_prop();
				walk_assert(rest != NULL, nearest_token(expr), "List element not able to resolve to type");
			}
			pop_binding(walk->local_scope, pos);
			expr->type = expected_type;
			return expected_type;
		}
		for (uint64_t i = 0;i<expr->data.block.line_count;++i){
			type_ast* rest walk_expr(walk, &expr->data.block.lines[i], expected_type->data.ptr);
			walk_assert_prop();
			walk_assert(rest != NULL, nearest_token(expr), "List element not able to resolve to type");
		}
		pop_binding(walk->local_scope, pos);
		expr->type = expected_type;
		return expected_type;
	case STRUCT_EXPR:
		walk_assert(expected_type != NULL, nearest_token(expr), "Unable to infer type of structure");
		if (inner->tag == STRUCT_STRUCT){
			uint64_t current_member = 0;
			for (uint64_t i = 0;i<expr->data.constructor.member_count;++i){
				if (expr->data.constructor.names[i] != NULL){
					uint8_t found = 0;
					for (uint64_t k = 0;k<inner->data.structure.count;++k){
						if (string_compare(&inner->data.structure.names[i].data.name, &expr->data.constructur.names[i].data.name) == 0){
							type_ast* inferred = walk_expr(walk, &expr->data.constructor.members[i], &inner->data.structure.members[k]);
							walk_assert_prop();
							walk_assert(inferred != NULL, nearest_token(&expr->data.constructor.members[i]_, "Unexpected type for structure member");
							current_member = k+1;
							found = 1;
						}
					}
					walk_assert(found == 1, expr->data.constructor.names[i].token_index, "Unknown member of structure or union");
					continue;
				}
				walk_assert(current_member >= inner->data.structure.count, &expr->data.constructor.names[i].token_index, "Extra member in constructor");
				type_ast* inferred = walk_expr(walk, &expr->data.constructor.members[i], &inner->data.structure.members[current_member]);
				walk_assert_prop();
				walk_assert(inferred != NULL, nearest_token(&expr->data.constructor.members[i]), "Unexpected type for structure member");
				current_member += 1;
			}
			expr->type = expected_type;
			pop_binding(walk->local_scope, pos);
			expr->type = expected_type;
			return expected_type;
		}
		walk_assert(inner->tag == ENUM_STRUCT, nearest_token(expr), "Expected enumerator value");
		walk_assert(expr->data.constructor.member_count == 1, nearest_token(expr), "Constructed enumerator requires 1 and only 1 value");
		type_ast* enum_type = walk_expr(walk, expr->data.constructor.members[0], inner_struct);
		expr->type = enum_type;
		return enum_type;
	case BINDING_EXPR:
		type_ast* actual = in_scope(walk, &expr->data.binding, expected_type);
		walk_assert(actual != NULL, nearest_token(expr), "Binding not found in scope");
		if (expected_type == NULL){
			pop_binding(walk->local_scope, pos);
			expr->type = actual;
			return actual;
		}
		walk_assert(type_equal(actual, expected), nearest_token(expr), "Binding was not the expected type");
		pop_binding(walk->local_scope, pos);
		expr->type = actual;
		return actual;
	case MUTATION_EXPR:
		walk_assert(expected_type == NULL);
		type_ast* mut_left = walk_expr(walk, expr->data.mutation.left, NULL);
		walk_assert_prop();
		walk_assert(mut_left != NULL, nearest_token(expr->data.mutation.left), "Left side of mutation did not resolve to a type");
		type_ast* mut_right = walk_expr(walk, expr->data.mutation.right, mut_left);;
		walk_assert_prop();
		walk_assert(mut_right != NULL, nearest_token(expr->data.mutation.right), "Left side of mutation did not match type of right side");
		pop_binding(walk->local_scope, pos);
		expr->type = NULL;
		return NULL;
	case RETURN_EXPR:
		type_ast* ret_type = walk_expr(walk, expr->data.ret, expected_type);
		pop_binding(walk->local_scope, pos);
		expr->type = ret_type;
		return ret_type;
	case SIZEOF_EXPR:
		type_ast* sizeof_type = pool_request(walk->parse->mem, sizeof(type_ast));
		sizeof_type->tag = LIT_TYPE,
		sizeof_type->data.lit = U64_TYPE
		if (expected_type == NULL){
			pop_binding(walk->local_scope, pos);
			expr->type = sizeof_type;
			return sizeof_type;
		}
		walk_assert(type_equals(sizeof_type, expected_type), nearest_token(expr), "Expected type did not match type of sizeof expression (u64 or int_any)");
		pop_binding(walk->local_scope, pos);
		expr->type = sizeof_type;
		return sizeof_type;
	case REF_EXPR:
		if (expected_type == NULL){
			type_ast* ref_infer = walk_expr(walk, expr->data.ref, NULL);
			walk_assert_prop();
			walk_assert(ref_infer != NULL, nearest_token(expr), "Unable to infer type to reference");
			type_ast* ref = pool_request(walk->parse->mem, sizeof(type_ast));
			ref->tag = PTR_TYPE;
			ref->data.ptr = ref_infer;
			pop_binding(walk->local_scope, pos);
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
		type_ast* ref_infer = walk_expr(walk, expr->data.ref, ref_inner);
		walk_assert_prop();
		walk_assert(ref_infer != NULL, nearest_token(expr), "Reference to type did not match expected type reference");
		pop_binding(walk->local_scope, pos);
		expr->type = expected_type;
		return expected_type;
	case DEREF_EXPR:
		if (expected_type == NULL){
			type_ast* deref_infer = walk_expr(walk, expr->data.deref, NULL);
			walk_assert_prop();
			walk_assert(deref_infer != NULL, nearest_token(expr), "Unable to infer type to dereference");
			walk_assert(deref_infer->tag == PTR_TYPE || deref_infer->tag == FAT_PTR_TYPE, nearest_token(expr), "Expected pointer to dereference");
			if (deref_infer->tag == FAT_PTR_TYPE){
				pop_binding(walk->local_scope, pos);
				expr->type = deref_infer->data.fat_ptr.ptr;
				return deref_infer->data.fat_ptr.ptr;
			}
			pop_binding(walk->local_scope, pos);
			expr->type = deref_infer->data.ptr;
			return deref_infer->data.ptr;
		}
		type_ast expected_ptr = {
			.tag = PTR_TYPE,
			.data.ptr = expected_type
		};
		type_ast* deref_infer = walk_expr(walk, expr->data.deref, &expected_ptr);
		walk_assert_prop();
		walk_assert(deref_infer != NULL, nearest_token(expr), "Expected pointer to dereference");
		pop_binding(walk->local_scope, pos);
		expr->type = expected_type;
		return expected_type;
	case IF_EXPR:
		type_ast if_predicate = {
			.tag = LIT_TYPE,
			.data.lit = INT_ANY
		};
		type_ast* ifpredtype = walk_expr(walk, expr->data.if_statement.pred, &if_predicate);
		walk_assert_prop();
		walk_assert(ifpredtype != NULL, nearest_token(expr->data.if_statement.pred), "If predicate must be integral");
		if (expected_type != NULL){
			type_ast* cons_type = walk_expr(walk, expr->data.if_statement.cons, NULL);
			walk_assert_prop();
			walk_assert(type_equal(const_type, expected_type), nearest_token(expr->data.if_statement.cons), "If statement consequent did not resolve to expected type");
			if (expr->data.if_statement.alt != NULL){
				type_ast* alt_type = walk_expr(walk, expr->data.if_statement.alt, cons_type);
			   	walk_assert_prop();
				walk_assert(alt_type != NULL, nearest_token(expr->data.if_statement.alt), "If alternate must be same type as cons when if statement is used as expression");
			}
			pop_binding(walk->local_scope, pos);
			expr->type = cons_type;
			return cons_type;
		}
		type_ast* cons_type = walk_expr(walk, expr->data.if_statement.cons, NULL);
		walk_assert_prop();
		walk_assert(const_type != NULL, nearest_token(expr->data.if_statement.cons), "If statement consequent did not resolve to a type");
		if (expr->data.if_statement.alt != NULL){
			if (walk_expr(walk, expr->data.if_statement.alt, const_type) == NULL){
				pop_binding(walk->local_scope, pos);
				expr->type = NULL;
				return NULL;
			}
		}
		pop_binding(walk->local_scope, pos);
		expr->type = cons_type;
		return cons_type;
	case FOR_EXPR:
		walk_assert(expected_type == NULL, nearest_token(expr), "Iterative loops cannot be used as expressions");
		type_ast for_type = {
			.tag = LIT_TYPE,
			.data.lit = INT_ANY
		};
		type_ast* forinittype = walk_expr(walk, expr->data.for_statement.initial, &for_type);
		walk_assert_prop();
	   	walk_assert(forinittype != NULL, nearest_token(expr->data.for_statement.initial), "For loop range must be integral");
		type_ast* forlimittype = walk_expr(walk, expr->data.for_statement.limit, &for_type);
		walk_assert_prop();
	   	walk_assert(forlimittype != NULL, nearest_token(expr->data.for_statement.limit), "For loop range must be integral");
		walk_expr(walk, expr->data.for_statement.cons, NULL);
		pop_binding(walk->local_scope, pos);
		expr->type = NULL;
		return NULL;
	case WHILE_EXPR:
		walk_assert(expected_type == NULL, nearest_token(expr), "Iterative loops cannot be used as expressions");
		type_ast while_predicate = {
			.tag = LIT_TYPE,
			.data.lit = INT_ANY
		};
		type_ast* whilepredtype = walk_expr(walk, expr->data.while_statement.pred, &while_predicate);
		walk_assert_prop();
	   	walk_assert(whilepredtype != NULL, nearest_token(expr->data.while_statement.pred), "While predicate must be integral");
		walk_expr(walk, expr->data.while_statement.cons, NULL);
		pop_binding(walk->local_scope, pos);
		expr->type = NULL;
		return NULL;
	case MATCH_EXPR:
		type_ast* match_infer = walk_expr(walk, expr->data.match.pred, NULL);
		walk_assert(match_infer != NULL, nearest_token(expr->data.match.pred), "Could not infer type of match predicate");
		if (expected_type != NULL){
			for (uint64_t i = 0;i<expr->data.match.count;++i){
				type_ast* pat_confirm = walk_pattern(walk, &expr->data.match.patterns[i], match_infer);
				walk_assert_prop();
				walk_assert(pat_confirm != NULL, nearest_pattern_token(&expr->data.match.patterns[i]), "Pattern in match did not resolve to correct type");
				type_ast* confirm = walk_expr(walk, &expr->data.match.cases[i], expected_type);
				walk_assert_prop();
				walk_assert(confirm != NULL, nearest_token(&expr->data.match.cases[i]), "Match case did not resolve to expected type");
			}
			pop_binding(walk->local_scope, pos);
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
				first = walk_expr(walk, &expr->data.match.cases[i], NULL);
				walk_assert_prop();
				pop_binding(walk->local_scope, pos);
				continue;
			}
			if (walk_expr(walk, &expr->data.match.cases[i], first) == NULL){
				matches = 0;
			}
			walk_assert_prop();
		}
		if (matches == 0){
			pop_binding(walk->local_scope, pos);
			expr->type = NULL;
			return NULL;
		}
		pop_binding(walk->local_scope, pos);
		expr->type = first;
		return first;
	case CAST_EXPR:
		type_ast* cast_confirm = walk_expr(walk, expr->data.cast.source, NULL);
		walk_assert(cast_confirm != NULL, nearest_token(expr), "Could not infer source type of cast"):
		if (expected_type == NULL){
			pop_binding(walk->local_scope, pos);
			expr->type = expr->data.cast.target;
			return expr->data.cast.target;
		}
		walk_assert(type_equal(expected_type, expr->data.cast.target), nearest_token(expr), "Expected type did not match target type of cast");
		pop_binding(walk->local_scope, pos);
		expr->type = expr->data.cast.target;
		return expr->data.cast.target;
	case NOP_EXPR:
		walk_assert(expected_type == NULL, nearest_token(expr), "Expected type, found NOP expression");
		pop_binding(walk->local_scope, pos);
		expr->type = NULL;
		return NULL;
	}
}

type_ast*
walk_term(walker* const walk, term_ast* const term, type_ast* expected_type){
	uint64_t pos = push_binding(walk->local_scope, term->name, term->type);//TODO check for duplicate
	type_ast* real_type = walk_expr(walk, term->expression, term->type);
	pop_binding(walk->local_scope, pos);
	walk_assert_prop();
	walk_assert(real_type != NULL, nearest_token(term->expression), "Term type did not match declared type");
	return term->type;
}

uint64_t
push_binding(scope* const s, token* const t, type_ast* const type){
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
		.type = type
	};
	s->bindings[s->binding_count] = b;
	s->binding_count += 1;
	return s->binding_count;
}

void
pop_binding(scope* const s, uint64_t pos){
	s->binding_count = pos;
}

type_ast*
reduce_alias(parser* const parse, type_ast* start_type){
	while (start_type->tag == NAMED_TYPE){
		alias_ast* alias = alias_ast_map_access(parse->aliases, start_type->data.named.name.data.name);
		if (alias == NULL){
			return start_type;
		}
		start_type = alias->type;
	}
	return start_type;
}

type_ast*
reduce_alias_and_type(parser* const parse, type_ast* start_type){
	while (start_type->tag == NAMED_TYPE){
		alias_ast* alias = alias_ast_map_access(parse->aliases, start_type->data.named.name.data.name);
		if (alias != NULL){
			start_type = alias->type;
			continue;
		}
		typedef_ast* type = typedef_ast_map_access(parse->types, start_type->data.named.name.data.name);
		if (type != NULL){
			if (start_type->data.named.arg_count != 0){
				type_ast_map relation = type_ast_map_init(parse->mem);
				assert_local(type->param_count >= start_type->data.named.arg_count, NULL, "Too many arguments given for parametric type\n");
				for (uint64_t i = 0;i<start_type->data.named.arg_count;++i){
					type_ast_map_insert(&relation, type->params[i].data.name, start_type->data.named.args[i]);
				}
				start_type = deep_copy_type_replace(parse->mem, &relation, type->type);
				continue;
			}
			start_type = type;
			continue;
		}
		return start_type;
	}
	return start_type;
}

type_ast*
in_scope(walker* const walk, token* const bind, type_ast* expected_type){
	expected_type = reduce_alias(walk->parse, expected_type)
	term_ast* term = term_ast_map_access(walk->parse->terms, bind->data.name);
	if (term != NULL){
		return term->type;
	}
	uint64_t* value = uint64_t_map_access(walk->parse->enumerated_values, bind->data.name);
	if (value != NULL){
		if (expected_type->tag != NULL){
			if ((expected_type->tag == STRUCT_TYPE) && (expected_type->data.structure->tag == ENUM_STRUCT)){
				for (uint64_t i = 0;i<expected_type->data.structure.data.enumeration.count;++i){
					if (string_compare(&expected_type->data.structure.data.enumeration.names[i].data.name, &bind->data.name) == 0){
						return expected_type;
					}
				}
			}
		}
		type_ast* any = pool_request(walk->parse->mem, sizeof(type_ast));
		u64->tag = LIT_TYPE;
		u64->data.lit = INT_ANY;
		return any;
	}
	for (uint64_t i = 0;i<walk->local_scope->binding_count;++i){
		if (string_compare(&bind->data.string, &walk->local_scope->bindings[i].name->data.name) == 0){
			return walk->local_scope->bindings[i].type;
		}
	}
	return NULL;
}

uint8_t
type_equal(type_ast* const left, type_ast* const right){
	if (left->tag != right->tag){
		return 0;
	}
	switch (left->tag){
	case DEPENDENCY_TYPE:
		//TODO
	case FUNCTION_TYPE:
		//TODO
	case LIT_TYPE:
		//TODO
	case PTR_TYPE:
		//TODO
	case FAT_PTR_TYPE:
		//TODO
	case STRUCT_TYPE:
		//TODO
	case NAMED_TYPE:
		//TODO
	}
	return 0;
}

uint64_t
nearest_token(expr_ast* const e){
	switch (e->tag){
	case APPL_EXPR:
		return nearest_token(e->data.appl.left);
	case LAMBDA_EXPR:
		return nearest_token(e->data.lambda.expression);
	case BLOCK_EXPR:
		if (e->data.block.line_count > 0){
			return nearest_token(e->data.block.lines[0]);
		}
		return 0;
	case LIT_EXPR:
		return 0;
	case TERM_EXPR:
		return e->data.term->name.token_index;
	case STRING_EXPR:
		return e->data.str.token_index;
	case LIST_EXPR:
		if (e->data.list.line_count > 0){
			return nearest_token(ex->data.list.lines[0]);
		}
		return 0;
	case STRUCT_EXPR:
		if (e->data.constructor.member_count > 0){
			return nearest_token(e->data.constructor.members[0]);
		}
		return 0;
	case BINDING_EXPR:
		return e->data.binding.token_index;
	case MUTATION_EXPR:
		return nearest_token(e->data.mutation.left);
	case RETURN_EXPR:
		return nearest_token(e->data.ret);
	case SIZEOF_EXPR:
		return nearest_token(e->data.size_type);
	case REF_EXPR:
		return nearest_token(e->data.ref);
	case DEREF_EXPR:
		return nearest_token(e->data.deref);
	case IF_EXPR:
		return nearest_token(e->data.if_statement.pred);
	case FOR_EXPR:
		return e->data.for_statement.binding.token_index;
	case WHILE_EXPR:
		return nearest_token(e->data.while_statement.pred);
	case MATCH_EXPR:
		return nearest_token(e->data.match.pred);
	case CAST_EXPR:
		return nearest_token(e->data.cast.source);
	case NOP_EXPR:
		return 0;
	}
	return 0;
}

type_ast*
deep_copy_type_replace(pool* const mem, type_ast_map* relation, type_ast* const source){
	type_ast* dest = pool_request(mem, sizeof(type_ast));
	*dest = *source;
	switch (source->tag){
	case DEPENDENCY_TYPE:
		dest->data.dependency.type = deep_copy_type_replace(mem, relation, source->data.dependency.type);
		return dest;
	case FUNCTION_TYPE:
		dest->data.function.left = deep_copy_type_replace(mem, relation, source->data.function.left);
		dest->data.function.right = deep_copy_type_replace(mem, relation, source->data.function.right);
		return dest;
	case LIT_TYPE:
		return dest;
	case PTR_TYPE:
		dest->data.ptr = deep_copy_type_replace(mem, relation, source->data.ptr);
		return dest;
	case FAT_PTR_TYPE:
		dest->data.fat_ptr.ptr = deep_copy_type_replace(mem, relation, source->data.fat_ptr.ptr);
		return dest;
	case STRUCT_TYPE:
		dest->data.structure = deep_copy_structure_replace(mem, relation, source->data.structure);
		return dest;
	case NAMED_TYPE:
		type_ast* replacement = type_ast_map_acceses(relation, source->data.named.name.data.name);
		if (replacement == NULL){
			for (uint64_t i = 0;i<source->data.named.arg_count;++i){
				dest->data.named.args[i] = *deep_cope_type_replace(mem, relation, &source->data.named.args[i])
			}
			return dest;
		}
		return deep_copy_replace(mem, relation, replacement);
	}
	return NULL;
}

structure_ast*
deep_copy_structure_replace(pool* const mem, type_ast_map* relation, structure_ast* const source){
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
}

type_ast*
walk_pattern(walker* const walk, pattern* const pat, type_ast* expected_type){
	expected_type = reduce_alias_and_type(walk->parse, expected_type);
	switch (pat->tag){
	case NAMED_PATTERN:
		push_binding(walk->local_scope, &pat->data.named.name, expecte_type);
		return walk_pattern(walk, pat->data.named.inner, expected_type);
	case STRUCT_PATTERN:
		walk_assert(expected_type->tag == STRUCT_TYPE, nearest_pattern_token(pat), "Tried to destructure non structure type as structure pattern");
		walk_assert(expected_type->data.structure->tag == STRUCT_STRUCT, nearest_pattern_token(pat),"Tried to destructure non structure structure type in pattern destructure");
		walk_assert(pat->data.structure.count == expected_type->data.structure->data.structure.count, nearest_pattern_token(pat), "Expected structure pattern destructure to match struct member count");
		for (uint64_t i = 0;i<pat->data.structure.count;++i){
			walk_pattern(walk, &pat->data.structure.member[i], &expected_type->data.structure->data.structure.members[i]);
			walk_assert_prop();
		}
		return expected_type;
	case FAT_PTR_PATTERN:
		walk_assert(expected_type->tag == FAT_PTR_TYPE, nearest_pattern_token(pat), "Expected fat pointer to destructure pattern");
		type_ast len_type = {
			.tag = LIT_TYPE,
			.data.lit = INT_ANY
		};
		walk_pattern(walk, pat->data.fat_ptr.len, &len_type);
		walk_assert_prop();
		walk_pattern(walk, pat->data.fat_ptr.ptr, expected_type->data.fat_ptr.ptr);
		return expected_type;
	case HOLE_PATTERN:
		return expected_type;
	case BINDING_PATTERN:
		push_binding(walk->local_scope, &pat->data.binding, expected_type);
		return expected_type;
	case LITERAL_PATTERN:
		walk_assert(expected_type->tag == LIT_TYPE, nearest_pattern_token(pat), "Tried to destructure non literal as literal pattern");
		return expected_type;
	case STRING_PATTERN:
		walk_assert(expected_type->tag == PTR_TYPE || expected_type->tag == FAT_PTR_TYPE, nearest_pattern_token(pat), "Tried to destructure non string type as string pattern");
		if (expected_type->tag == FAT_PTR_TYPE){
			walk_assert(expected_type->data.fat_ptr.ptr->tag == LIT_TYPE && expected_type->data.fat_ptr.ptr->data.lit == U8_TYPE, nearest_pattern_token(pat), "Destructuring a string must be from [u8] or u8^");
			return expected_type;
		}
		walk_assert(expected_type->data.ptr->tag == LIT_TYPE && expected_type->data.ptr.data.lit == U8_TYPE, nearest_pattern_token(pat), "String must be destructured from [u8] or u8^");
		return expected_type;
	case UNION_SELECTOR_PATTERN:
		walk_assert(expected_type->tag == STRUCT_TYPE, nearest_pattern_token(pat), "Expected union structure type to destructure");
		walk_assert(expected_type->data.structure->tag == UNION_STRUCT, nearest_pattern_token(pat), "Expected structure type to be union in pattern destructure");
		for (uint64_t i = 0;i<expected_type->data.structure->data.union_structure.count;++i){
			if (string_compare(&expected_type->data.structure->data.union_structure.names[i], &pat->data.union_selector.member) == 0){
				walk_pattern(walk, pat->data.union_selector.nest, &expected_type->data.structure->data.union_structure.members[i]);
				return expected_type;
			}
		}
		return NULL;
	}
	return NULL;
}

uint64_t
nearest_pattern_token(pattern* const pat){
	switch (pat->tag){
	case NAMED_PATTERN:
		return pat->data.named.name.token_index;
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
		return pat->data.binding.token_index;
	case LITERAL_PATTERN:
		return 0;
	case STRING_PATTERN:
		return pat->data.str.token_index;
	case UNION_SELECTOR_PATTERN:
		return nearest_pattern_token(pat->data.union_selector.nest);
	}
	return 0;
}

/* TODO
 * typeclass/implementation member tracking
 * scope checking on bindings + enumerated values
 * type inference and typed ast filling
 * type enforcement on bindings
 * alias reduction
 * structure/defined type monomorphization
 * lambda capture to arg and lifting
 * closure capture to arg and lifting
 * function type monomorphization
 * expression for break/continue was missed somehow, they are turned into bindings, fix this after the type checker is done, one problem at a time
 */

int
main(int argc, char** argv){
	compile_file("types.w", "test");
	return 0;
}
