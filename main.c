#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include "capra.h"

MAP_IMPL(TOKEN);
MAP_IMPL(typedef_ast);
MAP_IMPL(alias_ast);
MAP_IMPL(typeclass_ast);
MAP_IMPL(implementation_ast);
MAP_IMPL(term_ast);

void
compile_file(const char* input, const char* output){
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
		fprintf(stderr, "Unable to allcoate buffer\n");
		pool_dealloc(&mem);
		return;
	}
	TOKEN_map keymap = TOKEN_map_init(&mem);
	keymap_fill(&keymap);
	pool token_mem = pool_alloc(TOKEN_ARENA_SIZE, POOL_STATIC);
	typedef_ast_map types = typedef_ast_map_init(&mem);
	alias_ast_map aliases = alias_ast_map_init(&mem);
	typeclass_ast_map typeclasses = typeclass_ast_map_init(&mem);
	implementation_ast_map implementations = implementation_ast_map_init(&mem);
	term_ast_map terms = term_ast_map_init(&mem);
	parser parse = {
		.mem = &mem,
		.token_mem = &token_mem,
		.keymap = &keymap,
		.tokens = NULL,
		.text = str,
		.text_index = 0,
		.token_count = 0,
		.token_index = 0,
		.err.str = NULL,
		.err.len = 0,
		.types = &types,
		.aliases = &aliases,
		.typeclasses = &typeclasses,
		.implementations = &implementations,
		.terms = &terms
	};
	lex_string(&parse);
	if (parse.err.str != NULL){
		printf("Failed to lex, ");
		string_print(&parse.err);
		printf("\n");
	}
#ifdef DEBUG
	show_tokens(parse.tokens, parse.token_count);
	printf("\n");
#endif
	parse_program(&parse);
	if (parse.err.str != NULL){
		printf("Failed to parse, ");
		string_print(&parse.err);
		printf("\n");
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
	parse->tokens = pool_request(parse->token_mem, sizeof(token));
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
		case AT_TOKEN:
		case COLON_TOKEN:
		case PIPE_TOKEN:
		case ASTERISK_TOKEN:
		case EQUAL_TOKEN:
			if (issymbol(parse->text.str[parse->text_index])){
				break;
			}
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
			if (c != '\''){
				string_set(parse->mem, &parse->err, "Expected '\'' to close character literal\n");
				return;
			}
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
		string_set(parse->mem, &parse->err, "Unknown symbol\n");
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
		case ASTERISK_TOKEN:
			printf("ASTERISK * ");
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
		default:
			printf("UNKNOWN_TOKEN_TYPE ??? ");
			break;
		}
	}
}

type_ast*
parse_type(parser* const parse, uint8_t named, TOKEN end){
	token* t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	uint8_t found = 0;
	type_ast* outer;
	if (t->tag == PAREN_OPEN_TOKEN){
		uint64_t save = parse->token_index;
		while (parse->token_index < parse->token_count){
			t = &parse->tokens[parse->token_index];
			parse->token_index += 1;
			if (t->tag == end){
				found = 0;
				break;
			}
			if (t->tag == DOUBLE_ARROW_TOKEN){
				found = 1;
				break;
			}
			if (t->tag == ARROW_TOKEN){
				found = 0;
				break;
			}
		}
		parse->token_index = save;
		if (found == 1){
			outer = pool_request(parse->mem, sizeof(type_ast));
			outer->tag = DEPENDENCY_TYPE;
			uint64_t capacity = 2;
			outer->data.dependency.typeclass_dependencies = pool_request(parse->mem, sizeof(string)*capacity);
			outer->data.dependency.dependency_typenames = pool_request(parse->mem, sizeof(string)*capacity);
			outer->data.dependency.dependency_count = 0;
			while (parse->token_index < parse->token_count){
				t = &parse->tokens[parse->token_index];
				parse->token_index += 1;
				if (t->tag == PAREN_CLOSE_TOKEN){
					t = &parse->tokens[parse->token_index];
					parse->token_index += 1;
					assert(t->tag == DOUBLE_ARROW_TOKEN);
					break;
				}
				if (outer->data.dependency.dependency_count == capacity){
					capacity *= 2;
					string* tc_depend = pool_request(parse->mem, sizeof(string)*capacity);
					string* depend_names = pool_request(parse->mem, sizeof(string)*capacity);
					for (uint64_t i = 0;i<outer->data.dependency.dependency_count;++i){
						tc_depend[i] = outer->data.dependency.typeclass_dependencies[i];
						depend_names[i] = outer->data.dependency.dependency_typenames[i];
					}
					outer->data.dependency.typeclass_dependencies = tc_depend;
					outer->data.dependency.dependency_typenames = depend_names;
				}
				assert(t->tag == IDENTIFIER_TOKEN);
				outer->data.dependency.typeclass_dependencies[outer->data.dependency.dependency_count] = t->data.name;
				t = &parse->tokens[parse->token_index];
				parse->token_index += 1;
				assert(t->tag == IDENTIFIER_TOKEN);
				outer->data.dependency.dependency_typenames[outer->data.dependency.dependency_count] = t->data.name;
				outer->data.dependency.dependency_count += 1;
				t = &parse->tokens[parse->token_index];
				parse->token_index += 1;
				if (t->tag == COMMA_TOKEN){
					continue;
				}
				else if (t->tag == PAREN_CLOSE_TOKEN){
					t = &parse->tokens[parse->token_index];
					parse->token_index += 1;
					assert(t->tag == DOUBLE_ARROW_TOKEN);
					break;
				}
			}
		}
		else {
			parse->token_index -= 1;
		}
	}
	else{
		parse->token_index -= 1;
	}
	type_ast* inner = parse_type_worker(parse, named, end);
	if (found == 1){
		outer->data.dependency.type = inner;
		return outer;
	}
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
		base->data.named.name = t->data.name;
		base->data.named.args = NULL;
		base->data.named.arg_count = 0;
		parametric = 1;
		break;
	case BRACK_OPEN_TOKEN:
		base->tag = FAT_PTR_TYPE;
		base->data.fat_ptr.ptr = parse_type_worker(parse, 0, BRACK_CLOSE_TOKEN);
		base->data.fat_ptr.len = 0;//TODO
		parse->token_index += 1;
		break;
	case PAREN_OPEN_TOKEN:
		*base = *parse_type_worker(parse, 0, PAREN_CLOSE_TOKEN);
		parse->token_index += 1;
		break;
	default:
		assert(0);
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
				base->data.named.arg_count += 1;
				break;
			case BRACK_OPEN_TOKEN:
				*arg = *parse_type_worker(parse, 0, BRACK_CLOSE_TOKEN);
				base->data.named.arg_count += 1;
				break;
			case IDENTIFIER_TOKEN:
				arg->tag = NAMED_TYPE;
				arg->data.named.name = t->data.name;
				arg->data.named.args = NULL;
				arg->data.named.arg_count = 0;
				base->data.named.arg_count += 1;
				break;
			case SYMBOL_TOKEN:
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
				assert (base->tag == NAMED_TYPE);
				assert(base->data.named.arg_count > 0);
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
		case ASTERISK_TOKEN:
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
			assert(parse->tokens[parse->token_index+1].tag == end);
			return base;
		}
	}
	assert(t->tag == end);
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
		assert(t->tag == BRACE_OPEN_TOKEN);
		capacity = 2;
		structure->data.structure.names = pool_request(parse->mem, sizeof(string)*capacity);
		structure->data.structure.members = pool_request(parse->mem, sizeof(structure_ast)*capacity);
		structure->data.structure.count = 0;
		while (parse->token_index < parse->token_count){
			type_ast* type = parse_type(parse, 1, SEMI_TOKEN);
			t = &parse->tokens[parse->token_index];
			parse->token_index += 1;
			assert(t->tag == IDENTIFIER_TOKEN || t->tag == SYMBOL_TOKEN);
			string name = t->data.name;
			t = &parse->tokens[parse->token_index];
			parse->token_index += 1;
			assert(t->tag == SEMI_TOKEN);
			if (structure->data.structure.count == capacity){
				capacity *= 2;
				string* names = pool_request(parse->mem, sizeof(string)*capacity);
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
		assert(t->tag == BRACE_OPEN_TOKEN);
		capacity = 2;
		structure->data.union_structure.names = pool_request(parse->mem, sizeof(string)*capacity);
		structure->data.union_structure.members = pool_request(parse->mem, sizeof(structure_ast)*capacity);
		structure->data.union_structure.count = 0;
		while (parse->token_index < parse->token_count){
			type_ast* type = parse_type(parse, 1, SEMI_TOKEN);
			t = &parse->tokens[parse->token_index];
			parse->token_index += 1;
			assert(t->tag == IDENTIFIER_TOKEN || t->tag == SYMBOL_TOKEN);
			string name = t->data.name;
			t = &parse->tokens[parse->token_index];
			parse->token_index += 1;
			assert(t->tag == SEMI_TOKEN);
			if (structure->data.union_structure.count == capacity){
				capacity *= 2;
				string* names = pool_request(parse->mem, sizeof(string)*capacity);
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
		assert(t->tag == BRACE_OPEN_TOKEN);
		capacity = 2;
		structure->data.enumeration.names = pool_request(parse->mem, sizeof(string)*capacity);
		structure->data.enumeration.values = pool_request(parse->mem, sizeof(uint64_t)*capacity);
		structure->data.enumeration.count = 0;
		uint64_t current_value = 0;
		while (parse->token_index < parse->token_count){
			t = &parse->tokens[parse->token_index];
			parse->token_index += 1;
			assert(t->tag == IDENTIFIER_TOKEN);
			if (structure->data.enumeration.count == capacity){
				capacity *= 2;
				string* names = pool_request(parse->mem, sizeof(string)*capacity);
				uint64_t* values = pool_request(parse->mem, sizeof(uint64_t)*capacity);
				for (uint64_t i = 0;i<structure->data.enumeration.count;++i){
					names[i] = structure->data.enumeration.names[i];
					values[i] = structure->data.enumeration.values[i];
				}
				structure->data.enumeration.names = names;
				structure->data.enumeration.values = values;
			}
			structure->data.enumeration.names[structure->data.enumeration.count] = t->data.name;
			t = &parse->tokens[parse->token_index];
			parse->token_index += 1;
			if (t->tag == EQUAL_TOKEN){
				t = &parse->tokens[parse->token_index];
				parse->token_index += 1;
				assert(t->tag == INTEGER_TOKEN);
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
			current_value += 1;
			if (t->tag == BRACE_CLOSE_TOKEN){
				break;
			}
			assert(t->tag == COMMA_TOKEN);
		}
		break;
	default:
		assert(0);
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
			string_print(&type->data.dependency.typeclass_dependencies[i]);
			printf(" ");
			string_print(&type->data.dependency.dependency_typenames[i]);
		}
		printf(") => ");
		show_type(type->data.dependency.type);
		break;
	case FUNCTION_TYPE:
		show_type(type->data.function.left);
		printf(" -> ");
		show_type(type->data.function.right);
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
		string_print(&type->data.named.name);
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
			string_print(&s->data.structure.names[i]);
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
			string_print(&s->data.structure.names[i]);
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
			string_print(&s->data.enumeration.names[i]);
			printf("=%lu", s->data.enumeration.values[i]);
		}
		printf("}");
	}
}

void
parse_program(parser* const parse){
	type_ast* a = parse_type(parse, 1, SEMI_TOKEN);
	show_type(a);
	printf("\n");
	parse->token_index += 2;
	type_ast* b = parse_type(parse, 1, SEMI_TOKEN);
	show_type(b);
	printf("\n");
	parse->token_index += 2;
	type_ast* c = parse_type(parse, 1, EQUAL_TOKEN);
	show_type(c);
	printf("\n");
	parse->token_index += 2;
	type_ast* d = parse_type(parse, 1, EQUAL_TOKEN);
	show_type(d);
	printf("\n");
	parse->token_index += 2;
	type_ast* e = parse_type(parse, 0, SEMI_TOKEN);
	show_type(e);
	printf("\n");
	parse->token_index += 1;
	type_ast* f = parse_type(parse, 1, SEMI_TOKEN);
	show_type(f);
	printf("\n");
	parse->token_index += 2;
	type_ast* g = parse_type(parse, 0, SEMI_TOKEN);
	show_type(g);
	printf("\n");
	parse->token_index += 1;
	alias_ast* alias = parse_alias(parse);
	show_alias(alias);
	printf("\n");
	parse->token_index += 1;
	typedef_ast* type = parse_typedef(parse);
	show_typedef(type);
	printf("\n");
	parse->token_index += 1;
	typeclass_ast* class = parse_typeclass(parse);
	show_typeclass(class);
	printf("\n");
}

alias_ast*
parse_alias(parser* const parse){
	token* t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert(t->tag == ALIAS_TOKEN);
	t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert(t->tag == IDENTIFIER_TOKEN);
	alias_ast* alias = pool_request(parse->mem, sizeof(alias_ast));
	alias->name = t->data.name;
	t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert(t->tag == EQUAL_TOKEN);
	alias->type = parse_type(parse, 0, SEMI_TOKEN);
	return alias;
}

typedef_ast*
parse_typedef(parser* const parse){
	token* t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert(t->tag == TYPE_TOKEN);
	t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert(t->tag == IDENTIFIER_TOKEN);
	typedef_ast* type = pool_request(parse->mem, sizeof(typedef_ast));
	type->name = t->data.name;
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
	type->params = pool_request(parse->mem, sizeof(string)*type->param_count);
	for (uint64_t i = 0;i<type->param_count;++i){
		t = &parse->tokens[parse->token_index];
		parse->token_index += 1;
		assert(t->tag == IDENTIFIER_TOKEN);
		type->params[i] = t->data.name;
	}
	t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert(t->tag == EQUAL_TOKEN);
	type->type = parse_type(parse, 0, SEMI_TOKEN);
	return type;
}

void
show_alias(alias_ast* const alias){
	printf("alias ");
	string_print(&alias->name);
	printf(" = ");
	show_type(alias->type);
}

void
show_typedef(typedef_ast* const type){
	printf("type ");
	string_print(&type->name);
	for (uint64_t i = 0;i<type->param_count;++i){
		printf(" ");
		string_print(&type->params[i]);
	}
	printf(" = ");
	show_type(type->type);
}

typeclass_ast*
parse_typeclass(parser* const parse){
	token* t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert(t->tag == TYPECLASS_TOKEN);
	t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert(t->tag == IDENTIFIER_TOKEN);
	typeclass_ast* class = pool_request(parse->mem, sizeof(typeclass_ast));
	class->name = t->data.name;
	t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert(t->tag == IDENTIFIER_TOKEN);
	class->param = t->data.name;
	t = &parse->tokens[parse->token_index];
	parse->token_index += 1;
	assert(t->tag == BRACE_OPEN_TOKEN);
	uint64_t capacity = 2;
	class->member_count = 0;
	class->members = pool_request(parse->mem, sizeof(term_ast)*capacity);
	while (parse->token_index < parse->token_count){
		type_ast* type = parse_type(parse, 1, SEMI_TOKEN);
		t = &parse->tokens[parse->token_index];
		parse->token_index += 2;
		term_ast term = {
			.type = type,
			.name = t->data.name,
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
	//TODO
	return NULL;
}

void
show_typeclass(typeclass_ast* const class){
	printf("typeclass ");
	string_print(&class->name);
	printf(" ");
	string_print(&class->param);
	printf(" {");
	for (uint64_t i = 0;i<class->member_count;++i){
		show_type(class->members[i].type);
		printf(" ");
		string_print(&class->members[i].name);
		printf("; ");
	}
	printf("}");
}

void
show_implementation(implementation_ast* const impl){
	
}

int
main(int argc, char** argv){
	compile_file("types.n", "test");
	return 0;
}
