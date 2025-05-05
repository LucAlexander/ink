#include <stdio.h>
#include <ctype.h>
#include "capra.h"

MAP_IMPL(TOKEN);

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
	parser parse = {
		.mem = &mem,
		.token_mem = &token_mem,
		.keymap = &keymap,
		.tokens = NULL,
		.text = str,
		.text_index = 0,
		.token_count = 0,
		.err.str = NULL,
		.err.len = 0
	};
	lex_string(&parse);
	if (parse.err.str != NULL){
		printf("Failed to lex, ");
		string_print(&parse.err);
		printf("\n");
	}
#ifdef DEBUG
	show_tokens(parse.tokens, parse.token_count);
#endif
	parse_string(&parse);
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
		t->name.str = &parse->text.str[parse->text_index];
		t->name.len = 0;
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
		case EQUAL_TOKEN:
		case BACKTICK_TOKEN:
		case COMPOSE_TOKEN:
		case SHIFT_TOKEN:
		case AMPERSAND_TOKEN:
		case HOLE_TOKEN:
			t->tag = c;
			pool_request(parse->token_mem, sizeof(token));
			parse->token_count += 1;
			t = &parse->tokens[parse->token_count];
			continue;
		case '"':
			t->tag = STRING_TOKEN;
			t->name.len += 1;
			while (parse->text_index < parse->text.len){
				c = parse->text.str[parse->text_index];
				parse->text_index += 1;
				if (c == '"'){
					t->name.len += 1;
					break;
				}
				t->name.len += 1;
			}
			pool_request(parse->token_mem, sizeof(token));
			parse->token_count += 1;
			t = &parse->tokens[parse->token_count];
			continue;
		case '\'':
			t->tag = CHAR_TOKEN;
			t->name.len += 2;
			c = parse->text.str[parse->text_index];
			parse->text_index += 1;
			if (c == '\\'){
				t->name.len += 1;
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
			t->pos = c;
			c = parse->text.str[parse->text_index];
			parse->text_index += 1;
			t->name.len += 1;
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
			t->name.len += 1;
			t->tag = IDENTIFIER_TOKEN;
			c = parse->text.str[parse->text_index];
			parse->text_index += 1;
			while ((parse->text_index < parse->text.len) && (isalpha(c) || c == '_' || isdigit(c))){
				t->name.len += 1;
				c = parse->text.str[parse->text_index];
				parse->text_index += 1;
			}
			parse->text_index -= 1;
			TOKEN* tok = TOKEN_map_access(parse->keymap, t->name);
			if (tok != NULL){
				t->tag = *tok;
			}
			pool_request(parse->token_mem, sizeof(token));
			parse->token_count += 1;
			t = &parse->tokens[parse->token_count];
			continue;
		}
		else if (issymbol(c)){
			t->name.len += 1;
			t->tag = SYMBOL_TOKEN;
			c = parse->text.str[parse->text_index];
			parse->text_index += 1;
			while ((parse->text_index < parse->text.len) && issymbol(c)){
				t->name.len += 1;
				c = parse->text.str[parse->text_index];
				parse->text_index += 1;
			}
			parse->text_index -= 1;
			TOKEN* tok = TOKEN_map_access(parse->keymap, t->name);
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
			t->pos = 0;
			uint8_t neg = 0;
			if (c == '-'){
				neg = 1;
				c = parse->text.str[parse->text_index];
				parse->text_index += 1;
			}
			if (c == '0'){
				c = parse->text.str[parse->text_index];
				parse->text_index += 1;
				if (c == 'x'){
					while (parse->text_index < parse->text.len){
						uint64_t last = t->pos;
						t->pos <<= 4;
						if (c >= '0' && c <= '9'){
							t->pos += (c - 48);
						}
						else if (c >= 'A' && c <= 'F'){
							t->pos += (c - 55);
						}
						else if (c >= 'a' && c <= 'f'){
							t->pos += (c - 87);
						}
						else{
							t->pos = last;
							parse->text_index -= 1;
							break;
						}
						c = parse->text.str[parse->text_index];
						parse->text_index += 1;
					}
					if (neg == 1){
						t->neg = -t->pos;
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
						t->pos <<= 1;
						t->pos += (c-48);
						c = parse->text.str[parse->text_index];
						parse->text_index += 1;
					}
					if (neg == 1){
						t->neg = -t->pos;
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
						t->pos <<= 3;
						t->pos += (c-48);
						c = parse->text.str[parse->text_index];
						parse->text_index += 1;
					}
					if (neg == 1){
						t->neg = -t->pos;
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
				t->pos *= 10;
				t->pos += (c-48);
				c = parse->text.str[parse->text_index];
				parse->text_index += 1;
			}
			if (neg == 1){
				t->neg = -t->pos;
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
			string_print(&t.name);
			printf(" ");
			break;
		case SYMBOL_TOKEN:
			printf("SYMBOL ");
			string_print(&t.name);
			printf(" ");
			break;
		case STRING_TOKEN:
			printf("STRING ");
			string_print(&t.name);
			printf(" ");
			break;
		case CHAR_TOKEN:
			char c = t.pos;
			printf("CHAR %c ", c);
			break;
		case INTEGER_TOKEN:
			printf("INTEGER %lu (%ld) ", t.pos, t.neg);
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

void
parse_string(parser* const parse){

}

int
main(int argc, char** argv){
	compile_file("test.n", "test");
	return 0;
}
