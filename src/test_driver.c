#include <assert.h>
#include "targum_parser.h"
#include "targum_lexer.h"


int main(const int argc, char *restrict argv[restrict static 1])
{
	if( argc < 2 ) {
		puts("Targum Parser Driver Error: missing text file.");
		return 1;
	}
	
	struct TargumLexer tlexer = targum_lexer_make_from_file(argv[1], NULL, &( bool ){false});
	targum_lexer_load_cfg_file(&tlexer, "metatokens.cfg");
	targum_lexer_generate_tokens(&tlexer);
	
	printf("tokens lexed: '%zu'\n", tlexer.tokens.len);
	
	struct KatovaAST *parse = katova_parse(&tlexer);
	katova_print(parse, 0, stdout);
	katova_free(&parse);
	targum_lexer_clear(&tlexer, true);
}