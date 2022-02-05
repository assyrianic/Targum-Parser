#include <assert.h>
#include "targum_parser.h"
#include "targum_lexer.h"


static bool startup_targum_lexer(void *const userdata, const char filename[static 1]) {
	struct TargumLexer *const restrict lexer = userdata;
	bool result = false;
	*lexer = targum_lexer_make_from_file(filename, NULL, &result);
	if( !result || !targum_lexer_load_cfg_file(lexer, "tokens.cfg") ) {
		return false;
	}
	return targum_lexer_generate_tokens(lexer);
}

static bool shutdown_targum_lexer(void *const userdata, const char filename[static 1]) {
	( void )(filename);
	struct TargumLexer *const restrict lexer = userdata;
	targum_lexer_clear(lexer, true);
	return true;
}

static uint32_t targum_lexer_token(void *const userdata, const size_t lookahead, size_t *const restrict line, size_t *const restrict col) {
	const struct TargumLexer     *const lexer = userdata;
	const struct TargumTokenInfo *const ti    = targum_lexer_peek_token(lexer, lookahead);
	if( ti != NULL ) {
		*line = ti->line;
		*col  = ti->col;
		return ti->tag;
	}
	return 0;
}

static const char *targum_lexer_cstr(void *const userdata, const size_t lookahead, size_t *const restrict line, size_t *const restrict col) {
	const struct TargumLexer     *const lexer = userdata;
	const struct TargumTokenInfo *const ti    = targum_lexer_peek_token(lexer, lookahead);
	if( ti != NULL ) {
		*line = ti->line;
		*col  = ti->col;
		return ti->lexeme.cstr;
	}
	return "";
}

static void targum_lexer_consume(void *const userdata, const size_t lookahead, const bool consumed) {
	( void )(lookahead);
	struct TargumLexer *const lexer = userdata;
	if( consumed ) {
		targum_lexer_advance(lexer, true);
	}
}

static void print_cst(struct HarbolTree *const tree, const size_t tabs, FILE *const f) {
	if( tree==NULL )
		return;
	
	struct TargumCST *cst = ( struct TargumCST* )(tree->data);
	_print_tabs(tabs, f);
	fprintf(f, "%s :: '%s'\n", (cst->tag != SIZE_MAX)? "token" : "rule", cst->parsed);
	for( size_t i=0; i < tree->kids.len; i++ ) {
		struct HarbolTree **kid = harbol_array_get(&tree->kids, i, sizeof *kid);
		print_cst(*kid, tabs + 1, f);
	}
}


int main(const int argc, char *restrict argv[restrict static 1])
{
	if( argc < 2 ) {
		puts("Targum Parser Driver Error: missing text file.");
		return 1;
	}
	
	struct TargumLexer  tlexer  = {0};
	struct TargumParser tparser = targum_parser_make(startup_targum_lexer, shutdown_targum_lexer, targum_lexer_token, targum_lexer_cstr, targum_lexer_consume, &tlexer, argv[1], NULL);
	if( !targum_parser_init(&tparser) ) {
		puts("Targum Parser Driver Error: failed to initialize parser.");
		return 1;
	} else if( !targum_parser_load_cfg_file(&tparser, "./grammar.cfg") ) {
		puts("Targum Parser Driver Error: failed to load grammar config.");
		return 1;
	}
	
	/// don't access 'token_cfg' when the parser is done running, it'll be invalidated.
	const struct HarbolMap *token_cfg = targum_lexer_get_cfg(&tlexer);
	if( token_cfg==NULL ) {
		puts("Targum Parser Driver Error: failed to load token config.");
		return 1;
	}
	
	{
		const char *names[] = {
			"invalid",
			"comment",
			"identifier",
			"integer",
			"float",
			"string",
			"rune",
		};
		const struct HarbolMap *const tokens = harbol_cfg_get_section(token_cfg, "tokens");
		for( const char **iter=&names[0]; iter < 1[&names]; iter++ ) {
			const intmax_t *const val = harbol_cfg_get_int(tokens, *iter);
			if( val==NULL ) {
				continue;
			}
			targum_parser_define_token(&tparser, *iter, ( uint32_t )(*val));
		}
	}
	struct HarbolTree *cst = targum_parser_run(&tparser);
	token_cfg = NULL;
	
	FILE *output = fopen("targum_parser_cst_output.txt", "w");
	print_cst(cst, 0, output);
	fclose(output); output = NULL;
	targum_parser_free_cst(&cst);
	targum_parser_clear(&tparser, true);
}