#ifndef TARGUM_PARSER_INCLUDED
#	define TARGUM_PARSER_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include "map/map.h"
#include "lex/lex.h"
#include "msg_sys/msg_sys.h"
#include "cfg/cfg.h"
#include "tree/tree.h"


#ifdef TARGUM_DLL
#	ifndef TARGUM_LIB 
#		define TARGUM_API __declspec(dllimport)
#	else
#		define TARGUM_API __declspec(dllexport)
#	endif
#else
#	define TARGUM_API
#endif


/// token func assumes value of 0 is an invalid token.
typedef bool        LexerStartUpFunc(void *userdata, const char filename[]);
typedef bool        LexerShutDwnFunc(void *userdata, const char filename[]);
typedef uint32_t    TokenFunc(void *userdata, size_t lookahead, size_t *line, size_t *col);
typedef const char *LexemeFunc(void *userdata, size_t lookahead, size_t *line, size_t *col);
typedef void        ConsumeFunc(void *userdata, size_t lookahead, bool consumed);


struct TargumParser {
	struct HarbolMap      token_lits;  /// map[string]TokenValue
	struct LexerIFace {
		LexerStartUpFunc *startup_fn;
		LexerShutDwnFunc *shutdown_fn;
		TokenFunc        *tok_fn;
		LexemeFunc       *lexeme_fn;
		
		/// whether the parser consumed the token or not.
		/// Never invoked when error occurs.
		ConsumeFunc      *consume_fn;
		void             *userdata;
	} lexer_iface;
	const char           *filename, *cfg_file;
	struct HarbolMap     *cfg;
	bool                  warns : 1;
};

/// Targum 'Concrete Syntax Tree' aka a Parse Tree.
struct TargumCST {
	char  *parsed;
	size_t len, tag;
};

TARGUM_API NEVER_NULL(1,2,3,4,5,6,7) struct TargumParser targum_parser_make(LexerStartUpFunc *startup_func, LexerShutDwnFunc *shutdown_fn, TokenFunc *token_func, LexemeFunc *lexeme_func, ConsumeFunc *consume_func, void *userdata, const char filename[], struct HarbolMap *cfg);

TARGUM_API NO_NULL bool targum_parser_init(struct TargumParser *parser);

TARGUM_API NO_NULL void targum_parser_clear(struct TargumParser *parser, bool free_config);

TARGUM_API NO_NULL bool targum_parser_define_token(struct TargumParser *parser, const char token_name[], uint32_t tok_value);

TARGUM_API NO_NULL bool targum_parser_load_cfg_file(struct TargumParser *parser, const char cfg_file[]);
TARGUM_API NO_NULL bool targum_parser_load_cfg_cstr(struct TargumParser *parser, const char cfg_cstr[]);

TARGUM_API NO_NULL struct HarbolMap *targum_parser_get_cfg(const struct TargumParser *parser);

TARGUM_API NO_NULL const char *targum_parser_get_cfg_filename(const struct TargumParser *parser);

TARGUM_API NO_NULL struct HarbolTree *targum_parser_run(struct TargumParser *parser);

TARGUM_API NO_NULL void targum_parser_clear_cst(struct HarbolTree *cst);
TARGUM_API NO_NULL void targum_parser_free_cst(struct HarbolTree **cst_ref);


static inline NO_NULL void _print_tabs(const size_t tabs, FILE *const f) {
	const size_t amount = tabs * 2;
	char str_branches[256] = {0};
	if( amount > 0 ) {
		char *end = &str_branches[0] + sizeof str_branches;
		char *p = harbol_memccpy(str_branches, " ", 0, sizeof str_branches);
		for( size_t i=1; i<amount && p != NULL; i++ ) {
			p = harbol_memccpy(p - 1, " ", 0, end - p);
		}
	}
	fprintf(f, "%s", str_branches);
}

#ifdef __cplusplus
}
#endif

#endif /** TARGUM_PARSER_INCLUDED */