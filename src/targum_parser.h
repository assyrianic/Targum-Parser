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
#include "targum_lexer.h"


#ifdef TARGUM_DLL
#	ifndef TARGUM_LIB 
#		define TARGUM_API __declspec(dllimport)
#	else
#		define TARGUM_API __declspec(dllexport)
#	endif
#else
#	define TARGUM_API
#endif


typedef bool    LexerStartUpFunc(void *userdata, const char filename[]);
typedef bool    LexerShutDwnFunc(void *userdata, const char filename[]);

/// advance() Token
typedef void   *LexerAdvanceFunc(void *userdata);

/// peek(amount int) Token
typedef void   *LexerPeekFunc(void *userdata, size_t amount);

/// backtrack(amount int) Token
typedef void   *LexerBacktrackFunc(void *userdata, size_t amount);

/// expect(t Token) bool
typedef bool    ParserExpectFunc(void *userdata, const void *token);

/// got(toks +Token) bool
typedef bool    ParserGotFunc(void *userdata, const void *tokens[], size_t token_count);

/// pos(t Token) +int
typedef void    TokenPosFunc(void *userdata, const void *tokens, size_t rets[], size_t ret_count);

/// user(args +any) any
typedef void   *ParserUserFunc(void *userdata, void *args[], size_t arg_count);

/// err/warn(msg_fmt string, data +any)
typedef void    ParserErrOrWarnFunc(void *userdata, const char prefix[], const char msg_fmt[], void *args[], size_t arg_count);

/// to_node(t Token) Node
typedef struct KatovaNode *TokenToNode(void *userdata, const void *token);


enum KatovaASTType {
	KatovaASTInvalid = 0,
	KatovaASTGrammar,
	KatovaASTTypeSpec,
	KatovaASTTypeDecl,
	KatovaASTRule,
	KatovaASTField,
	KatovaASTFieldList,
	KatovaASTFuncSignature,
	KatovaASTCaseClause,
	KatovaASTMatchStmt,
	KatovaASTReturnStmt,
	KatovaASTLoopStmt,
	KatovaASTForStmt,
	KatovaASTBlock,
	KatovaASTIfStmt,
	KatovaASTExprStmt,
	KatovaASTExprList,
	KatovaASTAssignStmt,
	KatovaASTBinaryExpr,
	KatovaASTCall,
	KatovaASTArrayAccess,
	KatovaASTIntLiteral,
	KatovaASTStrLiteral,
	KatovaASTIdent,
	MaxKatovaASTTypes,
};


struct KatovaAST {
	union {
		struct {
			struct HarbolArray types, rules;
		} grammar;
		
		struct {
			struct KatovaAST *name, *type, *spec;
			bool is_alias : 1;
		} type_decl;
		
		struct {
			struct KatovaAST *name, *sig, *block;
		} rule;
		
		struct {
			struct KatovaAST *idens, *type;
		} field;
		
		struct {
			struct KatovaAST *params, *results;
		} func_signature;
		
		struct {
			struct KatovaAST *cases, *block;
		} match_case;
		
		struct {
			struct HarbolArray body;
			struct KatovaAST  *init, *cond;
		} match;
		
		struct {
			struct KatovaAST *init, *cond, *post, *body;
		} _for;
		
		struct {
			struct KatovaAST *init, *cond, *then, *_else;
		} _if;
		
		struct {
			struct KatovaAST *lhs, *rhs; /// .list
			char              op;
		} assign;
		
		struct {
			struct KatovaAST *l, *r;
			char              op;
		} binary_expr;
		
		struct {
			struct KatovaAST *caller, *args;
		} call;
		
		struct {
			struct KatovaAST *obj, *expr;
		} array_access;
		
		struct KatovaAST   *node;
		struct HarbolArray  list;
		
		struct HarbolString str; /// used by: KatovaASTIdent, KatovaASTStrLiteral, KatoveASTFieldAccess
	} _;
	enum KatovaASTType tag;
};

TARGUM_API NO_NULL struct KatovaAST *katova_parse(struct TargumLexer *lexer);
TARGUM_API void katova_print(const struct KatovaAST *ast, size_t tabs, FILE *stream);
TARGUM_API void katova_free(struct KatovaAST **ast_ref);


struct KatovaNode {
	struct HarbolArray *nodes;      /// []KatovaNode   . NULL if unused.
	struct HarbolMap   *fields;     /// map[string]any . NULL if unused.
	void               *token_data; /// Token          . NULL if unused.
	size_t              token_len;
	uint32_t            tag; /// value of 0 means generic Node.
};


struct KatovaParser {
	struct TargumLexer lexer;
	struct HarbolMap
		sym_table   /// map[string]Var
	  , node_types  /// map[string]NodeDef
	;
};

struct TargumParser {
	struct Builtins {
		LexerStartUpFunc   *startup_fn;
		LexerShutDwnFunc   *shutdown_fn;
		LexerAdvanceFunc   *advance_fn;
		LexerPeekFunc      *peek_fn;
		LexerBacktrackFunc *bktrk_fn;
		
		void               *userdata, *global_token;
		size_t              len_data,  token_len;
	} builtins;
	const char             *filename, *katova_filename;
};


#ifdef __cplusplus
}
#endif

#endif /** TARGUM_PARSER_INCLUDED */