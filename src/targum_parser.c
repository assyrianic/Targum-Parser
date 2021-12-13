#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include "targum_parser.h"


/** Structure of File:
 * MetaCompiler -> Starting with MetaLexer, then MetaParser, then MetaAST functions.
 * MetaInterpreter -> after line 530.
 */

enum MetaToken {
	MetaTokenInvalid,
	MetaTokenRule,     /// <a>
	MetaTokenAlt,      /// | /
	MetaTokenLParens, MetaTokenRParens, /// ()
	MetaTokenLBrack, MetaTokenRBrack, /// []
	MetaTokenPlus,     /// +
	MetaTokenStar,     /// *
	MetaTokenAmp,      /// &
	MetaTokenExclmtn,  /// !
	MetaTokenReqToken, /// 'i' "i"
	MetaTokenLexToken, /// {i*}
};

static inline const char *_get_metatoken(const enum MetaToken tok) {
	switch( tok ) {
		case MetaTokenRule:     return "rule metatoken";
		case MetaTokenAlt:      return "alt metatoken";
		case MetaTokenLParens:  return "( metatoken";
		case MetaTokenRParens:  return ") metatoken";
		case MetaTokenLBrack:   return "[ metatoken";
		case MetaTokenRBrack:   return "] metatoken";
		case MetaTokenPlus:     return "+ metatoken";
		case MetaTokenStar:     return "* metatoken";
		case MetaTokenAmp:      return "& metatoken";
		case MetaTokenExclmtn:  return "! metatoken";
		case MetaTokenReqToken: return "required metatoken";
		case MetaTokenLexToken: return "lexer metatoken";
		case MetaTokenInvalid:
		default:
			                    return "invalid meta-token";
	}
}


struct MetaLexer {
	struct HarbolString lexeme;
	const char         *src, *iter, *line_start;
	size_t              line, errs;
	enum MetaToken      token;
};

NO_NULL enum MetaToken metalexer_get_token(struct MetaLexer *mlexer);


enum MetaNodeType {
	MetaNodeInvalid = 0,
	MetaNodeRuleListExpr, /// <a> <b> ... enumerator_list := <enumerator> [',' <enumerator_list>] ;
	MetaNodeGroup,        /// (<a> <b>)
	MetaNodeOpt,          /// [<a> <b>]
	MetaNodeAlt,          /// <a> | <b>
	MetaNodePlusExpr,     /// +
	MetaNodeStarExpr,     /// *
	MetaNodePosLook,      /// &
	MetaNodeNegLook,      /// !
	MetaNodeLexToken,     /// i
	MetaNodeReqToken,     /// 'if'
	MetaNodeRuleExpr,     /// <a>
};

static inline const char *_get_metanode(const enum MetaNodeType tok) {
	switch( tok ) {
		case MetaNodeRuleListExpr: return "rule expr list";
		case MetaNodeGroup:        return "group";
		case MetaNodeOpt:          return "optional";
		case MetaNodeAlt:          return "alternate";
		case MetaNodePlusExpr:     return "one-or-more";
		case MetaNodeStarExpr:     return "none-or-more";
		case MetaNodePosLook:      return "positive lookahead";
		case MetaNodeNegLook:      return "negative lookahead";
		case MetaNodeLexToken:     return "lex token";
		case MetaNodeReqToken:     return "req token";
		case MetaNodeRuleExpr:     return "rule expr";
		case MetaNodeInvalid:
		default:
			                       return "invalid metanode";
	}
}

struct MetaNode {
	union {
		struct HarbolArray               *rule_list_expr;
		struct MetaNode                  *node_expr;
		struct{ struct MetaNode *l, *r; } alt_expr;
		struct HarbolString               token_expr;
	} node;
	enum MetaNodeType                     tag;
};

struct MetaNode *metanode_new_listexpr(struct HarbolArray *rule_list);
struct MetaNode *metanode_new_group(struct MetaNode *expr);
struct MetaNode *metanode_new_opt(struct MetaNode *expr);
struct MetaNode *metanode_new_alt(struct MetaNode *left, struct MetaNode *rite);
struct MetaNode *metanode_new_rep_plus(struct MetaNode *expr);
struct MetaNode *metanode_new_rep_star(struct MetaNode *expr);
struct MetaNode *metanode_new_pos_look(struct MetaNode *expr);
struct MetaNode *metanode_new_neg_look(struct MetaNode *expr);
struct MetaNode *metanode_new_rule(const struct HarbolString *rule);
struct MetaNode *metanode_new_lex_token(const struct HarbolString *tok);
struct MetaNode *metanode_new_req_token(const struct HarbolString *tok);
NO_NULL void metanode_free(struct MetaNode **nref);
void metanode_print(struct MetaNode *n, size_t tabs);


/**
 * Grammar of the MetaAST:
 * <rule>       = +<alt_expr> ;
 * <alt_expr>   = <rep_expr> [('|' | '/') <alt_expr>] ;
 * <rep_expr>   = ['+' | '*' | '&' | '!'] <factor> ;
 * <group_expr> = '(' <rule> ')' ;
 * <opt_expr>   = '[' <rule> ']' ;
 * <factor>     = <terminal> | '<' IDEN '>' | <group_expr> | <opt_expr> ;
 * <terminal>   = "'" KEYWORD "'" | '"' KEYWORD '"' | LEX_TOKEN ;
 */
typedef struct MetaNode *MetaParseFunc(struct MetaLexer *mlexer);

MetaParseFunc
	metaparser_parse_rule,
	metaparser_parse_alt,
	metaparser_parse_rep,
	metaparser_parse_factor
;


enum MetaToken metalexer_get_token(struct MetaLexer *const mlexer)
{
	if( mlexer->src==NULL ) {
		return (mlexer->token = MetaTokenInvalid);
	}
	harbol_string_clear(&mlexer->lexeme);
	while( *mlexer->iter != 0 ) {
		if( is_whitespace(*mlexer->iter) ) {
			if( *mlexer->iter=='\n' ) {
				mlexer->line++;
				mlexer->line_start = mlexer->iter;
			}
			mlexer->iter++;
			continue;
		}
		
		switch( *mlexer->iter ) {
			case '<': {
				mlexer->iter++;
				char *end = NULL;
				lex_until(mlexer->iter, ( const char** )(&end), &mlexer->lexeme, '>');
				if( end != NULL ) {
					mlexer->iter = end + 1;
				}
				return mlexer->token = MetaTokenRule;
			}
			case '\'': case '"': {
				char *end = NULL;
				const int res = lex_c_style_str(mlexer->iter, ( const char** )(&end), &mlexer->lexeme);
				if( res > HarbolLexNoErr ) {
					return (mlexer->token = MetaTokenInvalid);
				}
				if( end != NULL ) {
					mlexer->iter = end;
				}
				return mlexer->token = MetaTokenReqToken;
			}
			case '{': { /// literal value key.
				mlexer->iter++;
				char *end = NULL;
				lex_until(mlexer->iter, ( const char** )(&end), &mlexer->lexeme, '}');
				if( end != NULL ) {
					mlexer->iter = end + 1;
				}
				return mlexer->token = MetaTokenLexToken;
			}
			case '|': case '/':
				harbol_string_copy_cstr(&mlexer->lexeme, "|");
				mlexer->iter++;
				return mlexer->token = MetaTokenAlt;
			case '(':
				harbol_string_copy_cstr(&mlexer->lexeme, "(");
				mlexer->iter++;
				return mlexer->token = MetaTokenLParens;
			case ')':
				harbol_string_copy_cstr(&mlexer->lexeme, ")");
				mlexer->iter++;
				return mlexer->token = MetaTokenRParens;
			case '[':
				harbol_string_copy_cstr(&mlexer->lexeme, "[");
				mlexer->iter++;
				return mlexer->token = MetaTokenLBrack;
			case ']':
				harbol_string_copy_cstr(&mlexer->lexeme, "]");
				mlexer->iter++;
				return mlexer->token = MetaTokenRBrack;
			case '+':
				harbol_string_copy_cstr(&mlexer->lexeme, "+");
				mlexer->iter++;
				return mlexer->token = MetaTokenPlus;
			case '*':
				harbol_string_copy_cstr(&mlexer->lexeme, "*");
				mlexer->iter++;
				return mlexer->token = MetaTokenStar;
			case '&':
				harbol_string_copy_cstr(&mlexer->lexeme, "&");
				mlexer->iter++;
				return mlexer->token = MetaTokenAmp;
			case '!':
				harbol_string_copy_cstr(&mlexer->lexeme, "!");
				mlexer->iter++;
				return mlexer->token = MetaTokenExclmtn;
			default:
				harbol_err_msg(&mlexer->errs, "grammar", "syntax error", &mlexer->line, &( size_t ){ mlexer->iter - mlexer->src }, "Bad grammar token: '%c'. Aborting...", *mlexer->iter);
				abort();
		}
	}
	return mlexer->token = MetaTokenInvalid;
}

/**************************************************************************/

/// <rule> = +<alt_expr> ;
struct MetaNode *metaparser_parse_rule(struct MetaLexer *const mlexer)
{
	metalexer_get_token(mlexer);
	struct HarbolArray *nodelist = harbol_array_new(sizeof(struct MetaNode*), ARRAY_DEFAULT_SIZE);
	for( struct MetaNode *n = metaparser_parse_alt(mlexer); n != NULL; n = metaparser_parse_alt(mlexer) ) {
		if( harbol_array_full(nodelist) && !harbol_array_grow(nodelist, sizeof(struct MetaNode*)) ) {
			harbol_err_msg(NULL, "grammar", "memory error", &mlexer->line, &( size_t ){ mlexer->line_start - mlexer->src }, "Unable to grow node list. Aborting...");
			abort();
		}
		harbol_array_insert(nodelist, &n, sizeof n);
	}
	
	if( nodelist->len==0 ) {
		harbol_warn_msg(NULL, "grammar", "critical warning", &mlexer->line, &( size_t ){ mlexer->line_start - mlexer->src }, "Empty rule returns a NULL metanode.");
		harbol_array_cleanup(&nodelist);
	}
	return metanode_new_listexpr(nodelist);
}

/** <alt_expr> = <rep_expr> [('|' | '/') <alt_expr>] ; */
struct MetaNode *metaparser_parse_alt(struct MetaLexer *const mlexer)
{
	const enum MetaToken *t = &mlexer->token;
	struct MetaNode *n = metaparser_parse_rep(mlexer);
	if( *t==MetaTokenAlt ) {
		metalexer_get_token(mlexer);
		return metanode_new_alt(n, metaparser_parse_alt(mlexer));
	}
	return n;
}

/** <rep_expr> = ['+' | '*' | '&' | '!'] <factor> ; */
struct MetaNode *metaparser_parse_rep(struct MetaLexer *const mlexer)
{
	const enum MetaToken *const t = &mlexer->token;
	switch( *t ) {
		case MetaTokenPlus:
			metalexer_get_token(mlexer);
			return metanode_new_rep_plus(metaparser_parse_factor(mlexer));
		case MetaTokenStar:
			metalexer_get_token(mlexer);
			return metanode_new_rep_star(metaparser_parse_factor(mlexer));
		case MetaTokenAmp:
			metalexer_get_token(mlexer);
			return metanode_new_pos_look(metaparser_parse_factor(mlexer));
		case MetaTokenExclmtn:
			metalexer_get_token(mlexer);
			return metanode_new_neg_look(metaparser_parse_factor(mlexer));
		default:
			return metaparser_parse_factor(mlexer);
	}
}

/**
 * <factor> = <terminal> | '<' IDEN '>' | '{' IDEN '}' | '(' <rule> ')' | '[' <rule> ']';
 * <terminal> = "'" KEYWORD "'" | '"' KEYWORD '"' ;
 */
struct MetaNode *metaparser_parse_factor(struct MetaLexer *const mlexer)
{
	const enum MetaToken *const t = &mlexer->token;
	switch( *t ) {
		case MetaTokenLParens: {
			struct MetaNode *group = metanode_new_group(metaparser_parse_rule(mlexer));
			if( *t != MetaTokenRParens ) {
				harbol_err_msg(&mlexer->errs, "grammar", "error", &mlexer->line, &( size_t ){ mlexer->line_start - mlexer->src }, "Missing right parens ')'!");
				metanode_free(&group);
			} else {
				metalexer_get_token(mlexer);
			}
			return group;
		}
		case MetaTokenLBrack: {
			struct MetaNode *opt = metanode_new_opt(metaparser_parse_rule(mlexer));
			if( *t != MetaTokenRBrack ) {
				harbol_err_msg(&mlexer->errs, "grammar", "error", &mlexer->line, &( size_t ){ mlexer->line_start - mlexer->src }, "Missing right bracket ']'!");
				metanode_free(&opt);
			} else {
				metalexer_get_token(mlexer);
			}
			return opt;
		}
		case MetaTokenReqToken: {
			struct MetaNode *req = metanode_new_req_token(&mlexer->lexeme);
			metalexer_get_token(mlexer);
			return req;
		}
		case MetaTokenLexToken: {
			struct MetaNode *lex = metanode_new_lex_token(&mlexer->lexeme);
			metalexer_get_token(mlexer);
			return lex;
		}
		case MetaTokenRule: {
			struct MetaNode *rule = metanode_new_rule(&mlexer->lexeme);
			metalexer_get_token(mlexer);
			return rule;
		}
		default:
			return NULL;
	}
}


struct MetaNode *metanode_new_listexpr(struct HarbolArray *const rule_list)
{
	struct MetaNode *n = calloc(1, sizeof *n);
	assert( n != NULL && "bad MetaNode rule list expression." );
	n->node.rule_list_expr = rule_list;
	n->tag = MetaNodeRuleListExpr;
	return n;
}

struct MetaNode *metanode_new_group(struct MetaNode *const expr)
{
	struct MetaNode *n = calloc(1, sizeof *n);
	assert( n != NULL && "bad MetaNode group expression." );
	n->node.node_expr = expr;
	n->tag = MetaNodeGroup;
	return n;
}

struct MetaNode *metanode_new_opt(struct MetaNode *const expr)
{
	struct MetaNode *n = calloc(1, sizeof *n);
	assert( n != NULL && "bad MetaNode optional expression." );
	n->node.node_expr = expr;
	n->tag = MetaNodeOpt;
	return n;
}

struct MetaNode *metanode_new_alt(struct MetaNode *const left, struct MetaNode *const rite)
{
	struct MetaNode *n = calloc(1, sizeof *n);
	assert( n != NULL && "bad MetaNode alternate expression." );
	n->node.alt_expr.l = left;
	n->node.alt_expr.r = rite;
	n->tag = MetaNodeAlt;
	return n;
}

struct MetaNode *metanode_new_rep_plus(struct MetaNode *const expr)
{
	struct MetaNode *n = calloc(1, sizeof *n);
	assert( n != NULL && "bad MetaNode one-or-more expression." );
	n->node.node_expr = expr;
	n->tag = MetaNodePlusExpr;
	return n;
}

struct MetaNode *metanode_new_rep_star(struct MetaNode *const expr)
{
	struct MetaNode *n = calloc(1, sizeof *n);
	assert( n != NULL && "bad MetaNode zero-or-more expression." );
	n->node.node_expr = expr;
	n->tag = MetaNodeStarExpr;
	return n;
}

struct MetaNode *metanode_new_pos_look(struct MetaNode *const expr)
{
	struct MetaNode *n = calloc(1, sizeof *n);
	assert( n != NULL && "bad MetaNode positive lookahead expression." );
	n->node.node_expr = expr;
	n->tag = MetaNodePosLook;
	return n;
}

struct MetaNode *metanode_new_neg_look(struct MetaNode *const expr)
{
	struct MetaNode *n = calloc(1, sizeof *n);
	assert( n != NULL && "bad MetaNode negative lookahead expression." );
	n->node.node_expr = expr;
	n->tag = MetaNodeNegLook;
	return n;
}

struct MetaNode *metanode_new_rule(const struct HarbolString *const rule)
{
	struct MetaNode *n = calloc(1, sizeof *n);
	assert( n != NULL && "bad MetaNode rule expression." );
	harbol_string_copy_str(&n->node.token_expr, rule);
	n->tag = MetaNodeRuleExpr;
	return n;
}

struct MetaNode *metanode_new_lex_token(const struct HarbolString *const tok)
{
	struct MetaNode *n = calloc(1, sizeof *n);
	assert( n != NULL && "bad MetaNode lexical token expression." );
	harbol_string_copy_str(&n->node.token_expr, tok);
	n->tag = MetaNodeLexToken;
	return n;
}

struct MetaNode *metanode_new_req_token(const struct HarbolString *const tok)
{
	struct MetaNode *n = calloc(1, sizeof *n);
	assert( n != NULL && "bad MetaNode required token expression." );
	harbol_string_copy_str(&n->node.token_expr, tok);
	n->tag = MetaNodeReqToken;
	return n;
}

void metanode_free(struct MetaNode **const n)
{
	if( *n==NULL )
		return;
	
	switch( (*n)->tag ) {
		case MetaNodeRuleListExpr: {
			struct HarbolArray *nodes = (*n)->node.rule_list_expr;
			for( size_t i=0; i < nodes->len; i++ ) {
				struct MetaNode **p = harbol_array_get(nodes, i, sizeof *p);
				metanode_free(p);
			}
			harbol_array_cleanup(&(*n)->node.rule_list_expr);
			break;
		}
		case MetaNodeAlt: {
			metanode_free(&(*n)->node.alt_expr.l);
			metanode_free(&(*n)->node.alt_expr.r);
			break;
		}
		case MetaNodeGroup:
		case MetaNodeOpt:
		case MetaNodePlusExpr:
		case MetaNodeStarExpr:
		case MetaNodePosLook:
		case MetaNodeNegLook: {
			metanode_free(&(*n)->node.node_expr);
			break;
		}
		case MetaNodeLexToken:
		case MetaNodeReqToken:
		case MetaNodeRuleExpr: {
			harbol_string_clear(&(*n)->node.token_expr);
			break;
		}
		case MetaNodeInvalid:
			break;
	}
	free(*n); *n = NULL;
}

void metanode_print(struct MetaNode *const n, const size_t tabs)
{
	if( n==NULL )
		return;
	
	_print_tabs(tabs, stdout);
	switch( n->tag ) {
		case MetaNodeRuleListExpr: {
			puts("metanode :: rule list expr");
			const struct HarbolArray *const arr = n->node.rule_list_expr;
			for( size_t i=0; i < arr->len; i++ ) {
				struct MetaNode **p = harbol_array_get(arr, i, sizeof *p);
				metanode_print(*p, tabs + 1);
			}
			break;
		}
		case MetaNodeAlt:
			puts("metanode :: alternate expr, printing left");
			metanode_print(n->node.alt_expr.l, tabs + 1);
			_print_tabs(tabs, stdout);
			puts("metanode :: alternate expr, printing right");
			metanode_print(n->node.alt_expr.r, tabs + 1);
			break;
		case MetaNodeGroup:
			puts("metanode :: group expr");
			metanode_print(n->node.node_expr, tabs + 1);
			break;
		case MetaNodeOpt:
			puts("metanode :: optional expr");
			metanode_print(n->node.node_expr, tabs + 1);
			break;
		case MetaNodePlusExpr:
			puts("metanode :: one-or-more expr");
			metanode_print(n->node.node_expr, tabs + 1);
			break;
		case MetaNodeStarExpr:
			puts("metanode :: zero-or-more expr");
			metanode_print(n->node.node_expr, tabs + 1);
			break;
		case MetaNodePosLook:
			puts("metanode :: positive lookahead expr");
			metanode_print(n->node.node_expr, tabs + 1);
			break;
		case MetaNodeNegLook:
			puts("metanode :: negative lookahead expr");
			metanode_print(n->node.node_expr, tabs + 1);
			break;
		case MetaNodeLexToken:
			printf("metanode :: lex token expr: '%s'\n", n->node.token_expr.cstr);
			break;
		case MetaNodeReqToken:
			printf("metanode :: required token expr: '%s'\n", n->node.token_expr.cstr);
			break;
		case MetaNodeRuleExpr:
			printf("metanode :: rule expr: '%s'\n", n->node.token_expr.cstr);
			break;
		case MetaNodeInvalid:
		default:
			puts("metanode :: invalid expr");
			break;
	}
}


/**************************************************************************/

enum ParseFlags {
	FlagAlt,
	FlagOpt,
	FlagPlus,
	FlagStar,
	FlagPos,
	FlagNeg,
	MaxParseFlags,
};

struct TargumParseState {
	struct TargumParser     *parser;
	struct HarbolMap        *rules, *token_map;
	const char              *filename;
	const struct LexerIFace *lexer_pipe;
	size_t                  *recursive_def, curr_lookahead;
	
	/**
	 * rules can nest the same grammar expression types.
	 * example: '[ (<a> *<b>) <c> [+<d>] ]'.
	 * Having a simple bitwise flag isn't enough in this case.
	 * Do you toggle the bit flag after the inner or outter
	 * optional expression fails/succeeds?
	 */
	enum ParseFlags          flags[MaxParseFlags];
};


static NO_NULL struct HarbolTree *_targum_parser_new_cst(struct TargumParseState *state, size_t rule);
//#define DEBUG

#ifdef DEBUG
#	include <unistd.h>
#endif


static bool _targum_parser_exec_meta_ast(struct TargumParseState *const state, const struct MetaNode *const ast, const size_t rule, struct HarbolTree *const root) {
	state->recursive_def[rule]++;
	if( state->recursive_def[rule] > 1000000 ) {
		harbol_err_msg(NULL, state->filename, "error", NULL, NULL, "Recursive rule '%s' detected!", ( const char* )(state->rules->keys[rule]));
		return false;
	}
	
#ifdef DEBUG
	usleep(200000);
	printf("%s :: ast->tag - '%s' | rule - '%s'\n", __func__, _get_metanode(ast->tag), ( const char* )(state->rules->keys[rule]));
#endif
	
	switch( ast->tag ) {
		case MetaNodeInvalid: {
			harbol_err_msg(NULL, state->filename, "error", NULL, NULL, "Invalid MetaNode! rule: '%s'", ( const char* )(state->rules->keys[rule]));
			return false;
		}
		case MetaNodeRuleListExpr: {
			/**
			 * For a rule expression list,
			 * we iterate the node array until they all pass true
			 * or we hit a false return.
			 */
			bool res = false;
			const struct HarbolArray *const rule_list = ast->node.rule_list_expr;
			if( rule_list==NULL )
				return true;
			
			for( size_t i=0; i < rule_list->len; i++ ) {
				const struct MetaNode **const node = harbol_array_get(rule_list, i, sizeof *node);
				res = _targum_parser_exec_meta_ast(state, *node, rule, root);
				if( !res )
					break;
			}
			return res;
		}
		case MetaNodeGroup: {
			const struct HarbolArray *const list = ast->node.node_expr->node.rule_list_expr;
			if( list==NULL )
				return true;
			
			bool res = false;
			for( size_t i=0; i < list->len; i++ ) {
				const struct MetaNode **const node = harbol_array_get(list, i, sizeof *node);
				res = _targum_parser_exec_meta_ast(state, *node, rule, root);
				if( !res )
					break;
			}
			return res;
		}
		case MetaNodeOpt: {
			if( ast->node.node_expr==NULL )
				return true;
			
			const struct HarbolArray *const list = ast->node.node_expr->node.rule_list_expr;
			if( list==NULL || list->len==0 )
				return true;
			
			state->flags[FlagOpt]++;
			const struct MetaNode **node = harbol_array_get(list, 0, sizeof *node);
			bool res = _targum_parser_exec_meta_ast(state, *node, rule, root);
			state->flags[FlagOpt]--;
			if( !res )
				return true;
			
			for( size_t i=1; i < list->len; i++ ) {
				node = harbol_array_get(list, i, sizeof *node);
				res = _targum_parser_exec_meta_ast(state, *node, rule, root);
				if( !res )
					break;
			}
			return res;
		}
		case MetaNodeAlt: {
			/// Alternate expressions use a form of look-ahead.
			const size_t saved_lookahead = state->curr_lookahead;
			const size_t kids = harbol_tree_len(root);
			state->flags[FlagAlt]++;
			const bool result = _targum_parser_exec_meta_ast(state, ast->node.alt_expr.l, rule, root);
			state->flags[FlagAlt]--;
			if( result ) {
				return result;
			} else {
				if( state->curr_lookahead > saved_lookahead ) {
					const size_t child_count = harbol_tree_len(root);
					if( child_count > kids ) {
						for( size_t i=0; i < (child_count - kids); i++ ) {
							const size_t idx = harbol_tree_len(root) - 1;
							struct HarbolTree *const cst_node = harbol_tree_get_node_by_index(root, idx);
							struct TargumCST *const cst = harbol_tree_get(cst_node);
							free(cst->parsed); cst->parsed = NULL;
							harbol_tree_rm_index(root, idx);
						}
					}
				}
				state->curr_lookahead = saved_lookahead;
				return _targum_parser_exec_meta_ast(state, ast->node.alt_expr.r, rule, root);
			}
		}
		case MetaNodePlusExpr: {
			bool res = false;
			state->flags[FlagPlus]++;
			while( _targum_parser_exec_meta_ast(state, ast->node.node_expr, rule, root) ) {
				res = true;
			}
			state->flags[FlagPlus]--;
			return res;
		}
		case MetaNodeStarExpr: {
			state->flags[FlagStar]++;
			while( _targum_parser_exec_meta_ast(state, ast->node.node_expr, rule, root) );
			state->flags[FlagStar]--;
			return true;
		}
		case MetaNodePosLook: {
			state->flags[FlagPos]++;
			const bool result = _targum_parser_exec_meta_ast(state, ast->node.node_expr, rule, root);
			state->curr_lookahead = 0;
			state->flags[FlagPos]--;
			return result;
		}
		case MetaNodeNegLook: {
			state->flags[FlagNeg]++;
			const bool result = _targum_parser_exec_meta_ast(state, ast->node.node_expr, rule, root);
			state->curr_lookahead = 0;
			state->flags[FlagNeg]--;
			return !result;
		}
		case MetaNodeLexToken: {
			const struct HarbolString *const lit_str = &ast->node.token_expr;
			const uint32_t *const lex_tok_val = harbol_map_key_get(state->token_map, lit_str->cstr, lit_str->len+1);
			if( lex_tok_val==NULL ) {
				harbol_err_msg(NULL, state->filename, "runtime error", NULL, NULL, "Undefined token type '%s' in rule '%s'", lit_str->cstr, ( const char* )(state->rules->keys[rule]));
				return false;
			}
			
			const struct LexerIFace *const lex = state->lexer_pipe;
			size_t line=0, col=0;
			const uint32_t  tok_val = (*lex->tok_fn)(lex->userdata, state->curr_lookahead, &line, &col);
			const char     *tok_str = (*lex->lexeme_fn)(lex->userdata, state->curr_lookahead, &line, &col);
			if( tok_val==0 ) {
				return false;
			} else if( *lex_tok_val != tok_val ) {
				if( !state->flags[FlagPlus] && !state->flags[FlagStar] && !state->flags[FlagAlt] && !state->flags[FlagOpt] && !state->flags[FlagPos] && !state->flags[FlagNeg] ) {
					harbol_err_msg(NULL, state->filename, "syntax error", &line, &col, "Expected '%s' but got '%s'", lit_str->cstr, tok_str);
				}
				return false;
			}
			
			/// we're not in the look-ahead expressions, consume the token!
			const bool consume = !state->flags[FlagPos] && !state->flags[FlagNeg];
			if( consume ) {
				struct TargumCST cst = {
					.parsed = dup_str(tok_str),
					.len    = strlen(tok_str),
					.tag    = tok_val
				};
				if( cst.parsed==NULL ) {
					harbol_err_msg(NULL, state->filename, "memory error", &line, &col, "Unable to allocate CST Node for lexical token!");
					return false;
				}
				harbol_tree_insert_val(root, &cst, sizeof cst);
			} else {
				state->curr_lookahead++;
			}
			(*lex->consume_fn)(lex->userdata, state->curr_lookahead, consume);
			return true;
		}
		case MetaNodeReqToken: {
			const struct HarbolString *const lit_str = &ast->node.token_expr;
			const struct LexerIFace *const lex = state->lexer_pipe;
			size_t line=0, col=0;
			const uint32_t tok_val = (*lex->tok_fn)(lex->userdata, state->curr_lookahead, &line, &col);
			const char    *tok_str = (*lex->lexeme_fn)(lex->userdata, state->curr_lookahead, &line, &col);
			if( tok_val==0 || harbol_string_cmpcstr(lit_str, tok_str) ) {
				if( /*!state->flags[FlagPlus] && */!state->flags[FlagStar] && !state->flags[FlagAlt] && !state->flags[FlagOpt] && !state->flags[FlagPos] && !state->flags[FlagNeg] ) {
					harbol_err_msg(NULL, state->filename, "syntax error", &line, &col, "Expected '%s' but got '%s'", lit_str->cstr, tok_str);
				}
				return false;
			}
			const bool consume = !state->flags[FlagPos] && !state->flags[FlagNeg];
			if( consume ) {
				struct TargumCST cst = {
					.parsed = dup_str(tok_str),
					.len    = strlen(tok_str),
					.tag    = tok_val
				};
				if( cst.parsed==NULL ) {
					harbol_err_msg(NULL, state->filename, "memory error", &line, &col, "Unable to allocate CST Node for required token!");
					return false;
				}
				harbol_tree_insert_val(root, &cst, sizeof cst);
			} else {
				state->curr_lookahead++;
			}
			(*lex->consume_fn)(lex->userdata, state->curr_lookahead, consume);
			return true;
		}
		case MetaNodeRuleExpr: {
			const struct HarbolString *const lit_str = &ast->node.token_expr;
			const size_t subrule = harbol_map_get_entry_index(state->rules, lit_str->cstr, lit_str->len+1);
			if( subrule==SIZE_MAX ) {
				if( !state->flags[FlagPlus] && !state->flags[FlagStar] && !state->flags[FlagAlt] && !state->flags[FlagOpt] && !state->flags[FlagPos] && !state->flags[FlagNeg] ) {
					harbol_err_msg(NULL, state->filename, "runtime error", NULL, NULL, "Undefined rule '%s'!", lit_str->cstr);
				}
				return false;
			}
			
			struct HarbolTree *subchild = _targum_parser_new_cst(state, subrule);
			if( subchild==NULL ) {
				if( !state->flags[FlagPlus] && !state->flags[FlagStar] && !state->flags[FlagAlt] && !state->flags[FlagOpt] && !state->flags[FlagPos] && !state->flags[FlagNeg] ) {
					harbol_err_msg(NULL, state->filename, "memory error", NULL, NULL, "Failed to allocate tree for rule '%s'", lit_str->cstr);
				}
				return false;
			}
			harbol_tree_insert_node(root, &subchild);
			return true;
		}
		default:
			return false;
	}
}


static NO_NULL struct HarbolTree *_targum_parser_new_cst(struct TargumParseState *const state, const size_t rule)
{
	const struct MetaNode **const ast = harbol_map_idx_get(state->rules, rule);
	if( ast==NULL || *ast==NULL )
		return NULL;
	
	struct TargumCST cst = {
		.parsed = dup_str(( const char* )(state->rules->keys[rule])),
		.len    = state->rules->keylens[rule],
		.tag    = SIZE_MAX
	};
	struct HarbolTree *root = harbol_tree_new(&cst, sizeof cst);
	const bool result = _targum_parser_exec_meta_ast(state, *ast, rule, root);
	if( !result ) {
		targum_parser_free_cst(&root);
	} else if( harbol_tree_len(root)==0 ) {
		if( state->parser->warns ) {
			harbol_warn_msg(NULL, state->filename, "runtime warning", NULL, NULL, "rule produced no nodes.", ( const char* )(state->rules->keys[rule]));
		}
		targum_parser_free_cst(&root);
	}
	return root;
}


TARGUM_API struct TargumParser targum_parser_make(
	LexerStartUpFunc *const startup_func,
	LexerShutDwnFunc *const shutdown_func,
	TokenFunc        *const token_func,
	LexemeFunc       *const lexeme_func,
	ConsumeFunc      *const consume_func,
	void             *const userdata,
	const char        filename[static 1],
	struct HarbolMap *const cfg
) {
	return ( struct TargumParser ){
		.lexer_iface.startup_fn = startup_func,
		.lexer_iface.shutdown_fn = shutdown_func,
		.lexer_iface.tok_fn = token_func,
		.lexer_iface.lexeme_fn = lexeme_func,
		.lexer_iface.consume_fn = consume_func,
		.lexer_iface.userdata = userdata,
		.filename = filename,
		.cfg = cfg,
		.warns = true
	};
}

TARGUM_API bool targum_parser_init(struct TargumParser *const parser) {
	if( parser->lexer_iface.startup_fn==NULL ) {
		harbol_err_msg(NULL, parser->filename, "system error", NULL, NULL, "No lexer startup function loaded.");
		return false;
	} else if( !(*parser->lexer_iface.startup_fn)(parser->lexer_iface.userdata, parser->filename) ) {
		harbol_err_msg(NULL, parser->filename, "lexer error", NULL, NULL, "Lexer failed to start up. Check lexer and lexer interface.");
		if( parser->lexer_iface.shutdown_fn != NULL ) {
			(*parser->lexer_iface.shutdown_fn)(parser->lexer_iface.userdata, parser->filename);
		}
		return false;
	}
	return harbol_map_init(&parser->token_lits, 8);
}

TARGUM_API void targum_parser_clear(struct TargumParser *const parser, const bool free_config) {
	harbol_map_clear(&parser->token_lits);
	parser->filename = parser->cfg_file = NULL;
	if( free_config )
		harbol_cfg_free(&parser->cfg);
	
	parser->lexer_iface.startup_fn  = NULL;
	parser->lexer_iface.shutdown_fn = NULL;
	parser->lexer_iface.consume_fn  = NULL;
	parser->lexer_iface.lexeme_fn   = NULL;
	parser->lexer_iface.tok_fn      = NULL;
	parser->lexer_iface.userdata    = NULL;
}


TARGUM_API bool targum_parser_define_token(struct TargumParser *const restrict parser, const char token_name[static 1], const uint32_t tok_value) {
	const size_t token_name_len = strlen(token_name);
	return harbol_map_insert(&parser->token_lits, token_name, token_name_len+1, &tok_value, sizeof tok_value);
}


TARGUM_API bool targum_parser_load_cfg_file(struct TargumParser *const restrict parser, const char cfg_file[static 1]) {
	parser->cfg = harbol_cfg_parse_file(cfg_file);
	if( parser->cfg != NULL ) {
		parser->cfg_file = cfg_file;
		return true;
	}
	return false;
}
TARGUM_API bool targum_parser_load_cfg_cstr(struct TargumParser *const restrict parser, const char cfg_cstr[static 1]) {
	parser->cfg = harbol_cfg_parse_cstr(cfg_cstr);
	if( parser->cfg != NULL ) {
		parser->cfg_file = "user-defined";
		return true;
	}
	return false;
}

TARGUM_API struct HarbolMap *targum_parser_get_cfg(const struct TargumParser *const parser) {
	return parser->cfg;
}

TARGUM_API const char *targum_parser_get_cfg_filename(const struct TargumParser *const parser) {
	return parser->cfg_file;
}


TARGUM_API struct HarbolTree *targum_parser_run(struct TargumParser *const parser)
{
	if( parser->filename==NULL ) {
		harbol_err_msg(NULL, NULL, "system error", NULL, NULL, "No file name given.");
		return NULL;
	} else if( parser->cfg==NULL ) {
		harbol_err_msg(NULL, parser->filename, "system error", NULL, NULL, "No grammar config loaded.");
		return NULL;
	} else if( parser->lexer_iface.lexeme_fn==NULL || parser->lexer_iface.tok_fn==NULL || parser->lexer_iface.consume_fn==NULL ) {
		harbol_err_msg(NULL, parser->filename, "system error", NULL, NULL, "No lexer token functions loaded.");
		return NULL;
	}
	
	const struct HarbolMap *const grammar = harbol_cfg_get_section(parser->cfg, "grammar");
	if( grammar==NULL ) {
		harbol_err_msg(NULL, parser->filename, "system error", NULL, NULL, "Missing grammar section in config file '%s'.", parser->cfg_file);
		return NULL;
	} else if( grammar->len==0 ) {
		harbol_err_msg(NULL, parser->filename, "system error", NULL, NULL, "No grammar defined config file '%s'.", parser->cfg_file);
		return NULL;
	}
	
	struct HarbolMap rule_cache = harbol_map_make(4, &( bool ){false});
	for( size_t i=0; i < grammar->len; i++ ) {
		const struct HarbolVariant *const v = ( const struct HarbolVariant* )(grammar->datum[i]);
		const struct HarbolString *const str = *( const struct HarbolString *const * )(v->data);
		struct MetaLexer ml = { {0}, str->cstr, str->cstr, NULL, 1, 0, MetaTokenInvalid };
		struct MetaNode *rules = metaparser_parse_rule(&ml);
		//metanode_print(rules, 0);
		harbol_map_insert(&rule_cache, grammar->keys[i], grammar->keylens[i], &rules, sizeof rules);
		harbol_string_clear(&ml.lexeme);
	}
	
	struct TargumParseState state = {
		.parser     =  parser,
		.rules      = &rule_cache,
		.token_map  = &parser->token_lits,
		.filename   =  parser->filename,
		.lexer_pipe = &parser->lexer_iface,
	};
	
	state.recursive_def = calloc(rule_cache.len, sizeof *state.recursive_def);
	struct HarbolTree *root = _targum_parser_new_cst(&state, 0);
	if( root==NULL || harbol_tree_len(root)==0 ) {
		if( parser->warns ) {
			harbol_warn_msg(NULL, parser->filename, "runtime warning", NULL, NULL, "parsing '%s' failed.", ( const char* )(rule_cache.keys[0]));
		}
	} else if( (*parser->lexer_iface.tok_fn)(parser->lexer_iface.userdata, 0, &( size_t ){0}, &( size_t ){0}) != 0 ) {
		harbol_err_msg(NULL, parser->filename, "parse error", NULL, NULL, "Unparsed leftover tokens remaining.");
		targum_parser_free_cst(&root);
	}
	
	free(state.recursive_def); state.recursive_def = NULL;
	for( size_t i=0; i < rule_cache.len; i++ ) {
		struct MetaNode **rules = ( struct MetaNode** )(rule_cache.datum[i]);
		metanode_free(rules);
	}
	harbol_map_clear(&rule_cache);
	
	if( parser->lexer_iface.shutdown_fn != NULL ) {
		(*parser->lexer_iface.shutdown_fn)(parser->lexer_iface.userdata, parser->filename);
	}
	return root;
}

TARGUM_API void targum_parser_clear_cst(struct HarbolTree *const cst) {
	struct TargumCST *const first_cst = ( struct TargumCST* )(cst->data);
	free(first_cst->parsed); first_cst->parsed = NULL;
	
	for( size_t i=0; i < cst->kids.len; i++ ) {
		struct HarbolTree *kid = harbol_tree_get_node_by_index(cst, i);
		targum_parser_clear_cst(kid);
	}
}

TARGUM_API void targum_parser_free_cst(struct HarbolTree **const cst_ref) {
	if( *cst_ref==NULL )
		return;
	
	targum_parser_clear_cst(*cst_ref);
	harbol_tree_free(cst_ref);
}
