#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include "targum_parser.h"


/**
 * Structure of File:
 * MetaCompiler -> Starts with MetaLexer, MetaParser, then MetaAST.
 * MetaInterpreter -> after line 530.
 * Parser API is after the MetaInterpreter code.
 */

enum MetaToken {
	MetaTokenInvalid,
	MetaTokenRule,     /// <a>
	MetaTokenAlt,      /// | /
	MetaTokenLParens, MetaTokenRParens, /// ()
	MetaTokenLBrack,  MetaTokenRBrack,  /// []
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
	const char         *src, *iter, *line_start, *key;
	size_t              line, errs;
	enum MetaToken      token;
};

NO_NULL enum MetaToken metalexer_get_token(struct MetaLexer *mlexer);


enum MetaNodeType {
	MetaNodeInvalid = 0,
	MetaNodeRuleListExpr, /// <a> <b>, (<a> <b>) groups are parsed as rule lists. 
	MetaNodeOpt,          /// [<a> <b>]
	MetaNodeAlt,          /// <a> | <b>
	MetaNodePlusExpr,     /// +
	MetaNodeStarExpr,     /// *
	MetaNodePosLook,      /// &
	MetaNodeNegLook,      /// !
	MetaNodeLexToken,     /// {identifier}
	MetaNodeReqToken,     /// 'if'
	MetaNodeRuleExprStr,  /// "<a>"
	MetaNodeRuleExprAST,  /// ptr to <a> node
};

static inline const char *_get_metanode(const enum MetaNodeType tok) {
	switch( tok ) {
		case MetaNodeRuleListExpr: return "rule expr list";
		case MetaNodeOpt:          return "optional";
		case MetaNodeAlt:          return "alternate";
		case MetaNodePlusExpr:     return "one-or-more";
		case MetaNodeStarExpr:     return "none-or-more";
		case MetaNodePosLook:      return "positive lookahead";
		case MetaNodeNegLook:      return "negative lookahead";
		case MetaNodeLexToken:     return "lex token";
		case MetaNodeReqToken:     return "req token";
		case MetaNodeRuleExprStr:  return "rule expr string";
		case MetaNodeRuleExprAST:  return "rule expr node";
		case MetaNodeInvalid:
		default:                   return "invalid metanode";
	}
}

struct MetaNode {
	union {
		struct HarbolArray               *node_list;
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
NO_NULL void     metanode_free(struct MetaNode **nref, bool follow);
void             metanode_print(const struct MetaNode *n, size_t tabs, FILE *stream);


/**
 * Grammar of the MetaAST Parser
 * 
 * rule     := sequence *( ('|' | '/') sequence ) .
 * sequence := +rep .
 * rep      := ['+' | '*' | '&' | '!'] factor .
 * factor   := terminal | '<' IDEN '>' | '(' rule ')' | '[' rule ']' .
 * terminal := "'" KEYWORD "'" | '"' KEYWORD '"' | '{' KEYWORD '}' .
 */
typedef struct MetaNode *MetaParseFunc(struct MetaLexer *mlexer);

MetaParseFunc
	metaparser_parse_rule,
	metaparser_parse_seq,
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

/// rule := sequence *( ('|' | '/') sequence ) .
struct MetaNode *metaparser_parse_rule(struct MetaLexer *const mlexer) {
	metalexer_get_token(mlexer);
	const enum MetaToken *t = &mlexer->token;
	struct MetaNode *n = metaparser_parse_seq(mlexer);
	while( *t==MetaTokenAlt ) {
		metalexer_get_token(mlexer);
		n = metanode_new_alt(n, metaparser_parse_seq(mlexer));
	}
	return n;
}

struct HarbolArray *_make_metanode_list(struct MetaLexer *const mlexer, MetaParseFunc *const func) {
	struct HarbolArray *nodelist = harbol_array_new(sizeof(struct MetaNode*), ARRAY_DEFAULT_SIZE);
	for( struct MetaNode *n = (*func)(mlexer); n != NULL; n = (*func)(mlexer) ) {
		if( harbol_array_full(nodelist) && !harbol_array_grow(nodelist, sizeof(struct MetaNode*)) ) {
			harbol_err_msg(NULL, "grammar", "memory error", &mlexer->line, &( size_t ){ mlexer->line_start - mlexer->src }, "Unable to grow node list. Aborting...");
			abort();
		}
		harbol_array_insert(nodelist, &n, sizeof n);
	}
	if( nodelist->len==0 ) {
		harbol_warn_msg(NULL, "grammar", "critical warning", &mlexer->line, &( size_t ){ mlexer->line_start - mlexer->src }, "production '%s' produced an empty rule, freeing...", mlexer->key);
		harbol_array_cleanup(&nodelist);
	}
	return nodelist;
}

/** sequence := +rep . */
struct MetaNode *metaparser_parse_seq(struct MetaLexer *const mlexer) {
	return metanode_new_listexpr(_make_metanode_list(mlexer, metaparser_parse_rep));
}

/** rep := ['+' | '*' | '&' | '!'] factor . */
struct MetaNode *metaparser_parse_rep(struct MetaLexer *const mlexer) {
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
 * factor   := terminal | '<' IDEN '>' | '(' rule ')' | '[' rule ']' .
 * terminal := "'" KEYWORD "'" | '"' KEYWORD '"' | '{' KEYWORD '}'   .
 */
struct MetaNode *metaparser_parse_factor(struct MetaLexer *const mlexer) {
	const enum MetaToken *const t = &mlexer->token;
	switch( *t ) {
		case MetaTokenLParens: {
			struct MetaNode *group = metaparser_parse_rule(mlexer);
			if( *t != MetaTokenRParens ) {
				harbol_err_msg(&mlexer->errs, "grammar", "error", &mlexer->line, &( size_t ){ mlexer->line_start - mlexer->src }, "Missing right parens ')' in production '%s'!", mlexer->key);
				metanode_free(&group, false);
			} else {
				metalexer_get_token(mlexer);
			}
			return group;
		}
		case MetaTokenLBrack: {
			struct MetaNode *opt = metanode_new_opt(metaparser_parse_rule(mlexer));
			if( *t != MetaTokenRBrack ) {
				harbol_err_msg(&mlexer->errs, "grammar", "error", &mlexer->line, &( size_t ){ mlexer->line_start - mlexer->src }, "Missing right bracket ']' in production '%s'!", mlexer->key);
				metanode_free(&opt, false);
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
			//harbol_warn_msg(NULL, "grammar", "critical warning", &mlexer->line, &( size_t ){ mlexer->line_start - mlexer->src }, "returning a NULL factor node in production '%s'", mlexer->key);
			return NULL;
	}
}


struct MetaNode *metanode_new_listexpr(struct HarbolArray *const rule_list)
{
	struct MetaNode *n = calloc(1, sizeof *n);
	assert( n != NULL && "bad MetaNode rule list expression." );
	n->node.node_list = rule_list;
	n->tag = MetaNodeRuleListExpr;
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
	n->tag = MetaNodeRuleExprStr;
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

void metanode_free(struct MetaNode **const n, const bool follow)
{
	if( *n==NULL ) {
		return;
	}
	switch( (*n)->tag ) {
		case MetaNodeRuleListExpr: {
			struct HarbolArray *nodes = (*n)->node.node_list;
			for( size_t i=0; i < nodes->len; i++ ) {
				struct MetaNode **p = harbol_array_get(nodes, i, sizeof *p);
				metanode_free(p, follow);
			}
			harbol_array_cleanup(&(*n)->node.node_list);
			break;
		}
		case MetaNodeAlt: {
			metanode_free(&(*n)->node.alt_expr.l, follow);
			metanode_free(&(*n)->node.alt_expr.r, follow);
			break;
		}
		case MetaNodeOpt:
		case MetaNodePlusExpr:
		case MetaNodeStarExpr:
		case MetaNodePosLook:
		case MetaNodeNegLook: {
			metanode_free(&(*n)->node.node_expr, follow);
			break;
		}
		case MetaNodeLexToken:
		case MetaNodeReqToken:
		case MetaNodeRuleExprStr: {
			harbol_string_clear(&(*n)->node.token_expr);
			break;
		}
		case MetaNodeRuleExprAST: {
			if( follow ) {
				metanode_free(&(*n)->node.node_expr, follow);
			} else {
				(*n)->node.node_expr = NULL;
			}
			break;
		}
		case MetaNodeInvalid:
			break;
	}
	free(*n); *n = NULL;
}

void metanode_print(const struct MetaNode *const n, const size_t tabs, FILE *const stream)
{
	if( n==NULL ) {
		return;
	}
	_print_tabs(tabs, stream);
	switch( n->tag ) {
		case MetaNodeRuleListExpr: {
			fprintf(stream, "(%p) metanode :: rule list expr\n", ( const void* )(n));
			const struct HarbolArray *const arr = n->node.node_list;
			for( size_t i=0; i < arr->len; i++ ) {
				struct MetaNode **p = harbol_array_get(arr, i, sizeof *p);
				metanode_print(*p, tabs + 1, stream);
			}
			break;
		}
		case MetaNodeAlt:
			fprintf(stream, "(%p) metanode :: alternate expr, printing left\n", ( const void* )(n));
			metanode_print(n->node.alt_expr.l, tabs + 1, stream);
			_print_tabs(tabs, stream);
			fputs("metanode :: alternate expr, printing right\n", stream);
			metanode_print(n->node.alt_expr.r, tabs + 1, stream);
			break;
		case MetaNodeOpt:
			fprintf(stream, "(%p) metanode :: optional expr\n", ( const void* )(n));
			metanode_print(n->node.node_expr, tabs + 1, stream);
			break;
		case MetaNodePlusExpr:
			fprintf(stream, "(%p) metanode :: one-or-more expr\n", ( const void* )(n));
			metanode_print(n->node.node_expr, tabs + 1, stream);
			break;
		case MetaNodeStarExpr:
			fprintf(stream, "(%p) metanode :: zero-or-more expr\n", ( const void* )(n));
			metanode_print(n->node.node_expr, tabs + 1, stream);
			break;
		case MetaNodePosLook:
			fprintf(stream, "(%p) metanode :: positive lookahead expr\n", ( const void* )(n));
			metanode_print(n->node.node_expr, tabs + 1, stream);
			break;
		case MetaNodeNegLook:
			fprintf(stream, "(%p) metanode :: negative lookahead expr\n", ( const void* )(n));
			metanode_print(n->node.node_expr, tabs + 1, stream);
			break;
		case MetaNodeLexToken:
			fprintf(stream, "(%p) metanode :: lex token expr: '%s'\n", ( const void* )(n), n->node.token_expr.cstr);
			break;
		case MetaNodeReqToken:
			fprintf(stream, "(%p) metanode :: required token expr: '%s'\n", ( const void* )(n), n->node.token_expr.cstr);
			break;
		case MetaNodeRuleExprStr:
			fprintf(stream, "(%p) metanode :: rule string expr: '%s'\n", ( const void* )(n), n->node.token_expr.cstr);
			break;
		case MetaNodeRuleExprAST:
			fprintf(stream, "(%p) metanode :: rule node expr: '%p'\n", ( const void* )(n), ( void* )(n->node.node_expr));
			break;
		
		case MetaNodeInvalid:
		default:
			fprintf(stream, "(%p) metanode :: invalid expr\n", ( const void* )(n));
			break;
	}
}

void print_rules(const struct HarbolMap *const rules, FILE *const stream) {
	for( size_t i=0; i < rules->len; i++ ) {
		const struct MetaNode **n = harbol_map_idx_get(rules, i);
		const char *key = harbol_map_key_val(rules, n, sizeof n, &( size_t ){0});
		fprintf(stream, "rule :: '%s'\n", key);
		metanode_print(*n, 0, stream);
	}
}


/// effectively transforms the ASTs into a directed (cyclical) graph.
static void _attach_rule_metanodes(struct MetaNode *const n, const struct HarbolMap *const rules) {
	if( n==NULL ) {
		return;
	}
	switch( n->tag ) {
		case MetaNodeRuleListExpr: {
			const struct HarbolArray *const arr = n->node.node_list;
			for( size_t i=0; i < arr->len; i++ ) {
				struct MetaNode **p = harbol_array_get(arr, i, sizeof *p);
				_attach_rule_metanodes(*p, rules);
			}
			break;
		}
		case MetaNodeAlt:
			_attach_rule_metanodes(n->node.alt_expr.l, rules);
			_attach_rule_metanodes(n->node.alt_expr.r, rules);
			break;
		
		case MetaNodeOpt:
		case MetaNodePlusExpr: case MetaNodeStarExpr:
		case MetaNodePosLook:  case MetaNodeNegLook:
			_attach_rule_metanodes(n->node.node_expr, rules);
			break;
		
		case MetaNodeRuleExprStr: {
			struct MetaNode **const rule = harbol_map_key_get(rules, n->node.token_expr.cstr, n->node.token_expr.len + 1);
			if( rule != NULL && *rule != NULL ) {
				harbol_string_clear(&n->node.token_expr);
				n->node.node_expr = *rule;
				n->tag = MetaNodeRuleExprAST;
			} else {
				harbol_err_msg(NULL, "grammar", "runtime error", NULL, NULL, "Undefined rule '%s'", n->node.token_expr.cstr);
			}
			break;
		}
		case MetaNodeRuleExprAST:
		case MetaNodeLexToken: case MetaNodeReqToken:
		case MetaNodeInvalid:  default:
			break;
	}
}

/// 
static void _get_rule_deps(const struct HarbolMap *const rules, const struct HarbolMap *const deps, const struct MetaNode *n, const size_t curr_rule) {
	if( n==NULL ) {
		return;
	}
	switch( n->tag ) {
		case MetaNodeRuleListExpr: {
			const struct HarbolArray *const arr = n->node.node_list;
			for( size_t i=0; i < arr->len; i++ ) {
				const struct MetaNode **const p = harbol_array_get(arr, i, sizeof *p);
				_get_rule_deps(rules, deps, *p, curr_rule);
			}
			break;
		}
		case MetaNodeAlt:
			_get_rule_deps(rules, deps, n->node.alt_expr.l, curr_rule);
			_get_rule_deps(rules, deps, n->node.alt_expr.r, curr_rule);
			break;
		
		case MetaNodeOpt:
		case MetaNodePlusExpr: case MetaNodeStarExpr:
		case MetaNodePosLook:  case MetaNodeNegLook:
			_get_rule_deps(rules, deps, n->node.node_expr, curr_rule);
			break;
		
		case MetaNodeRuleExprAST: {
			const struct MetaNode **const rule_ref = harbol_map_idx_get(rules, curr_rule);
			struct HarbolMap *const restrict set = harbol_map_key_get(deps, rule_ref, sizeof *rule_ref);
			/*{
				const char *subkey = harbol_map_key_val(rules, rule_ref, sizeof *rule_ref, &( size_t ){0});
				printf("\t_get_rule_deps :: rule '%s'\n", subkey);
			}*/
			const bool set_value = false;
			harbol_map_key_set(set, &n->node.node_expr, sizeof n->node.node_expr, &set_value, sizeof set_value);
			break;
		}
		case MetaNodeRuleExprStr:
		case MetaNodeLexToken: case MetaNodeReqToken:
		case MetaNodeInvalid:  default:
			break;
	}
}

static void _prune_unused_rules(struct HarbolMap *const rules) {
	/** Credit to `devast8a` for algorithm.
		seen, working = {root}, {root}
		while working is non empty:
			current = pop item from working
			for every subrule directly reachable in current:
				if subrule is not in seen:
					add subrule to seen and to working
	 */
	bool throwaway = false;
	struct HarbolMap deps = harbol_map_make(8, &throwaway);
	for( size_t i=0; i < rules->len; i++ ) {
		struct HarbolMap set = harbol_map_make(8, &throwaway);
		const struct MetaNode **const rule_ref = harbol_map_idx_get(rules, i);
		harbol_map_insert(&deps, rule_ref, sizeof *rule_ref, &set, sizeof set);
		_get_rule_deps(rules, &deps, *rule_ref, i);
	}
	
	struct HarbolMap   seen    = harbol_map_make(8, &throwaway);
	struct HarbolArray working = harbol_array_make(sizeof(struct MetaNode*), rules->len, &throwaway);
	const struct MetaNode **const root = harbol_map_idx_get(rules, 0);
	harbol_map_insert(&seen, root, sizeof *root, &throwaway, sizeof throwaway);
	harbol_array_append(&working, root, sizeof *root);
	
	while( !harbol_array_empty(&working) ) {
		const struct MetaNode **const current  = harbol_array_pop(&working, sizeof *current);
		const struct HarbolMap *const deps_set = harbol_map_key_get(&deps, current, sizeof *current);
		for( size_t i=0; i < deps_set->len; i++ ) {
			const struct MetaNode **const subrule = ( const struct MetaNode** )(deps_set->keys[i]);
			if( !harbol_map_has_key(&seen, subrule, sizeof *subrule) ) {
				harbol_map_key_set(&seen, subrule, sizeof *subrule, &throwaway, sizeof throwaway);
				if( harbol_array_full(&working) ) {
					harbol_array_grow(&working, sizeof(struct MetaNode*));
				}
				harbol_array_append(&working, subrule, sizeof *subrule);
			}
		}
	}
	harbol_array_clear(&working);
	for( size_t i=0; i < deps.len; i++ ) {
		struct HarbolMap *const set = harbol_map_idx_get(&deps, i);
		harbol_map_clear(set);
	}
	harbol_map_clear(&deps);
	
	size_t deleted = 0;
	for( size_t i = rules->len - 1; i < rules->len; i-- ) {
		struct MetaNode **const n = harbol_map_idx_get(rules, i);
		if( !harbol_map_has_key(&seen, n, sizeof *n) ) {
			metanode_free(n, false);
			harbol_map_idx_rm(rules, i);
			i = rules->len;
			deleted++;
		}
	}
	harbol_map_clear(&seen);
}

#if 0
static void _transform_left_recursion(struct HarbolMap *const rules) {
	/**
	 * anything like:
		'expr': "<expr> '-' <term> | <term>"
	 * has to transform into:
		'expr': "<term> *('-' <term>)"
	 *
		rule -> (rule intermediate sequence) | sequence .
		rule -> sequence *( intermediate sequence ) .
		
		rule -> rule sequence .
		rule -> +sequence .
	 */
	( void )(rules);
}
#endif

static bool _has_cycle(const struct MetaNode *const n, const struct MetaNode *const rule, struct HarbolMap *const seen) {
	if( n==NULL ) {
		return false;
	}
	switch( n->tag ) {
		case MetaNodeRuleListExpr: {
			const struct HarbolArray *const arr = n->node.node_list;
			for( size_t i=0; i < arr->len; i++ ) {
				const struct MetaNode **const p = harbol_array_get(arr, i, sizeof *p);
				if( _has_cycle(*p, rule, seen) ) {
					return true;
				}
			}
			break;
		}
		case MetaNodeAlt: {
			const bool l = _has_cycle(n->node.alt_expr.l, rule, seen);
			const bool r = _has_cycle(n->node.alt_expr.r, rule, seen);
			return l || r;
		}
		case MetaNodeOpt:
		case MetaNodePlusExpr: case MetaNodeStarExpr:
		case MetaNodePosLook:  case MetaNodeNegLook:
			return _has_cycle(n->node.node_expr, rule, seen);
		
		case MetaNodeRuleExprAST: {
			if( harbol_map_has_key(seen, &n->node.node_expr, sizeof n->node.node_expr) ) {
				return true;
			} else {
				const bool throwaway = false;
				harbol_map_insert(seen, &n->node.node_expr, sizeof n->node.node_expr, &throwaway, sizeof throwaway);
				return _has_cycle(n->node.node_expr, n->node.node_expr, seen);
			}
		}
		case MetaNodeLexToken: case MetaNodeReqToken: {
			/// rule has a way to consume input.
			if( harbol_map_has_key(seen, &rule, sizeof rule) ) {
				const bool t = true;
				harbol_map_key_set(seen, &rule, sizeof rule, &t, sizeof t);
			}
			return false;
		}
		case MetaNodeRuleExprStr:
		case MetaNodeInvalid: default:
			break;
	}
	return false;
}

static void _check_inf_loop(struct HarbolMap *const rules, bool *const restrict has_cycle, bool *const restrict consumes_input) {
	/**
	 * First we need to detect a cycle within the Abstract Syntax "Graph"
	 * Then we check if any of the productions in the cycle can consume input.
	 */
	const struct MetaNode **const root = harbol_map_idx_get(rules, 0);
	struct HarbolMap seen = harbol_map_make(8, &( bool ){false});
	harbol_map_insert(&seen, root, sizeof *root, &( bool ){false}, sizeof(bool));
	*has_cycle = _has_cycle(*root, *root, &seen);
	for( size_t i=0; i < seen.len; i++ ) {
		const bool *const takes_input = harbol_map_idx_get(&seen, i);
		*consumes_input |= *takes_input;
	}
	harbol_map_clear(&seen);
}
/**************************************************************************/


enum /** ParseFlags */ {
	FlagAlt,  FlagOpt,
	FlagPlus, FlagStar,
	FlagLookAhead,
	MaxParseFlags,
};

struct TargumParseState {
	struct TargumParser     *parser;
	struct HarbolMap        *rules, *token_map;
	FILE                    *rule_trace;
	const char              *filename;
	const struct LexerIFace *lexer_pipe;
	size_t                   iterations, curr_lookahead, max_iterations, tokens_consumed;
	
	/**
	 * rules can nest the same grammar expression types.
	 * example: '[ (<a> *<b>) <c> [+<d>] ]'.
	 * Having a simple bitwise flag isn't enough in this case.
	 * Do you toggle the bit flag after the inner or outter
	 * optional expression fails/succeeds?
	 */
	uint_least16_t           flags[MaxParseFlags];
	bool                     hit_max_recurs : 1;
};


static NO_NULL struct HarbolTree *_targum_parser_new_cst(const char node_cstr[static 1], const size_t cstr_len)
{
	const struct TargumCST cst = {
		.parsed = dup_str(node_cstr),
		.len    = cstr_len,
		.tag    = SIZE_MAX
	};
	if( cst.parsed==NULL ) {
		return NULL;
	}
	return harbol_tree_new(&cst, sizeof cst);
}


enum ParseRes {
	ParseResFail, /// production failed hard.
	ParseResOk,   /// production failed softly.
	ParseResGood, /// production succeeded.
};

enum ParseRes _targum_parser_exec_meta_ast(
	struct TargumParseState *const state,
	const struct MetaNode   *const ast,
	const struct MetaNode   *const rule,
	struct HarbolTree       *const root
) {
	const struct LexerIFace *const lex = state->lexer_pipe;
	const char *const rule_key = harbol_map_key_val(state->rules, &rule, sizeof rule, &( size_t ){0});
	
	if( state->rule_trace != NULL ) {
		fprintf(state->rule_trace, "rule :: '%s', MetaAST tag: '%s', MetaAST ptr: '%p'\n", rule_key, _get_metanode(ast->tag), ( const void* )(ast));
	}
	
	state->iterations++;
	if( state->iterations > state->max_iterations ) {
		state->iterations = state->max_iterations;
	}
	
	/// `iterations` resets on every token consumption. 
	if( state->iterations==state->max_iterations ) {
		if( !state->hit_max_recurs ) {
			harbol_err_msg(NULL, state->filename, "runtime error", NULL, NULL, "Non-deterministic recursive rule detected: '%s'", rule_key);
			state->hit_max_recurs = true;
		}
		return ParseResFail;
	}
	
	switch( ast->tag ) {
		case MetaNodeInvalid: {
			harbol_err_msg(NULL, state->filename, "runtime error", NULL, NULL, "Invalid MetaNode! rule: '%s' | ast: '%p'", rule_key, ( const void* )(ast));
			return ParseResFail;
		}
		case MetaNodeRuleListExpr: {
			/// Returns result as it is.
			const struct HarbolArray *const rule_list = ast->node.node_list;
			if( rule_list==NULL || rule_list->len==0 ) {
				harbol_warn_msg(NULL, state->filename, "runtime warning", NULL, NULL, "rule sequence node for rule '%s' has bad node list.", rule_key);
				return ParseResOk;
			}
			
			enum ParseRes res = ParseResFail;
			for( size_t i=0; i < rule_list->len; i++ ) {
				const struct MetaNode **const node = harbol_array_get(rule_list, i, sizeof *node);
				if( (res = _targum_parser_exec_meta_ast(state, *node, rule, root))==ParseResFail ) {
					break;
				}
			}
			return res;
		}
		case MetaNodeOpt: {
			/// On failure, optional expressions must backtrack the lexer
			/// and remove any parsed CSTs but returns success.
			const size_t saved_lookahead   = state->curr_lookahead;
			const size_t saved_token_count = state->tokens_consumed;
			const size_t kids = root->kids.len;
			
			state->flags[FlagOpt]++;
			const enum ParseRes res = _targum_parser_exec_meta_ast(state, ast->node.node_expr, rule, root);
			state->flags[FlagOpt]--;
			/// if we failed BUT the optional consumed tokens, fail hard.
			if( res==ParseResFail ) {
				if( state->tokens_consumed > saved_token_count ) {
					harbol_err_msg(NULL, state->filename, "runtime error", NULL, NULL, "optional expression in rule '%s' passed then failed to complete.", rule_key);
					return res;
				} else if( state->curr_lookahead > saved_lookahead ) {
					const size_t child_count = root->kids.len;
					if( child_count > kids ) {
						for( size_t i=0; i < (child_count - kids); i++ ) {
							const size_t idx = root->kids.len - 1;
							struct HarbolTree *const cst_node = harbol_tree_get_node_by_index(root, idx);
							struct TargumCST *const cst = harbol_tree_get(cst_node);
							free(cst->parsed); cst->parsed = NULL;
							harbol_tree_rm_index(root, idx);
						}
					}
					state->curr_lookahead = saved_lookahead;
				}
			}
			return ParseResGood;
		}
		case MetaNodeAlt: {
			/// On failure, alt expressions must backtrack the lexer
			/// remove any parsed CSTs, then try the rightward node.
			/// returns result as is.
			const size_t saved_lookahead   = state->curr_lookahead;
			const size_t saved_token_count = state->tokens_consumed;
			const size_t kids = root->kids.len;
			
			state->flags[FlagAlt]++;
			const enum ParseRes result = _targum_parser_exec_meta_ast(state, ast->node.alt_expr.l, rule, root);
			state->flags[FlagAlt]--;
			if( result > ParseResFail ) {
				return result;
			} else {
				if( state->curr_lookahead > saved_lookahead ) {
					const size_t child_count = root->kids.len;
					if( child_count > kids ) {
						for( size_t i=0; i < (child_count - kids); i++ ) {
							const size_t idx = root->kids.len - 1;
							struct HarbolTree *const cst_node = harbol_tree_get_node_by_index(root, idx);
							struct TargumCST *const cst = harbol_tree_get(cst_node);
							free(cst->parsed); cst->parsed = NULL;
							harbol_tree_rm_index(root, idx);
						}
					}
				}
				state->curr_lookahead  = saved_lookahead;
				state->tokens_consumed = saved_token_count;
				return _targum_parser_exec_meta_ast(state, ast->node.alt_expr.r, rule, root);
			}
		}
		
		case MetaNodePlusExpr: {
			/// returns success if at least one expression returned success.
			enum ParseRes res = ParseResFail;
			state->flags[FlagPlus]++;
			while( _targum_parser_exec_meta_ast(state, ast->node.node_expr, rule, root)==ParseResGood ) {
				res = ParseResGood;
			}
			state->flags[FlagPlus]--;
			return res;
		}
		case MetaNodeStarExpr: {
			/// always returns success.
			state->flags[FlagStar]++;
			while( _targum_parser_exec_meta_ast(state, ast->node.node_expr, rule, root)==ParseResGood );
			state->flags[FlagStar]--;
			return ParseResGood;
		}
		
		case MetaNodePosLook: {
			state->flags[FlagLookAhead]++;
			const enum ParseRes result = _targum_parser_exec_meta_ast(state, ast->node.node_expr, rule, root);
			state->curr_lookahead = 0;
			state->flags[FlagLookAhead]--;
			return result;
		}
		case MetaNodeNegLook: {
			state->flags[FlagLookAhead]++;
			const enum ParseRes result = _targum_parser_exec_meta_ast(state, ast->node.node_expr, rule, root);
			state->curr_lookahead = 0;
			state->flags[FlagLookAhead]--;
			return !result;
		}
		
		case MetaNodeLexToken: {
			const struct HarbolString *const lit_str = &ast->node.token_expr;
			const uint32_t *const lex_tok_val = harbol_map_key_get(state->token_map, lit_str->cstr, lit_str->len+1);
			if( lex_tok_val==NULL ) {
				harbol_err_msg(NULL, state->filename, "runtime error", NULL, NULL, "Undefined token type '%s' in rule '%s'", lit_str->cstr, rule_key);
				return ParseResFail;
			}
			
			size_t
				line = 0
			  , col  = 0
			;
			const uint32_t tok_val = (*lex->tok_fn)(lex->userdata, state->curr_lookahead, &line, &col);
			struct {
				const char *str;
				size_t      len;
			} tok = {0};
			tok.str = (*lex->lexeme_fn)(lex->userdata, state->curr_lookahead, &line, &col, &tok.len);
			if( tok_val==0 ) {
				/// got invalid/EOF token?
				return ParseResFail;
			} else if( *lex_tok_val != tok_val ) {
				if( !state->flags[FlagPlus] && !state->flags[FlagStar] && !state->flags[FlagAlt] && !state->flags[FlagOpt] && !state->flags[FlagLookAhead] ) {
					harbol_err_msg(NULL, state->filename, "syntax error", &line, &col, "Expected '%s' but got '%.*s'", lit_str->cstr, ( int )(tok.len), tok.str);
				}
				return ParseResFail;
			}
			
			/// we're not in the look-ahead expressions, consume the token!
			const bool consume = !state->flags[FlagLookAhead];
			if( consume ) {
				state->iterations = 0;
				struct TargumCST cst = {
					.parsed = calloc(tok.len + 1, sizeof(char)),
					.len    = tok.len,
					.tag    = tok_val
				};
				if( cst.parsed==NULL ) {
					harbol_err_msg(NULL, state->filename, "memory error", &line, &col, "Unable to allocate CST Node for lexical token!");
					return ParseResFail;
				}
				strncpy(cst.parsed, tok.str, tok.len);
				cst.parsed[tok.len] = 0;
				harbol_tree_insert_val(root, &cst, sizeof cst);
				state->tokens_consumed++;
			} else {
				state->curr_lookahead++;
			}
			(*lex->consume_fn)(lex->userdata, state->curr_lookahead, consume);
			return ParseResGood;
		}
		case MetaNodeReqToken: {
			const struct HarbolString *const lit_str = &ast->node.token_expr;
			size_t
				line = 0
			  , col  = 0
			;
			const uint32_t tok_val = (*lex->tok_fn)(lex->userdata, state->curr_lookahead, &line, &col);

			struct {
				const char *str;
				size_t      len;
			} tok = {0};
			tok.str = (*lex->lexeme_fn)(lex->userdata, state->curr_lookahead, &line, &col, &tok.len);
			if( tok_val==0 || strncmp(lit_str->cstr, tok.str, tok.len) ) {
				if( /*!state->flags[FlagPlus] && */!state->flags[FlagStar] && !state->flags[FlagAlt] && !state->flags[FlagOpt] && !state->flags[FlagLookAhead] ) {
					harbol_err_msg(NULL, state->filename, "syntax error", &line, &col, "Expected '%s' but got '%.*s'", lit_str->cstr, ( int )(tok.len), tok.str);
				}
				return ParseResFail;
			}
			const bool consume = !state->flags[FlagLookAhead];
			if( consume ) {
				state->iterations = 0;
				struct TargumCST cst = {
					.parsed = calloc(tok.len + 1, sizeof(char)),
					.len    = tok.len,
					.tag    = tok_val
				};
				if( cst.parsed==NULL ) {
					harbol_err_msg(NULL, state->filename, "memory error", &line, &col, "Unable to allocate CST Node for required token!");
					return ParseResFail;
				}
				strncpy(cst.parsed, tok.str, tok.len);
				cst.parsed[tok.len] = 0;
				harbol_tree_insert_val(root, &cst, sizeof cst);
				state->tokens_consumed++;
			} else {
				state->curr_lookahead++;
			}
			(*lex->consume_fn)(lex->userdata, state->curr_lookahead, consume);
			return ParseResGood;
		}
		
		case MetaNodeRuleExprAST: {
			const struct MetaNode *const subrule = ast->node.node_expr;
			size_t key_len = 0;
			const char *const subrule_key = harbol_map_key_val(state->rules, &subrule, sizeof subrule, &key_len);
			struct HarbolTree *subchild = _targum_parser_new_cst(subrule_key, key_len);
			if( subchild==NULL ) {
				if( !state->flags[FlagPlus] && !state->flags[FlagStar] && !state->flags[FlagAlt] && !state->flags[FlagOpt] && !state->flags[FlagLookAhead] ) {
					harbol_err_msg(NULL, state->filename, "memory error", NULL, NULL, "Failed to allocate tree for rule '%s'", subrule_key);
				}
				return ParseResFail;
			}
			
			enum ParseRes result = _targum_parser_exec_meta_ast(state, subrule, subrule, subchild);
			if( result==ParseResFail ) {
				targum_parser_free_cst(&subchild);
			} else if( subchild->kids.len==0 ) {
				if( state->parser->warns ) {
					harbol_warn_msg(NULL, state->filename, "runtime warning", NULL, NULL, "rule '%s' produced no node(s).", subrule_key);
				}
				targum_parser_free_cst(&subchild);
				return ParseResOk;
			}
			if( subchild != NULL ) {
				harbol_tree_insert_node(root, &subchild);
			}
			return result;
		}
		
		default: {
			return ParseResFail;
		}
	}
}



TARGUM_API struct TargumParser targum_parser_make(
	LexerStartUpFunc *const startup_func,
	LexerShutDwnFunc *const shutdown_func,
	TokenFunc        *const token_func,
	LexemeFunc       *const lexeme_func,
	ConsumeFunc      *const consume_func,
	void             *const userdata,
	const size_t            userdata_len,
	const char              filename[static 1],
	struct HarbolMap *const cfg
) {
	return ( struct TargumParser ){
		.lexer_iface.startup_fn  = startup_func,
		.lexer_iface.shutdown_fn = shutdown_func,
		.lexer_iface.tok_fn      = token_func,
		.lexer_iface.lexeme_fn   = lexeme_func,
		.lexer_iface.consume_fn  = consume_func,
		.lexer_iface.userdata    = userdata,
		.lexer_iface.len_data    = userdata_len,
		.filename                = filename,
		.cfg                     = cfg,
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
	if( free_config ) {
		harbol_cfg_free(&parser->cfg);
	}
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
	struct HarbolTree *root = NULL;
	if( parser->filename==NULL ) {
		harbol_err_msg(NULL, NULL, "system error", NULL, NULL, "No file name given.");
		return root;
	} else if( parser->cfg==NULL ) {
		harbol_err_msg(NULL, parser->filename, "system error", NULL, NULL, "No grammar config loaded.");
		return root;
	} else if( parser->lexer_iface.lexeme_fn==NULL || parser->lexer_iface.tok_fn==NULL || parser->lexer_iface.consume_fn==NULL ) {
		harbol_err_msg(NULL, parser->filename, "system error", NULL, NULL, "No lexer token functions loaded.");
		return root;
	}
	
	const struct HarbolMap *const grammar = harbol_cfg_get_section(parser->cfg, "grammar");
	if( grammar==NULL ) {
		harbol_err_msg(NULL, parser->filename, "system error", NULL, NULL, "Missing grammar section in config file '%s'.", parser->cfg_file);
		return root;
	} else if( grammar->len==0 ) {
		harbol_err_msg(NULL, parser->filename, "system error", NULL, NULL, "No grammar defined config file '%s'.", parser->cfg_file);
		return root;
	}
	
	/// get parser settings.
	{
		const bool *const warnings = harbol_cfg_get_bool(parser->cfg, "settings.warnings");
		if( warnings != NULL ) {
			parser->warns = *warnings;
		} else {
			harbol_warn_msg(NULL, parser->filename, "system warning", NULL, NULL, "'warnings' key missing in parser settings section, defaulting to warnings disabled.");
		}
	}
	
	struct HarbolMap rules_cache = harbol_map_make(8, &( bool ){false});
	for( size_t i=0; i < grammar->len; i++ ) {
		const struct HarbolVariant *const v   =  ( const struct HarbolVariant* )(grammar->datum[i]);
		const char                 *const key =  ( const char* )(grammar->keys[i]);
		const struct HarbolString  *const str = *( const struct HarbolString *const * )(v->data);
		struct MetaLexer ml = { {0}, str->cstr, str->cstr, str->cstr, key, 1, 0, MetaTokenInvalid };
		struct MetaNode *rules = metaparser_parse_rule(&ml);
		harbol_map_insert(&rules_cache, key, grammar->keylens[i], &rules, sizeof rules);
		harbol_string_clear(&ml.lexeme);
	}
	
	//print_rules(&rules_cache, stdout);
	
	/// form the individual ASTs into a directed, cyclic graph.
	for( size_t i=0; i < rules_cache.len; i++ ) {
		struct MetaNode **const n = harbol_map_idx_get(&rules_cache, i);
		_attach_rule_metanodes(*n, &rules_cache);
	}
	
	/// reduce memory usage and less rules to mess around with.
	_prune_unused_rules(&rules_cache);
	
	/// Check if there's an infinite loop and if input is consumed.
	bool
		has_cycle      = false
	  , consumes_input = false
	;
	_check_inf_loop(&rules_cache, &has_cycle, &consumes_input);
	
	if( has_cycle && !consumes_input ) {
		struct HarbolString rule_strs = {0};
		for( size_t i=0; i < rules_cache.len; i++ ) {
			harbol_string_add_cstr(&rule_strs, ( const char* )(rules_cache.keys[i]));
			if( i+1 != rules_cache.len ) {
				harbol_string_add_cstr(&rule_strs, ", ");
			}
		}
		harbol_err_msg(NULL, parser->filename, "parse error", NULL, NULL, "detected deterministic recursion in grammar rules: '%s'.", rule_strs.cstr);
		harbol_string_clear(&rule_strs);
		goto parser_cleanup;
	}
	
	/// Finally interpret our MetaAST
	
	size_t max_iters = 5000;
	{
		const uintmax_t *const recursion_threshold = ( const uintmax_t* )(harbol_cfg_get_int(parser->cfg, "settings.recursion threshold"));
		if( recursion_threshold != NULL ) {
			max_iters = ( size_t )(*recursion_threshold);
		} else {
			harbol_warn_msg(NULL, parser->filename, "system warning", NULL, NULL, "'recursion threshold' key missing in parser settings section, defaulting to 5000 iterations.");
		}
	}
	
	bool trace_rules = false;
	{
		const bool *const _trace_rules = harbol_cfg_get_bool(parser->cfg, "settings.rule tracing");
		if( _trace_rules != NULL ) {
			trace_rules = *_trace_rules;
		} else {
			harbol_warn_msg(NULL, parser->filename, "system warning", NULL, NULL, "'rule tracing' key missing in parser settings section, defaulting to rule tracing disabled.");
		}
	}
	
	bool print_rule_tree = false;
	{
		const bool *const _print_rules = harbol_cfg_get_bool(parser->cfg, "settings.print rule tree");
		if( _print_rules != NULL ) {
			print_rule_tree = *_print_rules;
		} else {
			harbol_warn_msg(NULL, parser->filename, "system warning", NULL, NULL, "'print rule tree' key missing in parser settings section, defaulting to rule printing disabled.");
		}
	}
	
	struct TargumParseState state = {
		.parser         =  parser,
		.rules          = &rules_cache,
		.token_map      = &parser->token_lits,
		.filename       =  parser->filename,
		.lexer_pipe     = &parser->lexer_iface,
		.max_iterations =  max_iters,
		.rule_trace     = (trace_rules)? fopen("targum_parser_rule_tracing.txt", "w") : NULL
	};
	const struct MetaNode **const ast = harbol_map_idx_get(state.rules, 0);
	if( ast==NULL || *ast==NULL ) {
		harbol_err_msg(NULL, state.filename, "runtime error", NULL, NULL, "starter rule '%s' gave bad metanode!", ( const char* )(rules_cache.keys[0]));
		goto parser_cleanup;
	}
	
	root = _targum_parser_new_cst(( const char* )(state.rules->keys[0]), state.rules->keylens[0]);
	const enum ParseRes parse_res = _targum_parser_exec_meta_ast(&state, *ast, *ast, root);
	if( state.rule_trace != NULL ) {
		const char *str_parse_res = NULL;
		switch( parse_res ) {
			case ParseResFail: str_parse_res = "Fail";    break;
			case ParseResGood: str_parse_res = "Success"; break;
			case ParseResOk:   str_parse_res = "Ok";      break;
		}
		fprintf(state.rule_trace, "final parse result :: '%s'", str_parse_res);
		fclose(state.rule_trace); state.rule_trace = NULL;
	}
	
	if( print_rule_tree ) {
		FILE *rule_tree = fopen("targum_parser_rule_tree.txt", "w");
		for( size_t i=0; i < rules_cache.len; i++ ) {
			const char *key_name = ( const char* )(rules_cache.keys[i]);
			const struct MetaNode **const n = harbol_map_idx_get(&rules_cache, i);
			fprintf(rule_tree, "\nprinting MetaAST '%s' (%p):\n", key_name, ( const void* )(*n));
			metanode_print(*n, 0, rule_tree);
		}
		fclose(rule_tree); rule_tree = NULL;
	}
	
	if( parse_res==ParseResFail || root->kids.len==0 ) {
		if( parser->warns ) {
			const char *warn_msg = ( parse_res==ParseResFail )? "starting rule '%s' failed parsing." : "starter rule '%s' produced no parse tree nodes. freeing...";
			harbol_warn_msg(NULL, parser->filename, "runtime warning", NULL, NULL, warn_msg, ( const char* )(rules_cache.keys[0]));
		}
		targum_parser_free_cst(&root);
		goto parser_cleanup;
	}
	
	size_t line = 0, col = 0;
	const uint32_t token_val = (*parser->lexer_iface.tok_fn)(parser->lexer_iface.userdata, 0, &line, &col);
	if( token_val != 0 ) {
		size_t len = 0;
		const char *tok_str = (*parser->lexer_iface.lexeme_fn)(parser->lexer_iface.userdata, 0, &line, &col, &len);
		harbol_err_msg(NULL, parser->filename, "parse error", NULL, NULL, "unparsed, leftover tokens remaining '%.*s' at line: '%zu', col: '%zu', freeing parse tree nodes...", ( int )(len), tok_str, line, col);
		targum_parser_free_cst(&root);
	}
	
	
parser_cleanup:
	for( size_t i=0; i < rules_cache.len; i++ ) {
		struct MetaNode **const n = harbol_map_idx_get(&rules_cache, i);
		metanode_free(n, false);
	}
	harbol_map_clear(&rules_cache);
	
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
