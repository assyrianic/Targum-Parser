#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include "targum_parser.h"


/**
 * Katova's Grammar.
 * 
 * Grammar      = *TypeDecl +Rule .
 * TypeDecl     = 'type' identifier [ '=' ] ( Type | TypeSpec ) .
 * TypeSpec     = '{' +FieldList '}' .
 * Type         = identifier .
 * 
 * Field        = IdentList Type .
 * IdentList    = identifier *( ',' identifier ) .
 * FieldList    = Field *( ',' Field ) .
 * 
 * Rule         = 'rule' identifier Signature [ Block ] .
 * Signature    = Parameters [ Result ] .
 * Result       = Type | '(' IdentList ')' .
 * Parameters   = '(' [ FieldList ] ')' .
 * 
 * Block        = '{' +Statement '}' .
 * Statement    = TypeDecl | SimpleStmt | IfStmt | ForStmt | MatchStmt | LoopStmt | ReturnStmt .
 * 
 * IfStmt       = 'if' [ SimpleStmt ';' ] SimpleStmt Block [ 'else' ( IfStmt | Block ) ] .
 * 
 * ForStmt      = 'for' [ Condition(SimpleStmt) | ForClause ] Block .
 * ForClause    = [ InitStmt(SimpleStmt) ] ";" [ Condition(Expression) ] ";" [ PostStmt(SimpleStmt) ] .
 * 
 * LoopStmt     = 'break' | 'pass' .
 * ReturnStmt   = 'return' [ ExprList | ';' ] .
 * 
 * MatchStmt    = 'match' [ SimpleStmt ';' ] SimpleStmt '{' +MatchCase '}' .
 * CaseClause   = ExprList Block .
 * 
 * SimpleStmt   = '' | ExprStmt | Assignment | ShortVarDecl .
 * ExprStmt     = Expr .
 * Assignment   = ExprList ['+'] '=' ExprList .
 * ShortVarDecl = IdentList ':=' ExprList .
 * 
 * Expr         = OrExpr .
 * OrExpr       = AndExpr *( '||' ) AndExpr ) .
 * AndExpr      = EqExpr *( '&&' EqExpr ) .
 * EqExpr       = PrimaryExpr *( ( '=='|'!=' ) PrimaryExpr ) .
 * 
 * PrimaryExpr  = Operand *( '[' Expr ']' | '(' [ ExprList ] ')' ) .
 * Operand      = int | string | identifier | '(' Expr ')' .
 */

static struct KatovaAST *const _bad_node = &( struct KatovaAST ){0};

static struct KatovaAST *_new_katova_node(enum KatovaASTType tag);

void katova_parse_init_expr_header(struct TargumLexer *lexer, struct KatovaAST **init, struct KatovaAST **cond, struct KatovaAST **post);
struct KatovaAST *katova_parse_grammar(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_type_decl(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_type_spec(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_rule(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_field(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_params(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_signature(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_block(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_case_clause(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_match_stmt(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_for_stmt(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_if_stmt(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_stmt(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_simple_stmt(struct TargumLexer *lexer, struct KatovaAST *lhs);
struct KatovaAST *katova_parse_expr_list(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_expr(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_or_expr(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_and_expr(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_equality_expr(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_primary_expr(struct TargumLexer *lexer);
struct KatovaAST *katova_parse_operand(struct TargumLexer *lexer);


static const char *_get_lexeme(struct TargumLexer *const lexer) {
	return targum_lexer_get_lexeme(lexer, lexer->curr_tok);
}

static inline void _print_curr_token(struct TargumLexer *const lexer, FILE *const stream) {
	const size_t lexeme_len = targum_token_info_get_len(lexer->curr_tok);
	fprintf(stream, "curr token: '%.*s' | Pos line: %u, col: %u\n", ( int )(lexeme_len), _get_lexeme(lexer), lexer->curr_tok->line, lexer->curr_tok->col);
}


/** Grammar = *TypeDecl +Rule . */
struct KatovaAST *katova_parse_grammar(struct TargumLexer *const lexer) {
	struct TargumTokenInfo **token = &lexer->curr_tok;
	
	struct KatovaAST *grammar = _new_katova_node(KatovaASTGrammar);
	grammar->_.grammar.rules = harbol_array_make(sizeof(struct KatovaAST*), 4, &( bool ){false});
	grammar->_.grammar.types = harbol_array_make(sizeof(struct KatovaAST*), 4, &( bool ){false});
	/// parse until EOF.
	while( (*token)->tag != 0 ) {
		const char *lexeme = _get_lexeme(lexer);
		if( !strncmp(lexeme, "type", sizeof "type"-1) ) {
			struct KatovaAST *type_decl = katova_parse_type_decl(lexer);
			if( harbol_array_full(&grammar->_.grammar.types) ) {
				harbol_array_grow(&grammar->_.grammar.types, sizeof type_decl);
			}
			harbol_array_insert(&grammar->_.grammar.types, &type_decl, sizeof type_decl);
		} else if( !strncmp(lexeme, "rule", sizeof "rule"-1) ) {
			struct KatovaAST *rule_def = katova_parse_rule(lexer);
			if( harbol_array_full(&grammar->_.grammar.rules) ) {
				harbol_array_grow(&grammar->_.grammar.rules, sizeof rule_def);
			}
			harbol_array_insert(&grammar->_.grammar.rules, &rule_def, sizeof rule_def);
		} else {
			const size_t lexeme_len = targum_token_info_get_len(*token);
			harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "unknown token in top grammar: '%.*s'.", ( int )(lexeme_len), lexeme);
			return _bad_node;
		}
	}
	if( grammar->_.grammar.rules.len==0 ) {
		harbol_warn_msg(NULL, targum_lexer_get_filename(lexer), "warning", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "no rules defined.");
	}
	return grammar;
}

/**
 * TypeDecl = 'type' identifier [ '=' ] Type [ TypeSpec ] .
 * Type     = identifier .
 */
struct KatovaAST *katova_parse_type_decl(struct TargumLexer *const lexer) {
	struct TargumTokenInfo **token = &lexer->curr_tok;
	const char *lexeme = _get_lexeme(lexer);
	if( strncmp(lexeme, "type", sizeof "type"-1) ) {
		const size_t lexeme_len = targum_token_info_get_len(*token);
		harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "missing 'type' keyword for type declaration, got '%.*s'.", ( int )(lexeme_len), lexeme);
		return _bad_node;
	}
	targum_lexer_advance(lexer, false); /// advance past 'type' keyword.
	lexeme = _get_lexeme(lexer);
	if( (*token)->tag != 2 ) {
		const size_t lexeme_len = targum_token_info_get_len(*token);
		harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "missing name for type declaration, got '%.*s'.", ( int )(lexeme_len), lexeme);
		return _bad_node;
	}
	struct KatovaAST *typedecl = _new_katova_node(KatovaASTTypeDecl);
	typedecl->_.type_decl.name = katova_parse_operand(lexer); /// advances past name.
	lexeme = _get_lexeme(lexer);
	if( lexeme[0]=='=' ) {
		typedecl->_.type_decl.is_alias = true;
		targum_lexer_advance(lexer, false); /// advance past '='.
		lexeme = _get_lexeme(lexer);
	} else if( (*token)->tag != 2 ) {
		const size_t lexeme_len = targum_token_info_get_len(*token);
		harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "missing name for type declaration, got '%.*s'.", ( int )(lexeme_len), lexeme);
		katova_free(&typedecl);
		return _bad_node;
	}
	
	typedecl->_.type_decl.type = katova_parse_operand(lexer); /// advances past type name.
	lexeme = _get_lexeme(lexer);
	if( lexeme[0]=='{' ) {
		typedecl->_.type_decl.spec = katova_parse_type_spec(lexer);
	}
	return typedecl;
}

/** TypeSpec = '{' +FieldList '}' . */
struct KatovaAST *katova_parse_type_spec(struct TargumLexer *const lexer) {
	struct TargumTokenInfo **token = &lexer->curr_tok;
	const char *lexeme = _get_lexeme(lexer);
	if( lexeme[0] != '{' ) {
		const size_t lexeme_len = targum_token_info_get_len(*token);
		harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "expected '{' for type specification but have '%.*s'.", ( int )(lexeme_len), lexeme);
		return _bad_node;
	}
	targum_lexer_advance(lexer, false);
	lexeme = _get_lexeme(lexer);
	
	struct KatovaAST *type_spec = _new_katova_node(KatovaASTTypeSpec);
	type_spec->_.list = harbol_array_make(sizeof(struct KatovaAST*), 4, &( bool ){false});
	while( (*token)->tag != 0 && lexeme[0] != '}' ) {
		struct KatovaAST *stmt = katova_parse_field(lexer);
		if( stmt==_bad_node ) {
			break;
		}
		if( harbol_array_full(&type_spec->_.list) ) {
			harbol_array_grow(&type_spec->_.list, sizeof stmt);
		}
		harbol_array_insert(&type_spec->_.list, &stmt, sizeof stmt);
		lexeme = _get_lexeme(lexer);
	}
	
	if( type_spec->_.list.len==0 ) {
		harbol_array_clear(&type_spec->_.list);
	}
	
	lexeme = _get_lexeme(lexer);
	if( lexeme[0] != '}' ) {
		const int lexeme_len = targum_token_info_get_len(*token);
		harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "missing ending '}' for statement block. Current token: '%.*s'", lexeme_len, lexeme);
		katova_free(&type_spec);
		return _bad_node;
	}
	targum_lexer_advance(lexer, false);
	return type_spec;
}

/** Rule = 'rule' identifier Signature [ Block ] . */
struct KatovaAST *katova_parse_rule(struct TargumLexer *const lexer) {
	struct TargumTokenInfo **token = &lexer->curr_tok;
	const char *lexeme = _get_lexeme(lexer);
	if( strncmp(lexeme, "rule", sizeof "rule"-1) ) {
		const size_t lexeme_len = targum_token_info_get_len(*token);
		harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "missing 'rule' keyword, got '%.*s'.", ( int )(lexeme_len), lexeme);
		return _bad_node;
	}
	
	targum_lexer_advance(lexer, false); /// advance past 'rule' keyword.
	lexeme = _get_lexeme(lexer);
	if( (*token)->tag != 2 ) {
		const size_t lexeme_len = targum_token_info_get_len(*token);
		harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "missing name for rule definition, got '%.*s'.", ( int )(lexeme_len), lexeme);
		return _bad_node;
	}
	struct KatovaAST *rule = _new_katova_node(KatovaASTRule);
	rule->_.rule.name = katova_parse_operand(lexer); /// advances past name.
	rule->_.rule.sig = katova_parse_signature(lexer);
	
	lexeme = _get_lexeme(lexer);
	rule->_.rule.block = ( lexeme[0] == '{' )? katova_parse_block(lexer) : _bad_node;
	return rule;
}

/**
 * FieldDecl    = Field .
 * Field        = IdentList Type .
 * IdentList    = identifier *(',' identifier) .
 */
struct KatovaAST *katova_parse_field(struct TargumLexer *const lexer) {
	struct TargumTokenInfo **token = &lexer->curr_tok;
	struct KatovaAST *field = _new_katova_node(KatovaASTField);
	field->_.field.idens = katova_parse_expr_list(lexer);
	if( (*token)->tag != 2 ) {
		const char *lexeme = _get_lexeme(lexer);
		const size_t lexeme_len = targum_token_info_get_len(*token);
		harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "expected identifier in identifier list typing but have '%.*s'.", ( int )(lexeme_len), lexeme);
		katova_free(&field);
		field = _bad_node;
	}
	field->_.field.type = katova_parse_expr(lexer);
	return field;
}

/**
 * Parameters = '(' [ FieldList ] ')' .
 * FieldList  = FieldDecl *( ',' FieldDecl ) .
 */
struct KatovaAST *katova_parse_params(struct TargumLexer *const lexer) {
	struct TargumTokenInfo **token = &lexer->curr_tok;
	const char *lexeme = _get_lexeme(lexer);
	if( lexeme[0] != '(' ) {
		const size_t lexeme_len = targum_token_info_get_len(*token);
		harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "need '(' for rule signature but have '%.*s'.", ( int )(lexeme_len), lexeme);
		return _bad_node;
	}
	targum_lexer_advance(lexer, false); /// advance past (.
	lexeme = _get_lexeme(lexer);
	struct KatovaAST *fieldlist = _new_katova_node(KatovaASTFieldList);
	fieldlist->_.list = harbol_array_make(sizeof(struct KatovaAST*), 4, &( bool ){false});
	while( (*token)->tag > 0 && lexeme[0] != ')' ) {
		struct KatovaAST *field = katova_parse_field(lexer);
		if( harbol_array_full(&fieldlist->_.list) ) {
			harbol_array_grow(&fieldlist->_.list, sizeof field);
		}
		harbol_array_insert(&fieldlist->_.list, &field, sizeof field);
		lexeme = _get_lexeme(lexer);
		if( lexeme[0]==',' ) {
			targum_lexer_advance(lexer, false);
			lexeme = _get_lexeme(lexer);
		} else if( lexeme[0] != ')' ) {
			const size_t lexeme_len = targum_token_info_get_len(*token);
			harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "missing ',' in param list, got '%.*s'.", ( int )(lexeme_len), lexeme);
			katova_free(&fieldlist);
			return _bad_node;
		}
	}
	lexeme = _get_lexeme(lexer);
	if( lexeme[0] != ')' ) {
		const size_t lexeme_len = targum_token_info_get_len(*token);
		harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "missing ending ')' in param list, got '%.*s'.", ( int )(lexeme_len), lexeme);
		katova_free(&fieldlist);
		return _bad_node;
	}
	targum_lexer_advance(lexer, false); /// advance past ).
	
	if( fieldlist->_.list.len==0 ) {
		harbol_array_clear(&fieldlist->_.list);
	}
	return fieldlist;
}

/** Signature = Parameters [ Result ] . */
struct KatovaAST *katova_parse_signature(struct TargumLexer *const lexer) {
	struct TargumTokenInfo **token = &lexer->curr_tok;
	struct KatovaAST *sig = _new_katova_node(KatovaASTFuncSignature);
	sig->_.func_signature.params = katova_parse_params(lexer);
	
	const char *lexeme = _get_lexeme(lexer);
	if( lexeme[0] != '{' ) {
		if( lexeme[0]=='(' ) {
			targum_lexer_advance(lexer, false);
			sig->_.func_signature.results = katova_parse_expr_list(lexer);
			lexeme = _get_lexeme(lexer);
			if( lexeme[0] != ')' ) {
				const size_t lexeme_len = targum_token_info_get_len(*token);
				harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "missing ending ')' in results list, got '%.*s'.", ( int )(lexeme_len), lexeme);
				katova_free(&sig);
				return _bad_node;
			}
			targum_lexer_advance(lexer, false);
		} else {
			sig->_.func_signature.results = katova_parse_expr(lexer);
		}
	}
	return sig;
}

/** Block = '{' *Statement '}' . */
struct KatovaAST *katova_parse_block(struct TargumLexer *const lexer) {
	struct TargumTokenInfo **token = &lexer->curr_tok;
	const char *lexeme = _get_lexeme(lexer);
	if( lexeme[0] != '{' ) {
		const size_t lexeme_len = targum_token_info_get_len(*token);
		harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "expected '{' for block but have '%.*s'.", ( int )(lexeme_len), lexeme);
		return _bad_node;
	}
	targum_lexer_advance(lexer, false);
	lexeme = _get_lexeme(lexer);
	
	struct KatovaAST *block_stmt = _new_katova_node(KatovaASTBlock);
	block_stmt->_.list = harbol_array_make(sizeof(struct KatovaAST*), 4, &( bool ){false});
	while( (*token)->tag != 0 && lexeme[0] != '}' ) {
		struct KatovaAST *stmt = katova_parse_stmt(lexer);
		if( stmt==_bad_node ) {
			break;
		}
		if( harbol_array_full(&block_stmt->_.list) ) {
			harbol_array_grow(&block_stmt->_.list, sizeof stmt);
		}
		harbol_array_insert(&block_stmt->_.list, &stmt, sizeof stmt);
		lexeme = _get_lexeme(lexer);
	}
	
	if( block_stmt->_.list.len==0 ) {
		harbol_array_clear(&block_stmt->_.list);
	}
	
	lexeme = _get_lexeme(lexer);
	if( lexeme[0] != '}' ) {
		const int lexeme_len = targum_token_info_get_len(*token);
		harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "missing ending '}' for statement block. Current token: '%.*s'", lexeme_len, lexeme);
		katova_free(&block_stmt);
		block_stmt = _bad_node;
		return block_stmt;
	}
	targum_lexer_advance(lexer, false);
	return block_stmt;
}


/// keyword init; cond; post
void katova_parse_init_expr_header(struct TargumLexer *const lexer, struct KatovaAST **const init, struct KatovaAST **const cond, struct KatovaAST **const post) {
	struct TargumTokenInfo **token = &lexer->curr_tok;
	const char *lexeme = _get_lexeme(lexer);
	const int_fast8_t keyword = lexeme[0];
	
	targum_lexer_advance(lexer, false); /// advance past the keyword.
	lexeme = _get_lexeme(lexer);
	if( lexeme[0]=='{' && keyword=='i' ) { /// if
		harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "missing condition in if statement.");
		return;
	}
	
	if( lexeme[0] != ';' ) {
		*init = katova_parse_simple_stmt(lexer, NULL);
	}
	
	lexeme = _get_lexeme(lexer);
	if( lexeme[0] != '{' ) {
		if( lexeme[0]==';' ) {
			targum_lexer_advance(lexer, false);
			lexeme = _get_lexeme(lexer);
		} else if( lexeme[0] != '{' ) {
			harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "expected { in for-loop header.");
		}
		
		if( keyword=='f' ) { /// for keyword.
			if( lexeme[0] != ';' ) {
				if( lexeme[0]=='{' ) {
					harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "expecting for loop condition.");
					return;
				}
				*cond = katova_parse_simple_stmt(lexer, NULL);
			}
			lexeme = _get_lexeme(lexer);
			if( lexeme[0] != ';' ) {
				harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "missing ';' in for loop condition.");
				return;
			}
			targum_lexer_advance(lexer, false); /// advance past semicolon.
			lexeme = _get_lexeme(lexer);
			if( lexeme[0] != '{' ) {
				if( post != NULL ) {
					*post = katova_parse_simple_stmt(lexer, NULL);
					if( *post != _bad_node && (*post)->tag==KatovaASTAssignStmt && (*post)->_.assign.op==':' ) {
						harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "cannot declare in post statement of for loop.");
						return;
					}
				}
			}
		} else if( lexeme[0] != '{' ) {
			*cond = katova_parse_simple_stmt(lexer, NULL);
		}
	} else {
		*cond = *init;
		*init = NULL;
	}
}

/** CaseClause = ExprList Block . */
struct KatovaAST *katova_parse_case_clause(struct TargumLexer *const lexer) {
	struct KatovaAST *case_clause = _new_katova_node(KatovaASTCaseClause);
	case_clause->_.match_case.cases = katova_parse_expr_list(lexer);
	case_clause->_.match_case.block = katova_parse_block(lexer);
	return case_clause;
}

/** MatchStmt = 'match' [ SimpleStmt ';' ] SimpleStmt '{' +MatchCase '}' . */
struct KatovaAST *katova_parse_match_stmt(struct TargumLexer *const lexer) {
	struct TargumTokenInfo **token = &lexer->curr_tok;
	struct KatovaAST *match_stmt = _new_katova_node(KatovaASTMatchStmt);
	katova_parse_init_expr_header(lexer, &match_stmt->_.match.init, &match_stmt->_.match.cond, NULL);
	const char *lexeme = _get_lexeme(lexer);
	if( lexeme[0] != '{' ) {
		harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "missing { for match block.");
		katova_free(&match_stmt);
		match_stmt = _bad_node;
		return match_stmt;
	}
	match_stmt->_.match.body = harbol_array_make(sizeof(struct KatovaAST*), 4, &( bool ){false});
	struct HarbolArray *const match_body = &match_stmt->_.match.body;
	
	targum_lexer_advance(lexer, false); /// advance past {
	lexeme = _get_lexeme(lexer);
	while( (*token)->tag > 0 && lexeme[0] != '}' ) {
		struct KatovaAST *case_clause = katova_parse_case_clause(lexer);
		if( case_clause==_bad_node ) {
			break;
		}
		if( harbol_array_full(match_body) ) {
			harbol_array_grow(match_body, sizeof case_clause);
		}
		harbol_array_insert(match_body, &case_clause, sizeof case_clause);
		lexeme = _get_lexeme(lexer);
	}
	
	lexeme = _get_lexeme(lexer);
	if( lexeme[0] != '}' ) {
		harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "missing ending } for match block.");
		katova_free(&match_stmt);
		match_stmt = _bad_node;
		return match_stmt;
	}
	targum_lexer_advance(lexer, false); /// advance past }
	lexeme = _get_lexeme(lexer);
	
	if( match_body->len==0 ) {
		harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax warning", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "match block is empty.");
		harbol_array_clear(match_body);
	}
	return match_stmt;
}

/**
 * ForStmt      = 'for' [ Condition(SimpleStmt) | ForClause ] Block .
 * ForClause    = [ InitStmt(SimpleStmt) ] ";" [ Condition(Expression) ] ";" [ PostStmt(SimpleStmt) ] .
 */
struct KatovaAST *katova_parse_for_stmt(struct TargumLexer *const lexer) {
	struct KatovaAST *for_stmt = _new_katova_node(KatovaASTForStmt);
	katova_parse_init_expr_header(lexer, &for_stmt->_._for.init, &for_stmt->_._for.cond, &for_stmt->_._for.post);
	for_stmt->_._for.body = katova_parse_block(lexer);
	return for_stmt;
}

/** IfStmt = 'if' [ Init ';' ] Expr Block [ 'else' ( IfStmt | Block ) ] . */
struct KatovaAST *katova_parse_if_stmt(struct TargumLexer *const lexer) {
	struct KatovaAST *if_stmt = _new_katova_node(KatovaASTIfStmt);
	katova_parse_init_expr_header(lexer, &if_stmt->_._if.init, &if_stmt->_._if.cond, NULL);
	if_stmt->_._if.then = katova_parse_block(lexer);
	
	const char *lexeme = _get_lexeme(lexer);
	if( !strncmp(lexeme, "else", sizeof "else"-1) ) {
		targum_lexer_advance(lexer, false);
		lexeme = _get_lexeme(lexer);
		struct KatovaAST **else_ = &if_stmt->_._if._else;
		if( !strncmp(lexeme, "if", sizeof "if"-1) ) {
			*else_ = katova_parse_if_stmt(lexer);
		} else if( lexeme[0]=='{' ) {
			*else_ = katova_parse_block(lexer);
		}
	}
	return if_stmt;
}

/** Statement = Decl | SimpleStmt | IfStmt | ForStmt | MatchStmt | LoopStmt | ReturnStmt . */
struct KatovaAST *katova_parse_stmt(struct TargumLexer *const lexer) {
	struct TargumTokenInfo **token = &lexer->curr_tok;
	const char *lexeme = _get_lexeme(lexer);
	
	/// Golang's parsing typically checks for identifier.
	if( (*token)->tag==2 ) { /// identifier.
		struct KatovaAST *lhs = katova_parse_expr_list(lexer);
		return katova_parse_simple_stmt(lexer, lhs);
	}
	
	/// parse types here.
	
	
	lexeme = _get_lexeme(lexer);
	if( !strncmp(lexeme, "if", sizeof "if"-1) ) {
		return katova_parse_if_stmt(lexer);
	} else if( !strncmp(lexeme, "for", sizeof "for"-1) ) {
		return katova_parse_for_stmt(lexer);
	} else if( !strncmp(lexeme, "stop", sizeof "stop"-1) || !strncmp(lexeme, "pass", sizeof "pass"-1) ) {
		struct KatovaAST *loop_ctrl = _new_katova_node(KatovaASTLoopStmt);
		const size_t lexeme_len = targum_token_info_get_len(*token);
		harbol_string_format(&loop_ctrl->_.str, false, "%.*s", ( int )(lexeme_len), lexeme);
		targum_lexer_advance(lexer, false);
		return loop_ctrl;
	} else if( !strncmp(lexeme, "return", sizeof "return"-1) ) {
		struct KatovaAST *ret_stmt = _new_katova_node(KatovaASTReturnStmt);
		targum_lexer_advance(lexer, false);
		lexeme = _get_lexeme(lexer);
		if( lexeme[0] != ';' ) { /// empty return expression requires semicolon.
			ret_stmt->_.node = katova_parse_expr_list(lexer);
		} else {
			targum_lexer_advance(lexer, false);
		}
		return ret_stmt;
	} else if( !strncmp(lexeme, "match", sizeof "match"-1) ) {
		return katova_parse_match_stmt(lexer);
	} else if( !strncmp(lexeme, "type", sizeof "type"-1) ) {
		return katova_parse_type_decl(lexer);
	} else if( !strncmp(lexeme, "{", sizeof "{"-1) ) {
		return katova_parse_block(lexer);
	} else {
		harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "bad statement.");
		return _bad_node;
	}
}

/**
 * SimpleStmt   = '' | ExprStmt | Assignment | ShortVarDecl .
 * ExprStmt     = Expr .
 * Assignment   = ExprList ['+'] '=' ExprList .
 * ShortVarDecl = IdentList ':=' ExprList .
 */
struct KatovaAST *katova_parse_simple_stmt(struct TargumLexer *const lexer, struct KatovaAST *lhs) {
	const char *lexeme = _get_lexeme(lexer);
	
	if( lhs==NULL ) {
		lhs = katova_parse_expr_list(lexer);
	}
	
	lexeme = _get_lexeme(lexer);
	if( lexeme[0] != '=' && strncmp(lexeme, ":=", sizeof ":="-1) ) {
		if( !strncmp(lexeme, "+=", sizeof "+="-1) ) {
			targum_lexer_advance(lexer, false);
			struct KatovaAST *ast_assign = _new_katova_node(KatovaASTAssignStmt);
			ast_assign->_.assign.lhs = lhs;
			ast_assign->_.assign.op  = '+';
			ast_assign->_.assign.rhs = katova_parse_expr(lexer);
			return ast_assign;
		} else { /// default expr
			struct KatovaAST *expr_stmt = _new_katova_node(KatovaASTExprStmt);
			expr_stmt->_.node = lhs;
			return expr_stmt;
		}
	} else if( !strncmp(lexeme, ":=", sizeof ":="-1) ) {
		targum_lexer_advance(lexer, false);
		struct KatovaAST *ast_assign = _new_katova_node(KatovaASTAssignStmt);
		ast_assign->_.assign.lhs = lhs;
		ast_assign->_.assign.op  = ':';
		ast_assign->_.assign.rhs = katova_parse_expr_list(lexer);
		return ast_assign;
	} else if( lexeme[0]=='=' ) {
		targum_lexer_advance(lexer, false);
		struct KatovaAST *ast_assign = _new_katova_node(KatovaASTAssignStmt);
		ast_assign->_.assign.lhs = lhs;
		ast_assign->_.assign.op  = 0;
		ast_assign->_.assign.rhs = katova_parse_expr_list(lexer);
		return ast_assign;
	}
	return _bad_node;
}

/** ExprList = Expr *(',' Expr) */
struct KatovaAST *katova_parse_expr_list(struct TargumLexer *lexer) {
	struct KatovaAST *expr_list = _new_katova_node(KatovaASTExprList);
	expr_list->_.list = harbol_array_make(sizeof(struct KatovaAST*), 4, &( bool ){false});
	
	struct KatovaAST *expr = katova_parse_expr(lexer);
	if( harbol_array_full(&expr_list->_.list) ) {
		harbol_array_grow(&expr_list->_.list, sizeof expr);
	}
	harbol_array_insert(&expr_list->_.list, &expr, sizeof expr);
	
	const char *lexeme = _get_lexeme(lexer);
	if( lexeme[0]==',' ) {
		while( lexeme[0]==',' ) {
			targum_lexer_advance(lexer, false);
			expr = katova_parse_expr(lexer);
			if( harbol_array_full(&expr_list->_.list) ) {
				harbol_array_grow(&expr_list->_.list, sizeof expr);
			}
			harbol_array_insert(&expr_list->_.list, &expr, sizeof expr);
			lexeme = _get_lexeme(lexer);
		}
	}
	return expr_list;
}

/** Expr = OrExpr . */
struct KatovaAST *katova_parse_expr(struct TargumLexer *const lexer) {
	return katova_parse_or_expr(lexer);
}

/** OrExpr = AndExpr *( '||' AndExpr ) . */
struct KatovaAST *katova_parse_or_expr(struct TargumLexer *const lexer) {
	struct KatovaAST *and_expr = katova_parse_and_expr(lexer);
	const char *lexeme = _get_lexeme(lexer);
	while( !strncmp(lexeme, "||", sizeof "||"-1) ) {
		struct KatovaAST *logic_expr = _new_katova_node(KatovaASTBinaryExpr);
		logic_expr->_.binary_expr.l  = and_expr;
		logic_expr->_.binary_expr.op = lexeme[0];
		targum_lexer_advance(lexer, false);
		lexeme = _get_lexeme(lexer);
		logic_expr->_.binary_expr.r = katova_parse_and_expr(lexer);
		and_expr = logic_expr;
	}
	return and_expr;
}

/** AndExpr = EqualityExpr *( '&&' EqualityExpr ) . */
struct KatovaAST *katova_parse_and_expr(struct TargumLexer *const lexer) {
	struct KatovaAST *equality_expr = katova_parse_equality_expr(lexer);
	const char *lexeme = _get_lexeme(lexer);
	while( !strncmp(lexeme, "&&", sizeof "&&"-1) ) {
		struct KatovaAST *logic_expr = _new_katova_node(KatovaASTBinaryExpr);
		logic_expr->_.binary_expr.l  = equality_expr;
		logic_expr->_.binary_expr.op = lexeme[0];
		targum_lexer_advance(lexer, false);
		lexeme = _get_lexeme(lexer);
		logic_expr->_.binary_expr.r = katova_parse_equality_expr(lexer);
		equality_expr = logic_expr;
	}
	return equality_expr;
}

/** EqualityExpr = PrimaryExpr *( ( '=='| '!=' ) PrimaryExpr ) . */
struct KatovaAST *katova_parse_equality_expr(struct TargumLexer *const lexer) {
	struct KatovaAST *primary = katova_parse_primary_expr(lexer);
	const char *lexeme = _get_lexeme(lexer);
	while( !strncmp(lexeme, "==", sizeof "=="-1) || !strncmp(lexeme, "!=", sizeof "!="-1) ) {
		struct KatovaAST *logic_expr = _new_katova_node(KatovaASTBinaryExpr);
		logic_expr->_.binary_expr.l  = primary;
		logic_expr->_.binary_expr.op = lexeme[0];
		targum_lexer_advance(lexer, false);
		lexeme = _get_lexeme(lexer);
		logic_expr->_.binary_expr.r = katova_parse_primary_expr(lexer);
		primary = logic_expr;
	}
	return primary;
}

/** PrimaryExpr = Operand *( '.' identifier | '[' Expr ']' | '(' [ ExprList ] ')' ) . */
struct KatovaAST *katova_parse_primary_expr(struct TargumLexer *const lexer) {
	struct KatovaAST *operand = katova_parse_operand(lexer);
	struct TargumTokenInfo **token = &lexer->curr_tok;
	const char *lexeme = _get_lexeme(lexer);
	while( lexeme[0]=='[' || lexeme[0]=='(' ) {
		if( lexeme[0]=='[' ) { /// array index.
			struct KatovaAST *use_array = _new_katova_node(KatovaASTArrayAccess);
			use_array->_.array_access.obj = operand;
			targum_lexer_advance(lexer, false);
			use_array->_.array_access.expr = katova_parse_expr(lexer);
			
			lexeme = _get_lexeme(lexer);
			if( lexeme[0] != ']' ) {
				harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "expected closing ] bracket for array index.");
				katova_free(&use_array);
				use_array = _bad_node;
			}
			
			targum_lexer_advance(lexer, false);
			lexeme = _get_lexeme(lexer);
			if( use_array != NULL ) {
				operand = use_array;
			}
		} else if( lexeme[0]=='(' ) { /// func call.
			targum_lexer_advance(lexer, false);
			struct KatovaAST *func_call = _new_katova_node(KatovaASTCall);
			func_call->_.call.caller = operand;
			lexeme = _get_lexeme(lexer);
			if( lexeme[0] != ')' && (*token)->tag > 0 ) {
				func_call->_.call.args = katova_parse_expr_list(lexer);
			}
			
			lexeme = _get_lexeme(lexer);
			if( lexeme[0] != ')' ) {
				const size_t lexeme_len = targum_token_info_get_len(*token);
				harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "syntax error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "missing ')', got '%.*s'.", ( int )(lexeme_len), lexeme);
				katova_free(&func_call);
				func_call = _bad_node;
			}
			targum_lexer_advance(lexer, false);
			lexeme = _get_lexeme(lexer);
			if( func_call != NULL ) {
				operand = func_call;
			}
		}
	}
	return operand;
}

/**
 * Operand = int | rune | string | identifier | '(' Expr ')' .
 */
struct KatovaAST *katova_parse_operand(struct TargumLexer *const restrict lexer) {
	struct TargumTokenInfo **token = &lexer->curr_tok;
	size_t lexeme_len = targum_token_info_get_len(*token);
	const char  *lexeme = targum_lexer_get_lexeme(lexer, *token);
	
	size_t choice = 5;
	const char *keys[] = {
		"identifier",
		"integer",
		"string",
		"rune",
	};
	for( size_t i=0; i < (1[&keys] - &keys[0]); i++ ) {
		const struct HarbolMap *const token_section = harbol_cfg_get_section(lexer->cfg, "tokens");
		const intmax_t *const int_value = harbol_cfg_get_int(token_section, keys[i]);
		if( int_value==NULL ) {
			continue;
		} else if( *int_value==( intmax_t )((*token)->tag) ) {
			choice = i;
			break;
		}
	}
	switch( choice ) {
		case 0: { /// 'identifier': IOTA
			struct KatovaAST *const iden_node = _new_katova_node(KatovaASTIdent);
			harbol_string_format(&iden_node->_.str, false, "%.*s", ( int )(lexeme_len), lexeme);
			targum_lexer_advance(lexer, false);
			return iden_node;
		}
		case 1: { /// 'integer': IOTA
			struct KatovaAST *const int_node = _new_katova_node(KatovaASTIntLiteral);
			harbol_string_format(&int_node->_.str, false, "%.*s", ( int )(lexeme_len), lexeme);
			targum_lexer_advance(lexer, false);
			return int_node;
		}
		case 2: case 3: { /// 'string', 'rune': IOTA
			struct KatovaAST *const str_node = _new_katova_node(KatovaASTStrLiteral);
			harbol_string_format(&str_node->_.str, false, "%.*s", ( int )(lexeme_len), lexeme);
			targum_lexer_advance(lexer, false);
			return str_node;
		}
		default: {
			if( lexeme[0]=='(' ) {
				targum_lexer_advance(lexer, false);
				struct KatovaAST *expr = katova_parse_expr(lexer);
				lexeme = _get_lexeme(lexer);
				if( lexeme[0] != ')' ) {
					harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "Missing right parentheses ')', returning NULL expr.");
					katova_free(&expr);
					expr = _bad_node;
				} else {
					targum_lexer_advance(lexer, false);
				}
				return expr;
			}
			//lexeme_len = targum_token_info_get_len(*token);
			//harbol_err_msg(NULL, targum_lexer_get_filename(lexer), "error", &( size_t ){(*token)->line}, &( size_t ){(*token)->col}, "Bad operand: got '%.*s'", ( int )(lexeme_len), _get_lexeme(lexer));
			return _bad_node;
		}
	}
}


struct KatovaAST *_new_katova_node(const enum KatovaASTType tag) {
	struct KatovaAST *const n = calloc(1, sizeof *n);
	assert( n != NULL && "bad KatovaAST." );
	n->tag = tag;
	return n;
}

TARGUM_API void katova_free(struct KatovaAST **const n) {
	if( *n==NULL ) {
		return;
	}
	switch( (*n)->tag ) {
		case KatovaASTIdent:
		case KatovaASTIntLiteral:
		case KatovaASTStrLiteral:
		case KatovaASTLoopStmt:
			harbol_string_clear(&(*n)->_.str);
			break;
		case KatovaASTArrayAccess:
			katova_free(&(*n)->_.array_access.obj);
			katova_free(&(*n)->_.array_access.expr);
			break;
		case KatovaASTCall:
			katova_free(&(*n)->_.call.caller);
			katova_free(&(*n)->_.call.args);
			break;
		case KatovaASTBinaryExpr:
			katova_free(&(*n)->_.binary_expr.l);
			katova_free(&(*n)->_.binary_expr.r);
			break;
		case KatovaASTAssignStmt:
			katova_free(&(*n)->_.assign.lhs);
			katova_free(&(*n)->_.assign.rhs);
			break;
		case KatovaASTExprList:
		case KatovaASTBlock:
		case KatovaASTFieldList:
		case KatovaASTTypeSpec:
			for( size_t i=0; i < (*n)->_.list.len; i++ ) {
				struct KatovaAST **x = harbol_array_get(&(*n)->_.list, i, sizeof *x);
				katova_free(x);
			}
			harbol_array_clear(&(*n)->_.list);
			break;
		case KatovaASTExprStmt:
		case KatovaASTReturnStmt:
			katova_free(&(*n)->_.node);
			break;
		case KatovaASTIfStmt:
			katova_free(&(*n)->_._if.init);
			katova_free(&(*n)->_._if.cond);
			katova_free(&(*n)->_._if.then);
			katova_free(&(*n)->_._if._else);
			break;
		case KatovaASTForStmt:
			katova_free(&(*n)->_._for.init);
			katova_free(&(*n)->_._for.cond);
			katova_free(&(*n)->_._for.post);
			katova_free(&(*n)->_._for.body);
			break;
		case KatovaASTMatchStmt:
			katova_free(&(*n)->_.match.init);
			katova_free(&(*n)->_.match.cond);
			for( size_t i=0; i < (*n)->_.match.body.len; i++ ) {
				struct KatovaAST **x = harbol_array_get(&(*n)->_.match.body, i, sizeof *x);
				katova_free(x);
			}
			harbol_array_clear(&(*n)->_.match.body);
			break;
		case KatovaASTCaseClause:
			katova_free(&(*n)->_.match_case.cases);
			katova_free(&(*n)->_.match_case.block);
			break;
		case KatovaASTFuncSignature:
			katova_free(&(*n)->_.func_signature.params);
			katova_free(&(*n)->_.func_signature.results);
			break;
		case KatovaASTField:
			katova_free(&(*n)->_.field.idens);
			katova_free(&(*n)->_.field.type);
			break;
		case KatovaASTRule:
			katova_free(&(*n)->_.rule.name);
			katova_free(&(*n)->_.rule.sig);
			katova_free(&(*n)->_.rule.block);
			break;
		case KatovaASTTypeDecl:
			katova_free(&(*n)->_.type_decl.name);
			katova_free(&(*n)->_.type_decl.spec);
			katova_free(&(*n)->_.type_decl.type);
			break;
		case KatovaASTGrammar:
			for( size_t i=0; i < (*n)->_.grammar.types.len; i++ ) {
				struct KatovaAST **x = harbol_array_get(&(*n)->_.grammar.types, i, sizeof *x);
				katova_free(x);
			}
			harbol_array_clear(&(*n)->_.grammar.types);
			
			for( size_t i=0; i < (*n)->_.grammar.rules.len; i++ ) {
				struct KatovaAST **x = harbol_array_get(&(*n)->_.grammar.rules, i, sizeof *x);
				katova_free(x);
			}
			harbol_array_clear(&(*n)->_.grammar.rules);
			break;
		case KatovaASTInvalid:
		default:
			break;
	}
	if( (*n)->tag != KatovaASTInvalid ) {
		free(*n);
		*n = NULL;
	}
}

static void _print_tabs(const size_t tabs, FILE *const stream) {
	for( size_t i=0; i < tabs; i++ ) {
		fprintf(stream, "  ");
	}
}

TARGUM_API void katova_print(const struct KatovaAST *const ast, const size_t tabs, FILE *const stream) {
	if( ast==NULL ) {
		return;
	}
	_print_tabs(tabs, stream);
	switch( ast->tag ) {
		case KatovaASTIdent:
			fprintf(stream, "Katova Identifier:: '%s'\n", ast->_.str.cstr);
			break;
		case KatovaASTIntLiteral:
			fprintf(stream, "Katova Integer:: '%s'\n", ast->_.str.cstr);
			break;
		case KatovaASTStrLiteral:
			fprintf(stream, "Katova String:: '%s'\n", ast->_.str.cstr);
			break;
		case KatovaASTArrayAccess:
			fprintf(stream, "Katova Array Index::\n");
			katova_print(ast->_.array_access.obj, tabs + 1, stream);
			katova_print(ast->_.array_access.expr, tabs + 1, stream);
			break;
		case KatovaASTCall:
			fprintf(stream, "Katova Func Call::\n");
			katova_print(ast->_.call.caller, tabs + 1, stream);
			katova_print(ast->_.call.args, tabs + 1, stream);
			break;
		case KatovaASTBinaryExpr: {
			const char *oper = NULL;
			switch( ast->_.binary_expr.op ) {
				case '&': oper = "&&"; break;
				case '|': oper = "||"; break;
				case '=': oper = "=="; break;
				case '!': oper = "!="; break;
			}
			fprintf(stream, "Katova Binary Expression:: '%s'\n", oper);
			katova_print(ast->_.binary_expr.l, tabs + 1, stream);
			katova_print(ast->_.binary_expr.r, tabs + 1, stream);
			break;
		}
		case KatovaASTAssignStmt: {
			const char *oper = NULL;
			switch( ast->_.assign.op ) {
				case '+': oper = "+="; break;
				case ':': oper = ":="; break;
				case 0:   oper = "=";  break;
			}
			fprintf(stream, "Katova Assign Stmt:: lhs\n");
			katova_print(ast->_.assign.lhs, tabs + 1, stream);
			_print_tabs(tabs, stream); fprintf(stream, "Katova Assign Stmt:: '%s'\n", oper);
			_print_tabs(tabs, stream); fprintf(stream, "Katova Assign Stmt:: rhs list\n");
			katova_print(ast->_.assign.rhs, tabs + 1, stream);
			break;
		}
		case KatovaASTExprList:
			fprintf(stream, "Katova Expr List::\n");
			for( size_t i=0; i < ast->_.list.len; i++ ) {
				const struct KatovaAST **x = harbol_array_get(&ast->_.list, i, sizeof *x);
				katova_print(*x, tabs + 1, stream);
			}
			break;
		case KatovaASTExprStmt:
			fprintf(stream, "Katova Expr Stmt::\n");
			katova_print(ast->_.node, tabs + 1, stream);
			break;
		case KatovaASTReturnStmt:
			fprintf(stream, "Katova Return Stmt::\n");
			katova_print(ast->_.node, tabs + 1, stream);
			break;
		case KatovaASTIfStmt:
			fprintf(stream, "Katova If Stmt:: Init\n");
			katova_print(ast->_._if.init, tabs + 1, stream);
			_print_tabs(tabs, stream); fprintf(stream, "Katova If Stmt:: Cond\n");
			katova_print(ast->_._if.cond, tabs + 1, stream);
			_print_tabs(tabs, stream); fprintf(stream, "Katova If Stmt:: Block\n");
			katova_print(ast->_._if.then, tabs + 1, stream);
			if( ast->_._if._else != NULL ) {
				_print_tabs(tabs, stream);
				fprintf(stream, "Katova If Stmt:: Else\n");
				katova_print(ast->_._if._else, tabs + 1, stream);
			}
			break;
		case KatovaASTBlock:
			fprintf(stream, "Katova Block::\n");
			for( size_t i=0; i < ast->_.list.len; i++ ) {
				const struct KatovaAST **x = harbol_array_get(&ast->_.list, i, sizeof *x);
				katova_print(*x, tabs + 1, stream);
			}
			break;
		case KatovaASTForStmt:
			fprintf(stream, "Katova For Stmt:: Init\n");
			katova_print(ast->_._for.init, tabs + 1, stream);
			_print_tabs(tabs, stream); fprintf(stream, "Katova For Stmt:: Cond\n");
			katova_print(ast->_._for.cond, tabs + 1, stream);
			_print_tabs(tabs, stream); fprintf(stream, "Katova For Stmt:: Post\n");
			katova_print(ast->_._for.post, tabs + 1, stream);
			_print_tabs(tabs, stream); fprintf(stream, "Katova For Stmt:: Body\n");
			katova_print(ast->_._for.body, tabs + 1, stream);
			break;
		case KatovaASTLoopStmt:
			fprintf(stream, "Katova Loop Stmt:: '%s'\n", ast->_.str.cstr);
			break;
		case KatovaASTMatchStmt:
			fprintf(stream, "Katova Match Stmt:: Init\n");
			katova_print(ast->_.match.init, tabs + 1, stream);
			_print_tabs(tabs, stream); fprintf(stream, "Katova Match Stmt:: Cond\n");
			katova_print(ast->_.match.cond, tabs + 1, stream);
			_print_tabs(tabs, stream); fprintf(stream, "Katova Match Stmt:: Body\n");
			for( size_t i=0; i < ast->_.match.body.len; i++ ) {
				const struct KatovaAST **x = harbol_array_get(&ast->_.match.body, i, sizeof *x);
				katova_print(*x, tabs + 1, stream);
			}
			break;
		case KatovaASTCaseClause:
			fprintf(stream, "Katova Case Clauses:: Cases\n");
			katova_print(ast->_.match_case.cases, tabs + 1, stream);
			_print_tabs(tabs, stream); fprintf(stream, "Katova Case Clauses:: Blocks\n");
			katova_print(ast->_.match_case.block, tabs + 1, stream);
			break;
		case KatovaASTFuncSignature:
			fprintf(stream, "Katova Func Signature:: Params\n");
			katova_print(ast->_.func_signature.params, tabs + 1, stream);
			_print_tabs(tabs, stream); fprintf(stream, "Katova Func Signature:: Results\n");
			katova_print(ast->_.func_signature.results, tabs + 1, stream);
			break;
		case KatovaASTFieldList:
			fprintf(stream, "Katova Field List::\n");
			for( size_t i=0; i < ast->_.list.len; i++ ) {
				const struct KatovaAST **x = harbol_array_get(&ast->_.list, i, sizeof *x);
				katova_print(*x, tabs + 1, stream);
			}
			break;
		case KatovaASTField:
			fprintf(stream, "Katova Field:: Idens\n");
			katova_print(ast->_.field.idens, tabs + 1, stream);
			_print_tabs(tabs, stream); fprintf(stream, "Katova Field:: Type\n");
			katova_print(ast->_.field.type, tabs + 1, stream);
			break;
		case KatovaASTRule:
			fprintf(stream, "Katova Rule:: Name\n");
			katova_print(ast->_.rule.name, tabs + 1, stream);
			_print_tabs(tabs, stream); fprintf(stream, "Katova Rule:: Signature\n");
			katova_print(ast->_.rule.sig, tabs + 1, stream);
			_print_tabs(tabs, stream); fprintf(stream, "Katova Rule:: Body\n");
			katova_print(ast->_.rule.block, tabs + 1, stream);
			break;
		case KatovaASTTypeDecl:
			fprintf(stream, "Katova Type Decl:: Name\n");
			katova_print(ast->_.type_decl.name, tabs + 1, stream);
			_print_tabs(tabs, stream); fprintf(stream, "Katova Type Decl:: Type Name\n");
			katova_print(ast->_.type_decl.type, tabs + 1, stream);
			_print_tabs(tabs, stream); fprintf(stream, "Katova Rule:: Is Alias? '%s'\n", ast->_.type_decl.is_alias? "yes" : "no");
			_print_tabs(tabs, stream); fprintf(stream, "Katova Type Decl:: Type Spec\n");
			katova_print(ast->_.type_decl.spec, tabs + 1, stream);
			break;
		case KatovaASTTypeSpec:
			fprintf(stream, "Katova Type Spec::\n");
			for( size_t i=0; i < ast->_.list.len; i++ ) {
				const struct KatovaAST **x = harbol_array_get(&ast->_.list, i, sizeof *x);
				katova_print(*x, tabs + 1, stream);
			}
			break;
		case KatovaASTGrammar:
			fprintf(stream, "Katova Grammar:: Type Decls\n");
			for( size_t i=0; i < ast->_.grammar.types.len; i++ ) {
				const struct KatovaAST **x = harbol_array_get(&ast->_.grammar.types, i, sizeof *x);
				katova_print(*x, tabs + 1, stream);
			}
			_print_tabs(tabs, stream); fprintf(stream, "Katova Grammar:: Rules\n");
			for( size_t i=0; i < ast->_.grammar.rules.len; i++ ) {
				const struct KatovaAST **x = harbol_array_get(&ast->_.grammar.rules, i, sizeof *x);
				katova_print(*x, tabs + 1, stream);
			}
			break;
		case KatovaASTInvalid:
		default:
			break;
	}
}

TARGUM_API struct KatovaAST *katova_parse(struct TargumLexer *const lexer) {
	targum_lexer_get_token(lexer);
	return katova_parse_grammar(lexer);
}