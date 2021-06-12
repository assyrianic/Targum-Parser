# Targum Parser

## Introduction
Part of the Targum Compiler Frontend Suite, the Targum Parser is an string-configured, PEG interpretd parser.


### Features

* Using a config file, define your language grammar with powerful PEG features as quickly as needed!
* Produces a Parse Tree (Concrete Syntax Tree) that can be trimmed as needed into an Abstract Syntax Tree.

### TODO
[ ] - allow for left-associativity without uncontrollable left recursion.

## Usage

```c
#include "targum_parser.h"

static bool startup_lexer(void *userdata, const char filename[]) {
	return my_lexer_init(userdata, filename);
}
static bool shutdown_lexer(void *userdata, const char filename[]) {
	my_lexer_free(userdata, filename);
	return true;
}

static uint32_t lexer_token(void *userdata, size_t lookahead, size_t *line, size_t *col) {
	return my_lexer_get_token(userdata);
}

static const char *lexer_cstr(void *userdata, size_t lookahead, size_t *line, size_t *col) {
	return my_lexer_get_lexeme(userdata);
}

static void lexer_consume(void *userdata, size_t lookahead, bool consumed) {
	if( consumed ) {
		advance_my_lexer(userdata);
	}
}

int main(const int argc, char *argv[static 1])
{
	struct MyLexer lexer = {0};
	struct TargumParser parser = targum_parser_make(startup_lexer, shutdown_lexer, lexer_token, lexer_cstr, lexer_consume, &lexer, "example.txt", NULL);
	
	if( !targum_parser_init(&parser) ) {
		puts("failed to initialize targum parser.");
		return 1;
	} else if( !targum_parser_load_cfg_file(&parser, "./grammar.cfg") ) {
		puts("failed to load grammar config.");
		return 1;
	}
	
	targum_parser_define_token(&parser, "integer", MyLexerIntVal);
	targum_parser_define_token(&parser, "float", MyLexerFltVal);
	targum_parser_define_token(&parser, "string", MyLexerStrVal);
	targum_parser_define_token(&parser, "char", MyLexerCharVal);
	targum_parser_define_token(&parser, "identifier", MyLexerIdentVal);
	
	struct HarbolTree *cst = targum_parser_run(&parser);
	struct MyAST *ast = generate_ast_from_cst(cst);
	targum_parser_free_cst(&cst);
	...; ast = NULL;
	targum_parser_clear(&parser, true);
}
```

## Contributing

To submit a patch, first file an issue and/or present a pull request.

## Help

If you need help or have any question, make an issue on the github repository.
Simply drop a message or your question and you'll be reached in no time!

## Installation

### Requirements

C99 compliant compiler and libc implementation with stdlib.h, stdio.h, and stddef.h.

### Installation

To build the library, simply run `make` which will make the static library version of libtargum_lexer.

To clean up the `.o` files, run `make clean`.

To build a debug version of the library, run `make debug`.

### Testing

For testing code changes or additions, simply run `make test` with `test_driver.c` in the directory which will build an executable called `test_driver`.


## Credits

* Kevin Yonan - Lead Developer of the Targum Compiler Frontend Suite.


## License

This project is licensed under Apache License.
