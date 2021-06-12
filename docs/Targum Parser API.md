# C interface

# Datatypes

## struct TargumParser

```c
struct TargumParser {
	struct HarbolMap      token_lits;
	struct LexerIFace { 
		LexerStartUpFunc *startup_fn;
		LexerShutDwnFunc *shutdown_fn;
		TokenFunc        *tok_fn;
		LexemeFunc       *lexeme_fn;
		ConsumeFunc      *consume_fn;
		void             *userdata;
	} lexer_iface;
	const char           *filename, *cfg_file;
	struct HarbolMap     *cfg;
	bool                  warns : 1;
};
```

### token_lits
hash table that stores the literal value (integers, floats, strings) that are crucial to the lexer interface and the grammar config file.

### lexer_iface
interface object of pointers that are used during parsing to communicate between the lexer and Targum Parser.

### lexer_iface.startup_fn
virtual function for when the parser is about to start parsing and needs the lexer to startup/initialize.
signature is `bool (*)(void *userdata, const char filename[]);`

### lexer_iface.shutdown_fn
virtual function for when the parser finished parsing and lexer can shutdown/deinitialize.
signature is `bool (*)(void *userdata, const char filename[]);`

### lexer_iface.tok_fn
virtual function that gets the unsigned integer value representing the current token given by the lexer.
signature is `uint32_t (*)(void *userdata, size_t lookahead, size_t *line, size_t *col);`

### lexer_iface.lexeme_fn
virtual function that gets the C string lexeme of the current token given by the lexer.
signature is `const char *(*)(void *userdata, size_t lookahead, size_t *line, size_t *col);`

### lexer_iface.consume_fn
virtual function that's invoked to tell the lexer whether the parser has consumed a token or not.
signature is `void (*)(void *userdata, size_t lookahead, bool consumed);`
never invoked when an error occurs.

### lexer_iface.userdata
pointer that holds specific userdata that's given to the virtual lexer interface functions.

### filename
C string of the current filename the parser is parsing.

### cfg_file
C string of the filename of the config file used by the parser to determine grammar.

### cfg
hash table structure of the configurable grammar file.

### warns
bool whether certain warnings are enabled or not.


## struct TargumCST
"Concrete Syntax Tree" aka Parse Tree structure.
stored into `struct HarbolTree*`.

```c
struct TargumCST {
	char  *parsed;
	size_t len, tag;
};
```

### parsed
C string of the token that was parsed.

### len
size length of `parsed`.

### tag
tag representing the type of node.
value of `SIZE_MAX` is that it's a node and the token is the parse rule.
value that isn't `SIZE_MAX` is a lexer token node.


# Functions/Methods


## targum_parser_make
```c
struct TargumParser targum_parser_make(
	bool        startup_func(void *userdata, const char filename[]),
	bool        shutdown_fn(void *userdata, const char filename[]),
	uint32_t    token_func(void *userdata, size_t lookahead, size_t *line, size_t *col),
	const char *lexeme_func(void *userdata, size_t lookahead, size_t *line, size_t *col),
	void        consume_func(void *userdata, size_t lookahead, bool consumed),
	void       *userdata,
	const char  filename[],
	struct HarbolMap *cfg
);
```

### Description
Creates and initializes a parser object.

### Parameters
* `startup_func` - function that's invoked when the parser initializes the lexer.
* `shutdown_fn` - function that's invoked when the parser finishes parsing and deinitializes the lexer.
* `token_func` - function that returns an unsigned integer representing a token.
* `lexeme_func` - function that returns a C string representing a token lexeme.
* `consume_func` - function that's invoked when a token can be consumed by the parser.
* `userdata` - userdata passed to all the above functions.
* `filename` - name of the file we're parsing.
* `cfg` - hash table representing the grammar config file, can be NULL if sharing the same grammar config file(s).

### Return Value
parser object.


## targum_parser_init
```c
bool targum_parser_init(struct TargumParser *parser);
```

### Description
Starts up the parser and the lexer interface by invoking the startup virtual function.

### Parameters
* `parser` - ptr to parser object.

### Return Value
true if successful, false if no startup virtual function was given, virtual function returned false itself, or failed to initialize crucial parser data.


## targum_parser_clear
```c
void targum_parser_clear(struct TargumParser *parser, bool free_config);
```

### Description
clears out and deallocates the parser object's internal data.

### Parameters
* `parser` - ptr to parser object.
* `free_config` - bool to free the config file hash table structure stored in the parser object.

### Return Value
None.


## targum_parser_define_token
```c
bool targum_parser_define_token(struct TargumParser *parser, const char token_name[], uint32_t tok_value);
```

### Description
Allows a developer to define the value of the "literal" tokens (e.g. integers, floats, string literals, etc.) with a name to be accessible from the grammar config file.

### Parameters
* `parser` - ptr to parser object.
* `token_name` - name to be used in the grammar config file.
* `tok_value` - value of the token.

### Return Value
true if successful, false if otherwise.

### Example
```c
/// source code.
enum MyTokenValue {
	IntVal = 239,
	...
};

int main() {
	...;
	struct TargumParser parser = ...;
	targum_parser_define_token(&parser, "INT_VAL", IntVal);
}
```

```md
/// grammar config.
'grammar': {
	...
	'integer': '{INT_VAL}'
}
```


## targum_parser_load_cfg_file
```c
bool targum_parser_load_cfg_file(struct TargumParser *parser, const char cfg_file[]);
```

### Description
loads a grammar config file.

### Parameters
* `parser` - ptr to parser object.
* `cfg_file` - name of the file.

### Return Value
true if loading was successful, false otherwise.


## targum_parser_load_cfg_cstr
```c
bool targum_parser_load_cfg_cstr(struct TargumParser *parser, const char cfg_cstr[]);
```

### Description
parses a C string as a grammar config "file".

### Parameters
* `parser` - ptr to parser object.
* `cfg_cstr` - config file as a string.

### Return Value
true if loading was successful, false otherwise.


## targum_parser_get_cfg
```c
struct HarbolMap *targum_parser_get_cfg(const struct TargumParser *parser);
```

### Description
retrieves the config file as a hash table structure.
necessary to help with sharing the same hash table structure with other parser instances.

### Parameters
* `parser` - const ptr to parser object.

### Return Value
hash table pointer, NULL if no config file was loaded or config string parsed.


## targum_parser_get_cfg_filename
```c
const char *targum_parser_get_cfg_filename(const struct TargumParser *parser);
```

### Description
retrieves the C string filename.

### Parameters
* `parser` - const ptr to parser object.

### Return Value
C string of the grammar config filename.


## targum_parser_run
```c
struct HarbolTree *targum_parser_run(struct TargumParser *parser);
```

### Description
Starts the parser to parse the current file, using its grammar config to generate a grammar system, run the system, creating a parse tree of the current file until an error occurs or parsing was successful.

### Parameters
* `parser` - ptr to parser object.

### Return Value
tree structure storing `struct TargumCST*`


## targum_parser_clear_cst
```c
void targum_parser_clear_cst(struct HarbolTree *cst);
```

### Description
clears out the data for the tree structure holding the parse tree given by the Targum Parser system.

### Parameters
* `cst` - ptr to tree object.

### Return Value
None.


## targum_parser_free_cst
```c
void targum_parser_free_cst(struct HarbolTree **cst_ref);
```

### Description
clears out the data for the tree structure holding the parse tree given by the Targum Parser system, frees the pointer of the reference, and sets the reference to NULL.

### Parameters
* `cst_ref` - ptr to tree structure pointer.

### Return Value
None.

### Example
```c
struct TargumParser parser = ...;
struct HarbolTree *parse_tree = targum_parser_run(&parser);
...;
targum_parser_free_cst(&parse_tree);
```