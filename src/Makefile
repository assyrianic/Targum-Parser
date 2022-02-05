#CC = clang-6.0
CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c99 -flto -s -O2
TFLAGS = -Wall -Wextra -pedantic -std=c99 -flto -g -O2
# -fsanitize=undefined -fsplit-stack -flto

LIB_NAME = targum_parser
DEPS = -ldl

SRCS  = str/str.c
SRCS += array/array.c
SRCS += map/map.c
SRCS += variant/variant.c
SRCS += cfg/cfg.c
SRCS += lex/lex.c
SRCS += msg_sys/msg_sys.c
SRCS += tree/tree.c
SRCS += targum_parser.c

OBJS = $(SRCS:.c=.o)

targum_static:
	+$(MAKE) -C str
	+$(MAKE) -C array
	+$(MAKE) -C map
	+$(MAKE) -C variant
	+$(MAKE) -C cfg
	+$(MAKE) -C lex
	+$(MAKE) -C msg_sys
	+$(MAKE) -C tree
	$(CC) $(CFLAGS) -c $(SRCS)
	gcc-ar rcs lib$(LIB_NAME).a $(OBJS)

debug:
	+$(MAKE) -C str debug
	+$(MAKE) -C array debug
	+$(MAKE) -C map debug
	+$(MAKE) -C variant debug
	+$(MAKE) -C cfg debug
	+$(MAKE) -C lex debug
	+$(MAKE) -C msg_sys debug
	+$(MAKE) -C tree debug
	$(CC) $(TFLAGS) -c $(SRCS)
	gcc-ar rcs lib$(LIB_NAME).a $(OBJS)

test:
	$(CC) $(TFLAGS) test_driver.c -L. -l$(LIB_NAME) -o test_driver -ldl -Wl,--export-dynamic
test_targum:
	$(CC) $(TFLAGS) test_driver.c -L. -ltargum_lexer -l$(LIB_NAME) -o test_driver -ldl -Wl,--export-dynamic

clean:
	+$(MAKE) -C str clean
	+$(MAKE) -C array clean
	+$(MAKE) -C map clean
	+$(MAKE) -C variant clean
	+$(MAKE) -C cfg clean
	+$(MAKE) -C lex clean
	+$(MAKE) -C msg_sys clean
	+$(MAKE) -C tree clean
	$(RM) *.o

remove:
	$(RM) libtargum_parser.a
	$(RM) test_driver
