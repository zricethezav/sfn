EXEC     = bin/sfn
CC       = clang
CFLAGS   = -Wall -Iinclude -Ilib/oniguruma/src
LDFLAGS  = lib/oniguruma/src/.libs/libonig.a

SRC      = $(wildcard src/*.c)
OBJ      = $(SRC:.c=.o)
TEST_SRC = $(wildcard tests/*.c)
TEST_OBJ = $(TEST_SRC:.c=.o)
TEST_EXEC = bin/test_gitleaks

ONIGURUMA_DIR = lib/oniguruma
ONIGURUMA_LIB = $(ONIGURUMA_DIR)/src/.libs/libonig.a


all: $(ONIGURUMA_LIB) $(EXEC)


$(EXEC): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(EXEC)_nosanitize: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS_NOSANITIZE)

$(TEST_EXEC): $(TEST_OBJ) $(filter-out src/main.o, $(OBJ))
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

$(ONIGURUMA_DIR)/configure:
	cd $(ONIGURUMA_DIR) && ./autogen.sh

$(ONIGURUMA_LIB): $(ONIGURUMA_DIR)/configure
	cd $(ONIGURUMA_DIR) && ./configure --disable-shared && make


.PHONY: clean test memtest memtest_nosanitize

clean:
	@rm -rf src/*.o tests/*.o $(EXEC) $(TEST_EXEC) $(EXEC)_nosanitize

test: $(TEST_EXEC)
	@./$(TEST_EXEC)

memtest: $(EXEC)
	@leaks --atExit -- ./$(EXEC) directory out.txt

memtest_nosanitize: $(EXEC)_nosanitize
	@leaks --atExit -- ./$(EXEC)_nosanitize directory out.txt
