CC ?= gcc
CFLAGS ?= -O1 -Wall
BIN := bin
PROGS := cpu_hog mem_leak fork_bomb zombie thread_explosion ctx_switch

all: $(addprefix $(BIN)/,$(PROGS))

$(BIN)/%: %.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $< -lpthread

$(BIN):
	mkdir -p $(BIN)

clean:
	rm -rf $(BIN)

.PHONY: all clean
