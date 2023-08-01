# This Makefile is provided as an example of
# statically linking DOCA and DPDK/mlx5.

DOCA_APP_COMMON=/opt/mellanox/doca/applications/common/src

SOURCES = \
	flows.c \
	main.c \
	pkt_rss.c \
	program_args.c \
	session_hashtable.c \
	$(DOCA_APP_COMMON)/dpdk_utils.c \
	$(DOCA_APP_COMMON)/offload_rules.c

OBJECTS = $(SOURCES:.c=.o)

EXECUTABLE = doca_geneve_demo


CFLAGS += -O2 -Wall -DDOCA_ALLOW_EXPERIMENTAL_API -Wextra `pkg-config --cflags doca` -I. -I$(DOCA_APP_COMMON)
LDFLAGS += `pkg-config --libs --static doca`

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

clean:
	rm -f $(OBJECTS) $(EXECUTABLE)
