OPTS := -Os -std=gnu90
CFLAGS += -Wall -Werror -Wextra -fdata-sections -ffunction-sections -fno-strict-aliasing
LDFLAGS	+= -Wl,--gc-sections -static
SFLAGS := -R .comment -R .gnu.version -R .note -R .note.ABI-tag

ifeq ($(origin CC),default)
CC = $(CROSS_COMPILE)cc
endif
STRIP ?= $(CROSS_COMPILE)strip

SOURCES := $(wildcard *.c)
OBJECTS := $(patsubst %.c,%.o,$(SOURCES))
TARGET := fbsplash

.PHONY: all clean

all: $(OBJECTS) $(TARGET)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(OPTS) -c -o $@ $<

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OPTS) $(LDFLAGS) -o $@ $^
	$(STRIP) $(SFLAGS) $@

clean:
	rm -fv $(OBJECTS)
	rm -fv $(TARGET)
