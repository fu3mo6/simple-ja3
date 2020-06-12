CONFIG_DEBUG=y

CC ?= gcc
#STRIP ?= strip
CFLAGS ?= -g -Wall

########################################
###  Add objects according to option ###
########################################

# Main Objects
OBJS = pcap_handler.o ja3_parser.o

ifeq ($(CONFIG_DEBUG),y)
CFLAGS += -O0 -DCONFIG_DEBUG
endif

# Compile option
CFLAGS += -Werror

LDFLAGS += -lpcap

EXES = a.out

.PHONY: build clean

build : clean $(EXES)

$(EXES): main.o $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@  $(LDFLAGS)

%.o: %.c
	$(CC) $(CLAGS) $^ -c -o $@	

clean :
	rm -f *.o $(OBJS) $(EXES)
