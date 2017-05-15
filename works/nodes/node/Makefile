CONTIKI_PROJECT = node
all: $(CONTIKI_PROJECT)

CONTIKI=../../..
CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"

CONTIKI_WITH_IPV6 = 1
MAKE_WITH_FAST_C ?= 0 # force Orchestra from command line
MAKE_WITH_ORCHESTRA ?= 0 # force Orchestra from command line
SEND_CNT ?= 100

MODULES += core/net/mac/tsch

ifeq ($(MAKE_WITH_FAST_C),1)
APPS += fast-c
CFLAGS += -DWITH_FAST_C=1
endif

ifeq ($(MAKE_WITH_ORCHESTRA),1)
APPS += orchestra 
CFLAGS += -DWITH_ORCHESTRA=1
endif

CFLAGS += -DSEND_CNT=$(SEND_CNT)

include $(CONTIKI)/Makefile.include
