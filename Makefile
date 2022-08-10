
AR ?= $(CROSS)ar
CXX ?= $(CROSS)g++

UPDFPARSERLIB = ./lib/updfparser/libupdfparser.a

CXXFLAGS=-Wall -fPIC -I./include -I./lib/pugixml/src/ -I./lib/updfparser/include
LDFLAGS = $(UPDFPARSERLIB)

BUILD_STATIC ?= 0
BUILD_SHARED ?= 1
BUILD_UTILS  ?= 1

TARGETS =
ifneq ($(BUILD_STATIC), 0)
  TARGETS += libgourou.a
endif
ifneq ($(BUILD_SHARED), 0)
  TARGETS += libgourou.so
endif
ifneq ($(BUILD_UTILS), 0)
  TARGETS += build_utils
endif


ifneq ($(DEBUG),)
CXXFLAGS += -ggdb -O0 -DDEBUG
else
CXXFLAGS += -O2
endif

ifneq ($(STATIC_NONCE),)
CXXFLAGS += -DSTATIC_NONCE=1
endif

SRCDIR      := src
INCDIR      := inc
BUILDDIR    := obj
TARGETDIR   := bin
SRCEXT      := cpp
OBJEXT      := o

SOURCES      = src/libgourou.cpp src/user.cpp src/device.cpp src/fulfillment_item.cpp src/loan_token.cpp src/bytearray.cpp src/pugixml.cpp
OBJECTS     := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.$(OBJEXT)))

all: lib obj $(TARGETS)

lib:
	mkdir lib
	./scripts/setup.sh

update_lib:
	./scripts/update_lib.sh

obj:
	mkdir obj

$(BUILDDIR)/%.$(OBJEXT): $(SRCDIR)/%.$(SRCEXT)
	$(CXX) $(CXXFLAGS) -c $^ -o $@

libgourou: libgourou.a libgourou.so

libgourou.a: $(OBJECTS) $(UPDFPARSERLIB)
	$(AR) crs $@ obj/*.o  $(UPDFPARSERLIB)

libgourou.so: $(OBJECTS) $(UPDFPARSERLIB)
	$(CXX) obj/*.o $(LDFLAGS) -o $@ -shared

build_utils:
	make -C utils ROOT=$(PWD) CXX=$(CXX) AR=$(AR) DEBUG=$(DEBUG) STATIC_UTILS=$(STATIC_UTILS) OPENSSL3=$(OPENSSL3)

clean:
	rm -rf libgourou.a libgourou.so obj
	make -C utils clean

ultraclean: clean
	rm -rf lib
	make -C utils ultraclean
