
AR ?= $(CROSS)ar
CXX ?= $(CROSS)g++

CXXFLAGS=-Wall -fPIC -I./include -I./lib -I./lib/pugixml/src/
LDFLAGS=

ifneq ($(DEBUG),)
CXXFLAGS += -ggdb -O0
else
CXXFLAGS += -O2
endif

SRCDIR      := src
INCDIR      := inc
BUILDDIR    := obj
TARGETDIR   := bin
SRCEXT      := cpp
OBJEXT      := o

SOURCES=src/libgourou.cpp src/user.cpp src/device.cpp src/fulfillment_item.cpp src/bytearray.cpp src/pugixml.cpp
OBJECTS     := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.$(OBJEXT)))

.PHONY: utils

all: lib obj libgourou utils

lib:
	mkdir lib
	./scripts/setup.sh

obj:
	mkdir obj

$(BUILDDIR)/%.$(OBJEXT): $(SRCDIR)/%.$(SRCEXT)
	$(CXX) $(CXXFLAGS) -c $^ -o $@

libgourou: libgourou.a libgourou.so

libgourou.a: $(OBJECTS)
	$(AR) crs $@ obj/*.o

libgourou.so: libgourou.a
	$(CXX) obj/*.o $(LDFLAGS) -o $@ -shared

utils:
	make -C utils ROOT=$(PWD) CXX=$(CXX) AR=$(AR) DEBUG=$(DEBUG) STATIC_UTILS=$(STATIC_UTILS)

clean:
	rm -rf libgourou.a libgourou.so obj
	make -C utils clean

ultraclean: clean
	rm -rf lib
	make -C utils ultraclean
