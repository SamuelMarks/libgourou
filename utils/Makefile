
TARGETS=acsmdownloader adept_activate adept_remove

CXXFLAGS=-Wall `pkg-config --cflags Qt5Core Qt5Network` -fPIC -I$(ROOT)/include -I$(ROOT)/lib/pugixml/src/

STATIC_DEP=
LDFLAGS=`pkg-config --libs Qt5Core Qt5Network` -L$(ROOT) -lcrypto -lzip -lz

ifneq ($(STATIC_UTILS),)
STATIC_DEP = $(ROOT)/libgourou.a
else
LDFLAGS += -lgourou
endif

ifneq ($(DEBUG),)
CXXFLAGS += -ggdb -O0
else
CXXFLAGS += -O2
endif

COMMON_DEPS = drmprocessorclientimpl.cpp $(STATIC_DEP)

all: $(TARGETS)

acsmdownloader: acsmdownloader.cpp $(COMMON_DEPS)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

adept_activate: adept_activate.cpp $(COMMON_DEPS)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

adept_remove: adept_remove.cpp $(COMMON_DEPS)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -f $(TARGETS)

ultraclean: clean
