
TARGETS=acsmdownloader adept_activate

CXXFLAGS=-Wall `pkg-config --cflags Qt5Core Qt5Network` -fPIC -I$(ROOT)/include -I$(ROOT)/lib/pugixml/src/

LDFLAGS=`pkg-config --libs Qt5Core Qt5Network` -L$(ROOT) -lcrypto -lzip -lz
ifneq ($(STATIC_UTILS),)
LDFLAGS += $(ROOT)/libgourou.a
else
LDFLAGS += -lgourou
endif

ifneq ($(DEBUG),)
CXXFLAGS += -ggdb -O0
else
CXXFLAGS += -O2
endif

all: $(TARGETS)

acsmdownloader: drmprocessorclientimpl.cpp acsmdownloader.cpp 
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

adept_activate: drmprocessorclientimpl.cpp adept_activate.cpp 
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -f $(TARGETS)

ultraclean: clean
