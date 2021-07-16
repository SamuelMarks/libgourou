
TARGETS=acsmdownloader adept_activate

CXXFLAGS=-Wall `pkg-config --cflags Qt5Core Qt5Network` -fPIC -I$(ROOT)/include -I$(ROOT)/lib/pugixml/src/
ifneq ($(STATIC_UTILS),)
LDFLAGS=`pkg-config --libs Qt5Core Qt5Network` -L$(ROOT) $(ROOT)/libgourou.a -lcrypto -lzip
else
LDFLAGS=`pkg-config --libs Qt5Core Qt5Network` -L$(ROOT) -lgourou -lcrypto -lzip
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
