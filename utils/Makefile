
TARGETS=acsmdownloader activate

CXXFLAGS=-Wall `pkg-config --cflags Qt5Core Qt5Network` -fPIC -I$(ROOT)/include -I$(ROOT)/lib/pugixml/src/
LDFLAGS=`pkg-config --libs Qt5Core Qt5Network` -L$(ROOT) -lgourou -lcrypto -lzip

ifneq ($(DEBUG),)
CXXFLAGS += -ggdb -O0
else
CXXFLAGS += -O2
endif

all: $(TARGETS)

acsmdownloader: drmprocessorclientimpl.cpp acsmdownloader.cpp 
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

activate: drmprocessorclientimpl.cpp activate.cpp 
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -f $(TARGETS)

ultraclean: clean
