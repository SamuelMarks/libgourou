
TARGETS=acsmdownloader adept_activate adept_remove

CXXFLAGS=-Wall -fPIC -I$(ROOT)/include -I$(ROOT)/lib/pugixml/src/

STATIC_DEP=
LDFLAGS=-L$(ROOT) -lcrypto -lzip -lz -lcurl

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

COMMON_DEPS = drmprocessorclientimpl.cpp utils_common.cpp $(STATIC_DEP)

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
