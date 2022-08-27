
TARGETS=acsmdownloader adept_activate adept_remove adept_loan_mgt launcher

CXXFLAGS=-Wall -fPIC -I$(ROOT)/include -I$(ROOT)/lib/pugixml/src/

STATIC_DEP=
LDFLAGS += -L$(ROOT) -lcrypto -lzip -lz -lcurl

ifneq ($(STATIC_UTILS),)
STATIC_DEP = $(ROOT)/libgourou.a
else
LDFLAGS += -lgourou
endif

ifneq ($(DEBUG),)
CXXFLAGS += -ggdb -O0 -DDEBUG
else
CXXFLAGS += -O2
endif


COMMON_DEPS = drmprocessorclientimpl.cpp utils_common.cpp
COMMON_OBJECTS = $(COMMON_DEPS:.cpp=.o)
COMMON_LIB  = utils.a

all: $(TARGETS)

${COMMON_LIB}: ${COMMON_DEPS} ${STATIC_DEP}
	$(CXX) $(CXXFLAGS) ${COMMON_DEPS} $(LDFLAGS) -c
	$(AR) crs $@ ${COMMON_OBJECTS} $(STATIC_DEP)

%: %.cpp ${COMMON_LIB}
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -f $(TARGETS) $(COMMON_LIB)

ultraclean: clean
