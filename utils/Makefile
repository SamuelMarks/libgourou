
TARGETS=acsmdownloader adept_activate adept_remove adept_loan_mgt

CXXFLAGS=-Wall -fPIC -I$(ROOT)/include -I$(ROOT)/lib/pugixml/src/

LDFLAGS=

ifneq ($(OPENSSL3),)
# OpenSSL 1.1.0 compat
CXXFLAGS += -DOPENSSL_API_COMPAT=0x10100000L
CXXFLAGS += -I/tmp/openssl3/usr/include/ -I/tmp/openssl3/usr/include/x86_64-linux-gnu
LDFLAGS += -L/tmp/openssl3/usr/lib/x86_64-linux-gnu -L/tmp/openssl3/usr/lib/x86_64-linux-gnu/ossl-modules
endif


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

acsmdownloader: acsmdownloader.cpp ${COMMON_LIB}
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

adept_activate: adept_activate.cpp ${COMMON_LIB}
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

adept_remove: adept_remove.cpp ${COMMON_LIB}
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

adept_loan_mgt: adept_loan_mgt.cpp ${COMMON_LIB}
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -f $(TARGETS)

ultraclean: clean
