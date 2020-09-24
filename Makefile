##### Available defines for JWT_CFLAGS #####
##
## AUTHOR: chenweiqi [2016-4-13]
## https://github.com/chenweiqi/lua-jwt
##

##### Build defaults #####
LUA_VERSION =       5.3
TARGET =            jwt.so
PREFIX =            /usr/local
#CFLAGS =            -g -Wall -pedantic -fno-inline
CFLAGS =            -O3 -Wall -pedantic -DNDEBUG
JWT_CFLAGS =        -fPIC
JWT_LDFLAGS =       -shared
LUA_INCLUDE_DIR =   $(PREFIX)/include
LUA_CMODULE_DIR =   $(PREFIX)/lib/lua/$(LUA_VERSION)
LUA_MODULE_DIR =    $(PREFIX)/share/lua/$(LUA_VERSION)
LUA_BIN_DIR =       $(PREFIX)/bin

##### End customisable sections #####

EXECPERM =          755

BUILD_CFLAGS =      -I$(LUA_INCLUDE_DIR) $(JWT_CFLAGS)
OBJS =              lua_jwt.o

.PHONY: all clean install

.c.o:
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $(BUILD_CFLAGS) -Iinclude -o $@ $<

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(JWT_LDFLAGS) -Iinclude -Wl,--whole-archive ./lib/*.a -Wl,--no-whole-archive -o $@ $(OBJS) ./lib/libjwt.a ./lib/libjansson.a ./lib/libcrypto.a ./lib/libssl.a  ./lib/libidn.a 

install: $(TARGET)
	mkdir -p $(DESTDIR)$(LUA_CMODULE_DIR)
	cp $(TARGET) $(DESTDIR)$(LUA_CMODULE_DIR)
	chmod $(EXECPERM) $(DESTDIR)$(LUA_CMODULE_DIR)/$(TARGET)

clean:
	rm -f *.o $(TARGET)

test:
	$(LUA_BIN_DIR)/lua -e "io.stdout:setvbuf 'no'" "tests/sample.lua"
