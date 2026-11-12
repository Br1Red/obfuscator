CFLAGS += -std=gnu11 -O2 -Wall -Wextra -Wformat=2 -fstack-protector-strong -D_FORTIFY_SOURCE=3
OBFUSCATOR_LDLIBS = -lcrypto -largon2

.PHONY: all clean
.DELETE_ON_ERROR:

all: libobfuscator.so

clean:
	@rm -f libobfuscator.so hide_strings obfuscator_secrets.h *.o .depend

hide_strings: hide_strings.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

libobfuscator.so: libobfuscator.o libobfuscator_start.o
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,-e,libobfuscator_start -o $@ $^ $(OBFUSCATOR_LDLIBS) $(LDLIBS)

libobfuscator.o: libobfuscator.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -c -o $@ $<

obfuscator_secrets.h: obfuscator_secrets.txt hide_strings
	./hide_strings obfuscator_secrets.txt

.depend: hide_strings.c libobfuscator.c libobfuscator_start.S Makefile
	@set -e; { \
		$(CC) $(CPPFLAGS) $(CFLAGS) -MM -MG -MP -MT hide_strings.o -MT .depend hide_strings.c; \
		$(CC) $(CPPFLAGS) $(CFLAGS) -MM -MG -MP -MT libobfuscator.o -MT .depend libobfuscator.c; \
		$(CC) $(CPPFLAGS) $(ASFLAGS) -MM -MG -MP -MT libobfuscator_start.o -MT .depend libobfuscator_start.S; \
	} > $@

ifneq ($(MAKECMDGOALS),clean)
include .depend
endif
