APP        := rise
SRC_DIR    := src
PREFIX     ?= /usr/local
SYSCONFDIR ?= /etc
MANDIR     ?= $(PREFIX)/share/man

GNATMAKE ?= gnatmake
CC       ?= cc

ADAFLAGS ?= -O2 -gnat2022 -gnata -gnato -Wall -fstack-protector-strong -fPIE
CFLAGS   ?= -O2 -Wall -Wextra -Wpedantic -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2
LDFLAGS  ?= -lpam -lpam_misc -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -pie

.PHONY: all install install-bin install-config install-pam install-man uninstall clean check check-config

all: $(APP)

$(APP): $(SRC_DIR)/rise.adb $(SRC_DIR)/rise_platform.o
	$(GNATMAKE) $(ADAFLAGS) $(SRC_DIR)/rise.adb -o $(APP) -largs $(SRC_DIR)/rise_platform.o $(LDFLAGS)

$(SRC_DIR)/rise_platform.o: $(SRC_DIR)/rise_platform.c
	$(CC) $(CFLAGS) -c $(SRC_DIR)/rise_platform.c -o $(SRC_DIR)/rise_platform.o

# install intentionally does NOT depend on $(APP).
# Build as your normal user with `make`, then install with `sudo make install`.
# This avoids sudo losing PATH entries for GNAT/GNATMAKE and trying to rebuild as root.
install: install-bin install-config install-pam install-man

install-bin:
	@test -x ./$(APP) || { echo "error: ./$(APP) is missing; run 'make' first"; exit 1; }
	install -d -o root -g root -m 0755 $(DESTDIR)$(PREFIX)/bin
	install -o root -g root -m 4755 ./$(APP) $(DESTDIR)$(PREFIX)/bin/$(APP)

install-config:
	install -d -o root -g root -m 0755 $(DESTDIR)$(SYSCONFDIR)
	@if [ ! -f $(DESTDIR)$(SYSCONFDIR)/rise.conf ]; then \
		install -o root -g root -m 0600 examples/rise.conf $(DESTDIR)$(SYSCONFDIR)/rise.conf; \
	else \
		echo "keeping existing $(DESTDIR)$(SYSCONFDIR)/rise.conf"; \
	fi

install-pam:
	install -d -o root -g root -m 0755 $(DESTDIR)$(SYSCONFDIR)/pam.d
	@if [ ! -f $(DESTDIR)$(SYSCONFDIR)/pam.d/rise ]; then \
		install -o root -g root -m 0644 pam.d/rise $(DESTDIR)$(SYSCONFDIR)/pam.d/rise; \
	else \
		echo "keeping existing $(DESTDIR)$(SYSCONFDIR)/pam.d/rise"; \
	fi

install-man:
	install -d -o root -g root -m 0755 $(DESTDIR)$(MANDIR)/man1
	install -o root -g root -m 0644 man/rise.1 $(DESTDIR)$(MANDIR)/man1/rise.1

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(APP)
	rm -f $(DESTDIR)$(MANDIR)/man1/rise.1

check: $(APP)
	./$(APP) --help >/dev/null

check-config:
	@test -x ./$(APP) || { echo "error: ./$(APP) is missing; run 'make' first"; exit 1; }
	./$(APP) -C

clean:
	rm -f $(APP) $(SRC_DIR)/*.o $(SRC_DIR)/*.ali
