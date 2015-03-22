CFLAGS=-Wall -g `pkg-config --cflags libpci`
LDFLAGS=`pkg-config --libs libpci`

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

rtl8168-eeprom: rtl8168-eeprom.o
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f rtl8168-eeprom rtl8168-eeprom.o
