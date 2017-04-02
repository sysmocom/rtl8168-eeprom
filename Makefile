CFLAGS=-Wall -g `pkg-config --cflags libpci`
LIBS=`pkg-config --libs libpci`

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

rtl8168-eeprom: rtl8168-eeprom.o
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	rm -f rtl8168-eeprom rtl8168-eeprom.o
