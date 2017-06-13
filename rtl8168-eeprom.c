#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>

#include <pci/pci.h>
#include <sys/fcntl.h>
#include <sys/mman.h>

/* utility to program MAC address of RTL8168 / RTL8111E EEPROM
 * (C) 2015 by Harald Welte <hwelte@sysmocom.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

static void die(char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	vfprintf(stderr, msg, args);
	fputc('\n', stderr);
	exit(1);
}

static int macaddr_parse(uint8_t *out, const char *in)
{
	/* 00:00:00:00:00:00 */
	char tmp[18];
	char *tok;
	unsigned int i = 0;

	if (strlen(in) < 17)
		return -1;

	strncpy(tmp, in, sizeof(tmp)-1);
	tmp[sizeof(tmp)-1] = '\0';

	for (tok = strtok(tmp, ":"); tok && (i < 6); tok = strtok(NULL, ":")) {
		unsigned long ul = strtoul(tok, NULL, 16);
		out[i++] = ul & 0xff;
	}

	return 0;
}


/* 
 * RTL8188E SPI Access
 */

enum rtlspi_pin {
	RTLSPI_CS,
	RTLSPI_CK,
	RTLSPI_SI,
	RTLSPI_SO,
};

const uint8_t pin2bit[] = {
#if 0
	/* according to RTL8111F Series EEPROM & eFuse data sheet */
	[RTLSPI_CS] = 0x40,
	[RTLSPI_CK] = 0x20,
	[RTLSPI_SI] = 0x10,
	[RTLSPI_SO] = 0x08,
#define RTLSPI_C0_REG	0x51
#else
	/* according to non-mainline driver patch, works on 8111E */
	[RTLSPI_CS] = 0x08,
	[RTLSPI_CK] = 0x04,
	[RTLSPI_SI] = 0x02,
	[RTLSPI_SO] = 0x01,
#define RTLSPI_C0_REG	0x50
#endif
};


static void rtlspi_delay(void)
{
	usleep(3);
}

/* this is ugly and should go */
int g_memfd;
void *g_mapped_base;

#define rtl_reg_readb(offs)		*((uint8_t *) g_mapped_base + offs)
#define rtl_reg_writeb(offs, val)	*((uint8_t *) g_mapped_base + offs) = (val)

int rtlspi_init(struct pci_dev *d)
{
	size_t page_size = (size_t) sysconf (_SC_PAGESIZE);

	g_memfd = open("/dev/mem", O_RDWR | O_SYNC);
	if (g_memfd < 0) {
		perror("open");
		return -1;
	}
	g_mapped_base = mmap(0, page_size, PROT_READ|PROT_WRITE, MAP_SHARED, g_memfd, d->base_addr[2] & PCI_ADDR_MEM_MASK);
	if (g_mapped_base == MAP_FAILED) {
		perror("mmap");
		close(g_memfd);
		return -1;
	}

#if 0
	uint8_t v;
	v = rtl_reg_readb(0x52);
	v &= ~0xc0;
	rtl_reg_writeb(0x52, v);
#endif

	return 0;
}

int rtlspi_fini(struct pci_dev *d)
{
	munmap(g_mapped_base, d->size[2]);
	close(g_memfd);
	return 0;
}

int rtlspi_pin_set(struct pci_dev *d, enum rtlspi_pin pin, int lvl)
{
	uint8_t val;

	if (pin > (sizeof(pin2bit)/sizeof(pin2bit[0])))
		return -1;

	val = rtl_reg_readb(RTLSPI_C0_REG);
	val |= 0x80;
	val &= ~0x40;
	if (lvl)
		val |= pin2bit[pin];
	else
		val &= ~pin2bit[pin];

	rtl_reg_writeb(RTLSPI_C0_REG, val);

	return 0;
}

int rtlspi_pin_get(struct pci_dev *d, enum rtlspi_pin pin)
{
	uint8_t val;

	if (pin > (sizeof(pin2bit)/sizeof(pin2bit[0])))
		return -1;

	val = rtl_reg_readb(RTLSPI_C0_REG);

	if (val & pin2bit[pin])
		return 1;
	else
		return 0;
}

int rtlspi_xceive_bit(struct pci_dev *d, int lvl)
{
	int rc;

	/* set the bit */
	rc = rtlspi_pin_set(d, RTLSPI_SI, lvl);
	if (rc < 0)
		return rc;

	rtlspi_delay();

	/* raising edge on CK */
	rc = rtlspi_pin_set(d, RTLSPI_CK, 1);
	if (rc < 0)
		return rc;

	rtlspi_delay();

	/* falling edge of clock */
	rc = rtlspi_pin_set(d, RTLSPI_CK, 0);
	if (rc < 0)
		return rc;

	rc = rtlspi_pin_get(d, RTLSPI_SO);

	rtlspi_delay();

	return rc;
}

int rtlspi_xceive_bits(struct pci_dev *d, uint32_t data, int num_bits)
{
	int i, rc;
	uint32_t in = 0;

	for (i = 0; i < num_bits; i ++) {
		uint32_t bit_out = (data >> (num_bits - i -1)) & 1;
		in <<= 1;
		rc = rtlspi_xceive_bit(d, bit_out);
		if (rc < 0)
			return rc;
		in |= rc & 1;
	}

	return in;
}


/* 
 * AT93 EEPROM
 */

enum at93_op {
	AT93_OP_MISC	= 0,
	AT93_OP_WRITE	= 1,
	AT93_OP_READ	= 2,
	AT93_OP_ERASE	= 3,
};

static int at93c46_op(struct pci_dev *d, enum at93_op op, uint8_t addr, uint16_t data)
{
	uint32_t in;
	int rc;

	/* set initial state of pins: CS/SK/DI low */
	rc = rtlspi_pin_set(d, RTLSPI_CS, 0);
	rc |= rtlspi_pin_set(d, RTLSPI_CK, 0);
	rc |= rtlspi_pin_set(d, RTLSPI_SI, 0);
	if (rc)
		return -1;

	rtlspi_delay();

	/* start with raising edge on CS */
	rc = rtlspi_pin_set(d, RTLSPI_CS, 1);

	rtlspi_delay();

	/* start bit */
	rc = rtlspi_xceive_bit(d, 1);

	/* READ command bits */
	rc = rtlspi_xceive_bit(d, op & 2);
	rc = rtlspi_xceive_bit(d, op & 1);

	/* send address */
	rc = rtlspi_xceive_bits(d, addr, 6);

	switch (op) {
	case AT93_OP_ERASE:
	case AT93_OP_MISC:
		in = 0;
		break;
	default:
		/* read/write data */
		in = rtlspi_xceive_bits(d, data, 16);
		break;
	}
	
	/* stop with falling edge on CS */
	rc = rtlspi_pin_set(d, RTLSPI_CS, 0);

	if (rc)
		return -1;

	return in;
}

/* read one word */
int at93c46_op_read(struct pci_dev *d, uint8_t addr)
{
	return at93c46_op(d, AT93_OP_READ, addr, 0);
}

/* write one word */
int at93c46_op_write(struct pci_dev *d, uint8_t addr, uint16_t data)
{
	int rc = at93c46_op(d, AT93_OP_WRITE, addr, data);
	if (rc < 0)
		return rc;
	return 0;
}

/* endable write access */
int at93c46_op_ewen(struct pci_dev *d)
{
	return at93c46_op(d, AT93_OP_MISC, 0x30, 0);
}

/* endable write access */
int at93c46_op_erase(struct pci_dev *d, uint8_t addr)
{
	int i, rc;

	rc = at93c46_op(d, AT93_OP_ERASE, addr, 0);
	if (rc < 0)
		return rc;

	/* wait until ERASE cycle has finished */
	rtlspi_delay();
	rtlspi_pin_set(d, RTLSPI_CS, 1);
	for (i = 0; i < 0xffff; i++) {
		rc = rtlspi_pin_get(d, RTLSPI_SO);
		//rc = rtlspi_xceive_bit(d, 0);
		if (rc == 1)
			break;
	}
	rtlspi_pin_set(d, RTLSPI_CS, 0);

	if (i == 0xffff) {
		fprintf(stderr, "timeout during ERASE\n");
		return -1;
	}

	return 0;
}

/* disable write access */
int at93c46_op_ewds(struct pci_dev *d)
{
	return at93c46_op(d, AT93_OP_MISC, 0x00, 0);
}

static int eeprom_magic_ok(struct pci_dev *p)
{
	if (at93c46_op_read(p, 0) != 0x8129)
		return 0;
	if (at93c46_op_read(p, 1) != 0x10ec)
		return 0;
	if (at93c46_op_read(p, 2) != 0x8168)
		return 0;
	return 1;
}

static int eeprom_get_mac(struct pci_dev *p, uint8_t *mac_addr)
{
	uint16_t tmp;

	if (!eeprom_magic_ok(p))
		return -1;

	tmp = at93c46_op_read(p, 7);
	mac_addr[0] = tmp & 0xff;
	mac_addr[1] = tmp >> 8;
	tmp = at93c46_op_read(p, 8);
	mac_addr[2] = tmp & 0xff;
	mac_addr[3] = tmp >> 8;
	tmp = at93c46_op_read(p, 9);
	mac_addr[4] = tmp & 0xff;
	mac_addr[5] = tmp >> 8;

	return 0;
}

static int eeprom_set_mac(struct pci_dev *p, const uint8_t *mac_addr)
{
	uint16_t tmp;
	int rc = 0;

	if (!eeprom_magic_ok(p))
		return -1;

	printf("Writing new MAC address %02x:%02x:%02x:%02x:%02x:%02x...\n",
		mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
		mac_addr[4], mac_addr[5]);

	at93c46_op_ewen(p);

	tmp = mac_addr[0] | mac_addr[1] << 8;
	rc |= at93c46_op_erase(p, 7);
	rc |= at93c46_op_write(p, 7, tmp);

	tmp = mac_addr[2] | mac_addr[3] << 8;
	rc |= at93c46_op_erase(p, 8);
	rc |= at93c46_op_write(p, 8, tmp);
	tmp = mac_addr[4] | mac_addr[5] << 8;

	rc |= at93c46_op_erase(p, 9);
	rc |= at93c46_op_write(p, 9, tmp);
	if (rc)
		die("Error during EEPROM WRITE, MAC address is corrupt!\n");

	at93c46_op_ewds(p);

	printf("You need to COLD BOOT for the new address to be used\n");

	return 0;
}

/* generate a full dump */
static int eeprom_backup(struct pci_dev *p)
{
	uint8_t mac_addr[6];
	char fname[PATH_MAX];
	int i, rc, outfd;

	rc = eeprom_get_mac(p, mac_addr);
	if (rc < 0)
		return rc;

	snprintf(fname, sizeof(fname), "%02X%02X%02X%02X%02X%02X.backup",
		 mac_addr[0], mac_addr[1], mac_addr[2],
		 mac_addr[3], mac_addr[4], mac_addr[5]);

	outfd = open(fname, O_CREAT|O_WRONLY);
	if (!outfd)
		die("Can't open/create %s\n", fname);

	printf("Saving EEPROM backup to %s\n", fname);

	for (i = 0; i < 64; i++) {
		uint8_t tmp[2];
		int rc = at93c46_op_read(p, i);
		if (rc < 0)
			die("Error reading EEPROM addr %d\n", i);

		tmp[0] = rc & 0xff;
		tmp[1] = rc >> 8;
		if (write(outfd, tmp, 2) != 2)
			die("Error writing to backup file %s\n", fname);
	}
	close(outfd);

	return 0;
}

static void iterate_devices(struct pci_access *pa, char *filter_id, char *filter_slot,
			    const uint8_t *new_mac)
{
	struct pci_filter filt;
	struct pci_dev *p;
	char *msg;

	/* filter for specific devices only */
	printf("building filter\n");
	pci_filter_init(pa, &filt);

	if (filter_id) {
		msg = pci_filter_parse_id(&filt, filter_id);
		if (msg)
			die(msg);
	}
	if (filter_slot) {
		msg = pci_filter_parse_slot(&filt, filter_slot);
		if (msg)
			die(msg);
	}

	printf("starting bus iteration\n");
	for (p = pa->devices; p; p = p->next) {
		uint8_t old_mac[6];
		if (!pci_filter_match(&filt, p))
			continue;

		/* our own clumsy implementation of filtering */
		if (p->vendor_id != 0x10ec || p->device_id != 0x8168)
			continue;

		printf("found matching device (%02x:%02x.%d), ", p->bus, p->dev, p->func);
		printf("base_addr=0x%lx (len=%lu)\n", p->base_addr[2] & PCI_ADDR_MEM_MASK, p->size[2]);

		if (rtlspi_init(p) < 0)
			die("Cannot initialize RTL SPI mode\n");

		if (!eeprom_magic_ok(p))
			die("EEPROM Magic !OK\n");

		if (eeprom_get_mac(p, old_mac) < 0)
			die("Cannot read existing MAC addr from EEPROM\n");

		printf("Existing/Old MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
			old_mac[0], old_mac[1], old_mac[2],
			old_mac[3], old_mac[4], old_mac[5]);
		
		/* will die itself */
		eeprom_backup(p);

		if (new_mac)
			eeprom_set_mac(p, new_mac);

		rtlspi_fini(p);

		/* we support only one device per execution (for now) */
		if (new_mac)
			exit(0);
	}
}

int main(int argc, char **argv)
{
	int i;
	char *filter_id = NULL;
	char *filter_slot = NULL;
	uint8_t new_macbuf[6];
	uint8_t *new_mac = NULL;
	struct pci_access *pa = pci_alloc();

	/* same syntax as lspci */
	while ((i = getopt(argc, argv, "d:s:m:")) != -1) {
		switch (i) {
		case 'd':
			filter_id = optarg;
			break;
		case 's':
			filter_slot = optarg;
			break;
		case 'm':
			if (macaddr_parse(new_macbuf, optarg))
				die("Unable to parse `%s' as mac address\n", optarg);
			new_mac = new_macbuf;
			break;
		default:
			die("Syntax error");
		}
	}

	printf("initializing pci access\n");
	pa->error = die;
	pa->writeable = 1;
	pci_init(pa);
	pci_scan_bus(pa);

	iterate_devices(pa, filter_id, filter_slot, new_mac);

	exit(0);
}
