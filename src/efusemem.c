// SPDX-License-Identifier: MIT
/*
 * Copyright (C) 2024 PHYTEC Messtechnik GmbH
 * Author: Yunus Bas <y.bas@phytec.de>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include "version.h"

#define MAXBUFSZ	24
#define SOC_COUNT	3

#define BIT(n) (0x1UL << (n))
#define BITMAP(x, n)	(x << n)
#define ALIGN(x)	\
	(!(x & 3) ? x : ((x & ~3) + 4))

#define _WORD(x)	((x) << 2)
#define _BANK_MX6(x)	((x) << 5)
#define _BANK_MX8(x)	((x) << 4)
#define BANK_WORD_OFFSET_MX6(x, y)	(_BANK_MX6(x) + _WORD(y))
#define BANK_WORD_OFFSET_MX8(x, y)	(_BANK_MX8(x) + _WORD(y))

#define OCOTP_REVOKE(x)	((1 << x) & 0xf)

#define add_fuse(_name, _reg, _size, _lock, _read, __write)	\
	{	\
		.name = _name, \
		.reg = _reg, \
		.size = _size, \
		.access_flags = 0, \
		.lockbit = _lock, \
		.read = _read, \
		.write = __write, \
		.is_active = false, \
	}

#define _fuse_init(_fuse)		\
	_fuse->is_active = true;	\
	if (ioflag == IO_WRITE)	{	\
		if (optarg == NULL && optind < argc \
				&& argv[optind][0] != '-')	\
			optarg = argv[optind++]; \
		else if (optarg == NULL) {	\
			printf("Missing argument\n"); \
			goto main_free_mem;	\
		}	\
		size = strlen(optarg);	\
		if (size > 1 && size != _fuse->size<<1) {	\
			printf("Value incorrect\n"); \
			goto main_free_mem;	\
		}	\
		_fuse->arg = (size > 1) ? strdup(optarg) : calloc(1, sizeof(int)); \
		if (!(_fuse->arg)) {	\
			perror("Failed to allocate memory");	\
			goto main_free_mem; } \
		if (size == 1)	\
			*_fuse->arg = atoi(optarg); \
	}

#define switch_entry(_opt)		\
	fusemap_t * fuse##_opt = &efuse->soc_data->fuses[_opt]; \
	_fuse_init(fuse##_opt)

enum efuse_op_flag {
	IO_READ,
	IO_WRITE,
	IO_LOCK
};

enum efuse_regs {
	CFG5,
	SRK,
	MAC,
	REVOKE,
	EFUSE_REGS_END
};

typedef enum efuse_lock_id {
	SRK_LOCK,
	SEC_CONFIG,
	SDP_DISABLE,
	SJC_DISABLE,
	LOCKID_END
} lock_id_t;

struct efuse_data;

typedef struct fusemap {
	const char *name;
	uint32_t reg;
	uint8_t size;
	uint8_t access_flags;
	uint8_t lockbit;
	char *arg;
	int (*read)(struct efuse_data *, uint32_t *);
	int (*write)(struct efuse_data *, uint8_t *);
	bool is_active;
} fusemap_t;

typedef struct lockopt {
	lock_id_t id;
	uint32_t addr;
	uint8_t bit;
} lockopt_t;

typedef struct soc_data {
	const char *soc_name;
	fusemap_t *fuses;
	const lockopt_t *locks;
} soc_data_t;

struct efuse_lock_options_s {
	int secureboot;
	int sdp;
	int jtag;
} efuse_lock_options_default = {0, 0, 0};

typedef struct efuse_lock_options_s efuse_lock_options;

struct efuse_data {
	soc_data_t *soc_data;
	enum efuse_regs reg_current;
	union hashval {
		uint8_t byte[32];
		uint32_t word[8];
		uint64_t lword[4];
	} hexbin;
	uint32_t lockstat;
	FILE *file;
	bool force;
};

const char * soc_id_path = "/sys/devices/soc0/soc_id";
static efuse_lock_options lockopts;
static struct efuse_data *efuse;

void print_help(void) {
	printf("Usage: efusemem read/write/lock [fhkmryv] <options> <path_to_nvmem>\n");
	puts("  Read/Write options:\n"
		 "	-k --hash		read/write HASH from commandline\n"
		 "	-f --file		write HASH from file\n"
		 "	-m --mac		read/write MAC address from commandline\n"
		 "	-r --revoke		revoke keys\n"
		 "  Lock options:\n"
		 "	--secureboot		Enable Secureboot and lock HASH\n"
		 "	--sdp			lock serial download port\n"
		 "	--jtag			lock (disable) JTAG port\n"
		 "  General options:\n"
		 "	-y --force		bypass user confirm. Say yes to all\n"
		 "	-h --help		print help info\n"
		 "	-v --version    print version of the program\n"
		 "  path to nvmem:\n"
		 "	(default: /sys/bus/nvmem/devices/imx-ocotp0/nvmem)\n"
	);
}

fusemap_t * get_fusemap(struct efuse_data * efuse)
{
	return &efuse->soc_data->fuses[efuse->reg_current];
}

static const lockopt_t * get_lockopts(struct efuse_data * efuse)
{
	return efuse->soc_data->locks;
}

char *lock_helper(int id)
{
	switch (id) {
		case SRK_LOCK:
		case SEC_CONFIG:
			return "enable Secureboot";
			break;
		case SDP_DISABLE:
			return "disable Serial Download Protocol";
			break;
		case SJC_DISABLE:
			return "disable Secure JTAG Controller";
			break;
	}
	return NULL;
}

void str_to_hex(char *dest, char *src, size_t n)
{
	char c;

	unsigned i;
	int j = 0;

	for (i = 0; i < n; i++) {
		c = src[i];
		if (c >= '0' && c <= '9')
			c -= 48;
		else if (c >= 'A' && c <= 'F')
			c -= 55;
		else if (c >= 'a' && c <= 'f')
			c -= 87;
		else {
			printf("Hex value incorrect\n");
			break;
		}

		if ((i % 2) == 0)
			dest[j] = (c << 4);
		else
			dest[j++] |= (c & 0xf);
	}
}

static int _read(FILE *file, uint8_t *buf, int offset, size_t len)
{
	int size;
	fseek(file, offset, SEEK_SET);

	size = fread(buf, len, 1, file);
	if (ferror(file)) {
		printf("Read from file failed\n");
		clearerr(file);
		return -1;
	}
	return size;
}

static int _write(FILE *file, uint8_t *buf, int offset, int len)
{
	int size;
	fseek(file, offset, SEEK_SET);

	size = fwrite(buf, 1, len, file);
	if (ferror(file)) {
		printf("Write to file failed\n");
		clearerr(file);
		return -1;
	}

	return size;
}

int read_hash_from_file(struct efuse_data *efuse, char *file)
{
	fusemap_t *fuse = get_fusemap(efuse);
	int fd;
	int size;
	char *buf = (char*)efuse->hexbin.byte;

	fd = open(file, O_RDONLY, 0);
	if (fd < 0) {
		perror("Cannot open file");
		return fd;
	}

	size = read(fd, buf, fuse->size);
	if (size != fuse->size)
		printf("read: size mismatch.\n");

	close(fd);

	return 0;
}

int user_confirmation(uint8_t *data, int reg, int len)
{
	char input;
	int i;
	int ret;

	printf("This will irrecoverably burn the value\n");

	for (i = 0; i < len; i++)
		printf("%.2x ", data[i]);

	printf(" to address 0x%x.\nDo you want to continue? [Y/N]: ", reg);

	ret = scanf("%c", &input);

	ret = input == 'y' || input == 'Y' ? 1 : 0;

	return ret;
}

int user_confirmation_lock(const lockopt_t *lock)
{
	char input;
	int ret;

	printf("This will irrecoverably %s.", lock_helper(lock->id));
	printf(" Do you want to continue? [Y/N]: ");

	ret = scanf("%c", &input);

	ret = input == 'y' || input == 'Y' ? 1 : 0;

	return ret;
}


int efuse_read(struct efuse_data *efuse, uint8_t *buf)
{
	fusemap_t *fuse = get_fusemap(efuse);
	int ret;

	ret = _read(efuse->file, (uint8_t*)buf, fuse->reg, fuse->size);

	return ret < 0 ? ret : 0;
}

int efuse_write(struct efuse_data *efuse, uint8_t *buf)
{
	fusemap_t *fuse = get_fusemap(efuse);
	int ret = 0;
	int aligned_size = ALIGN(fuse->size);
	unsigned offset = fuse->reg;

	uint8_t *data = calloc(aligned_size, sizeof(uint8_t));

	memcpy(data, buf, fuse->size);

	if (efuse->force || user_confirmation(data, fuse->reg, fuse->size)) {
		for (int i = 0; i < aligned_size; i+=4)
			ret = _write(efuse->file, &data[i], offset+i, 4);
		//if (ret == aligned_size >> 2)
		printf("Done!\n");
	} else {
		printf("Burn efuse aborted. \n");
	}

	free(data);
	return ret;
}

// TODO Two MACs can be burned but one is supported at the moment
int efuse_write_mac_mx8(struct efuse_data *efuse, uint8_t *buf)
{
	fusemap_t *fuse = get_fusemap(efuse);

	uint8_t mac[8] = {0};

	str_to_hex((char*)efuse->hexbin.byte, (char*)buf, fuse->size<<1);

	// IMX8 MAC byte ordering is reversed
	for (uint8_t i = 0; i < 6; i++){
		mac[i] = efuse->hexbin.byte[5-i];
	}

	/* Two MACs can be fused on 3 words. The middle word is shared
	 * by the two MACs. We can just write zero to the unhandled two
	 * bytes, since even if fuses are set, it won't have any negative
	 * effect. */

	return efuse_write(efuse, mac);
}

int efuse_revoke_status(struct efuse_data *efuse, uint32_t *rvk)
{
	int ret;
	uint32_t revoke;
	int i;
	ret = efuse_read(efuse, (uint8_t*)rvk);
	if (ret)
		return ret;

	revoke = *rvk;
	if (!revoke) {
		printf("No key has been revoked\n");
	} else {
		for(i = 0; i < 4; i++)
			if (OCOTP_REVOKE(i) & revoke)
				printf("Key %d revoked\n", i+1);
	}
	return 0;
}

int efuse_revoke_update(struct efuse_data *efuse, uint8_t *rvk)
{
	int ret;
	uint8_t revoke_status = 0, revoke = 0;
	ret = efuse_read(efuse, &revoke_status);
	if (ret)
		return ret;

	memcpy(&revoke, rvk, 1);

	if (revoke < 1 || revoke > 4) {
		printf("Revoke key out of range\n");
		return 0;
	}

	if (BIT(revoke-1) & revoke_status) {
		printf("Key %u already revoked\n", revoke);
	} else {
		revoke_status |= BIT(revoke-1);
		ret = efuse_write(efuse, &revoke_status);
	}

	return ret;
}

struct fusemap imx6ull_fuses[] = {
	add_fuse("CFG5", BANK_WORD_OFFSET_MX6(0, 6), 4, 100, NULL, NULL),
	add_fuse("SRK", BANK_WORD_OFFSET_MX6(3, 0), 32, 14, NULL, NULL),
	add_fuse("MAC", BANK_WORD_OFFSET_MX6(4, 2), 6, 8, NULL, NULL),
	add_fuse("Revoke", BANK_WORD_OFFSET_MX6(5, 7), 1, 100, efuse_revoke_status, efuse_revoke_update),
	{NULL}
};

static const lockopt_t imx6ull_locks[] = {
	{
		.id = SRK_LOCK,
		.addr = BANK_WORD_OFFSET_MX6(0, 0),
		.bit = 14,
	}, {
		.id = SEC_CONFIG,
		.addr = BANK_WORD_OFFSET_MX6(0, 6),
		.bit = 1,
	}, {
		.id = SDP_DISABLE,
		.addr = BANK_WORD_OFFSET_MX6(0, 6),
		.bit = 17,
	}, {
		.id = SJC_DISABLE,
		.addr = BANK_WORD_OFFSET_MX6(0, 6),
		.bit = 20,
	},
	{LOCKID_END, 0, 0}
};

struct fusemap imx8mp_fuses[] = {
	{NULL},
	add_fuse("SRK", BANK_WORD_OFFSET_MX8(6, 0), 32, 100, NULL, NULL),
	add_fuse("MAC", BANK_WORD_OFFSET_MX8(9, 0), 6, 100, NULL, efuse_write_mac_mx8),
	add_fuse("Revoke", BANK_WORD_OFFSET_MX8(9, 3), 1, 100, efuse_revoke_status, efuse_revoke_update),
	{NULL}
};

static const lockopt_t imx8mp_locks[] = {
	{
		.id = SRK_LOCK,
		.addr = BANK_WORD_OFFSET_MX8(0, 0),
		.bit = 9,
	}, {
		.id = SEC_CONFIG,
		.addr = BANK_WORD_OFFSET_MX8(1, 3),
		.bit = 25,
	}, {
		.id = SDP_DISABLE,
		.addr = BANK_WORD_OFFSET_MX8(2, 0),
		.bit = 21,
	}, {
		.id = SJC_DISABLE,
		.addr = BANK_WORD_OFFSET_MX8(1, 3),
		.bit = 21,
	},
	{LOCKID_END, 0, 0}
};


static struct soc_data socs[] = {
	{
		.soc_name = "i.MX6ULL",
		.fuses = imx6ull_fuses,
		.locks = imx6ull_locks,
	}, {
		.soc_name = "i.MX6Q",
		.fuses = imx6ull_fuses,
		.locks = imx6ull_locks,
	}, {
		.soc_name = "i.MX8MP",
		.fuses = imx8mp_fuses,
		.locks = imx8mp_locks,
	}, {
		.soc_name = "i.MX8MM",
		.fuses = imx8mp_fuses,
		.locks = imx8mp_locks,
	},
	{NULL}
};

struct soc_data * get_soc_data(void)
{
	FILE * soc_id;
	char name[MAXBUFSZ];

	int i;
	bool found = false;

	/* For the means of generic SOC approach (at least for ARM cores)
	 * we need to detect the soc-type. This should be possible through
	 * vendor reserved registers. But for now, we can use the kernel
	 * derived sysfs-file for SoC ID.
	 */

	soc_id = fopen(soc_id_path, "r");
	if (soc_id == NULL) {
		perror("fopen");
		return NULL;
	}

	if (fgets(name, MAXBUFSZ, soc_id) == NULL)
		goto get_soc_data_exit;

	for (i = 0; i < SOC_COUNT; i++) {
		if ( ! strncmp(name, socs[i].soc_name, strlen(socs[i].soc_name)) ) {
			printf("Found SoC: %s\n", name);
			found = true;
			break;
		}
	}

get_soc_data_exit:
	fclose(soc_id);

	return found ? &socs[i] : NULL;
}

int efuse_hashfile_update(struct efuse_data *efuse, uint8_t *file)
{
	int ret;

	ret = read_hash_from_file(efuse, (char*)file);
	if (ret < 0) {
		printf("Failed to read from file '%s': %d\n", file, ret);
		return ret;
	}

	ret = efuse_write(efuse, efuse->hexbin.byte);

	return ret;
}

static int efuse_io_lock(struct efuse_data *efuse)
{
	const lockopt_t *locks = get_lockopts(efuse);
	uint32_t addr, data;
	int ret = 0;

	if (lockopts.secureboot) {
		data = BIT(locks[SRK_LOCK].bit);
		addr = locks[SRK_LOCK].addr;
		if (efuse->force || user_confirmation_lock(&locks[SRK_LOCK]))
			ret = _write(efuse->file, (uint8_t*) &data, addr, 1);
		else
			goto efuse_io_lock_ret_abort;

		if (ret)
			goto efuse_io_lock_ret_fail;

		data = BIT(locks[SEC_CONFIG].bit);
		addr = locks[SEC_CONFIG].addr;
		ret = _write(efuse->file, (uint8_t*) &data, addr, 1);
	}

	if (lockopts.sdp) {
		data = BIT(locks[SDP_DISABLE].bit);
		addr = locks[SDP_DISABLE].addr;
		if (efuse->force || user_confirmation_lock(&locks[SDP_DISABLE]))
			ret = _write(efuse->file, (uint8_t*) &data, addr, 1);
		else
			goto efuse_io_lock_ret_abort;

		if (ret)
			goto efuse_io_lock_ret_fail;
	}

	if (lockopts.jtag) {
		data = BIT(locks[SJC_DISABLE].bit);
		addr = locks[SJC_DISABLE].addr;
		if (efuse->force || user_confirmation_lock(&locks[SJC_DISABLE]))
			ret = _write(efuse->file, (uint8_t*) &data, addr, 1);
		else
			goto efuse_io_lock_ret_abort;

		if (ret)
			goto efuse_io_lock_ret_fail;
	}

	return 0;

efuse_io_lock_ret_abort:
	printf("Burn efuse aborted.\n");
efuse_io_lock_ret_fail:
	return ret;
}

void efuse_io(struct efuse_data *efuse, enum efuse_op_flag opflag)
{
	fusemap_t *fuse;
	int ret;
	uint8_t *data = NULL;

	for (efuse->reg_current = 0; efuse->reg_current < EFUSE_REGS_END; efuse->reg_current++) {
		fuse = get_fusemap(efuse);
		if (!fuse->is_active)
			continue;

		switch (opflag) {
			case IO_READ:
				data = calloc(1, fuse->size*sizeof(char));
				if (data == NULL) {
					perror("calloc");
					return;
				}

				ret = fuse->read ? fuse->read(efuse, (uint32_t*)data)
						: efuse_read(efuse, data);
				if (ret < 0) {
					printf("Failed to read %s\n", fuse->name);
				} else {
					printf("%s: ", fuse->name);
					if (! strcmp(fuse->name, "SRK") ) {
						for (int i = 0; i < fuse->size; i=i+2)
							printf("%.2x%.2x", *(uint8_t*)(data+i),*(uint8_t*)(data+i+1));
					} else if (! strcmp(fuse->name, "MAC") ) {
						for (int i = 5; i >= 0; i--)
							printf("%.2x", *(uint8_t*)(data+i));
					} else {
						for (int i = 0; i < fuse->size; i=i+1)
							printf("%.2x ", *(uint8_t*)(data+i));
					}
					printf("\n");
				}

				if (data)
					free(data);
				break;
			case IO_WRITE:
				printf("%s: Write operation\n", fuse->name);

				if (fuse->write) {
					ret = fuse->write(efuse, (uint8_t*)fuse->arg);
				} else {
					str_to_hex((char*)efuse->hexbin.byte, fuse->arg,
							(fuse->size == 1) ? fuse->size : fuse->size<<1);
					ret = efuse_write(efuse, efuse->hexbin.byte);
				}
				break;
			default:
				break;
		}
	}

	if (opflag == IO_LOCK) {
		ret = efuse_io_lock(efuse);
	}
//efuse_io_exit:
}

struct efuse_data * efuse_data_init(void)
{
	struct efuse_data *efuse_data;

	efuse_data = calloc(1, sizeof(struct efuse_data));
	if (efuse_data == NULL) {
		perror("Failed to allocate memory");
		goto efuse_init_ret;
	}

	efuse_data->reg_current = 0;
	efuse_data->force = false;
	efuse_data->soc_data = get_soc_data();

	if (efuse_data->soc_data == NULL) {
		printf("Cannot get SOC type. Using i.MX6ULL as default fuse base\n");
		efuse_data->soc_data = &socs[0];
	}

efuse_init_ret:
	return efuse_data;
}

const struct option efuseopts[] = {
	{"hash", optional_argument, 0, 'k'},
	{"mac", optional_argument, 0, 'm'},
	{"revoke", optional_argument, 0, 'r'},
	{"file", required_argument, 0, 'f'},
	{"force", no_argument, 0, 'y'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'v'},
	{"secureboot", no_argument, &lockopts.secureboot, true},
	{"sdp", no_argument, &lockopts.sdp, true},
	{"jtag", no_argument, &lockopts.jtag, true},
	{0}
};

int main(int argc, char** argv)
{
	int opt;
	int efuseoptind;
	char *nvmem = NULL;
	enum efuse_op_flag ioflag = false;
	int size;
	int return_code=0;

	if (argc < 2) {
		printf("Too few arguments\n");
		print_help();
		exit(EXIT_FAILURE);
	}

	if (!strcmp(argv[1], "read"))
		ioflag = IO_READ;
	else if (!strcmp(argv[1], "write"))
		ioflag = IO_WRITE;
	else if (!strcmp(argv[1], "lock"))
		ioflag = IO_LOCK;

	efuse = efuse_data_init();
	if (!efuse)
		return EXIT_FAILURE;

	const char *opts = "k::m::r::f:S:yhv";
	while((opt = getopt_long(argc, argv, opts, efuseopts, &efuseoptind)) != -1) {
		switch(opt) {
			case 'k':;
				switch_entry(SRK)
				break;
			case 'm':;
				switch_entry(MAC)
				break;
			case 'f':;
				fusemap_t *fuse = &efuse->soc_data->fuses[SRK];
				fuse->arg = strdup(optarg);
				if (!fuse->arg) {
					printf("Cannot allocate memory\n");
					goto main_free_file;
				}
				fuse->is_active = true;
				fuse->write = efuse_hashfile_update;
				break;
			case 'r':;
				switch_entry(REVOKE);
				break;
			case 'y':
				efuse->force = true;
				break;
			case 0:
				break;
			case 'h':
				print_help();
				goto main_free_mem;
				break;
			case 'v':
				printf("Version: %s\n",EFUSEMEM_VERSION_STRING);
			default:
				goto main_free_mem;
				break;
		}
	}

	nvmem = (optind == argc || !argv[optind+1])
			? strdup("/sys/bus/nvmem/devices/imx-ocotp0/nvmem")
			: strdup(argv[optind+1]);
	if (!nvmem) {
		printf("Cannot allocate memory\n");
		return_code = EXIT_FAILURE;
		goto main_free_file;
	}

	//printf("fuse device: %s\n", nvmem);

	efuse->file = fopen(nvmem, "r+b");
	if (efuse->file == NULL) {
		perror("fopen");
		return_code = EXIT_FAILURE;
		goto main_exit;
	}

	//printf("Soc name: %s\n", efuse->soc_data->soc_name);

	/* Read lock status registers */
	size = _read(efuse->file, (uint8_t*)&efuse->lockstat, 0, 4);
	//printf("lockstats: %x\n", efuse->lockstat);

	efuse_io(efuse, ioflag);

	if (fclose(efuse->file) == EOF) {
		perror("fclose");
		return_code = EXIT_FAILURE;
		goto main_free_file;
	}

main_free_file:
	if (nvmem)
		free(nvmem);

main_free_mem:
	for(fusemap_t *fuse = efuse->soc_data->fuses; fuse->name; fuse++) {
		if (fuse->arg)
			free(fuse->arg);
	}

	if (efuse)
		free(efuse);
main_exit:
	return return_code;
}
