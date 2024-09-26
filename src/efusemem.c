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

#define BIT(n) (0x1UL << (n))
#define BITMAP(x, n)	(x << n)

#define _BANK(x)	((x) << 5)
#define _WORD(x)	((x) << 2)
#define BANK_WORD_OFFSET(x, y)	(_BANK(x) + _WORD(y))

#define OCOTP_REVOKE(x)	((1 << x) & 0xf)

/* CFG5 register */
#define CFG5_SEC_CONFIG		BIT(1)
#define CFG5_SDP_DISABLE	BIT(17)
#define	CFG5_SJC_DISABLE	BIT(20)
#define CFG5_WDOG_ENABLE	BIT(21)
#define CFG5_JTAG_SMODE		BITMAP(3, 22)

#define add_fuse(_name, _reg, _size, _lock, _read, _write)	\
	{.name = _name, .reg = _reg, .size = _size, 0,	\
	 .lockbit = _lock, .read = _read, .write = _write, NULL, false}

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
	struct fusemap * fuse##_opt = &efuse->fuses[_opt]; \
	_fuse_init(fuse##_opt)

enum efuse_regs {
	CFG5,
	SRK,
	MAC,
	REVOKE,
	EFUSE_REGS_END
};

struct efuse_data;

struct fusemap {
	const char *name;
	uint32_t reg;
	uint8_t size;
	uint8_t access_flags;
	uint8_t lockbit;
	char *arg;
	int (*read)(struct efuse_data *, uint32_t *);
	int (*write)(struct efuse_data *, uint8_t *);
	int (*misc_func)(struct efuse_data *);
	bool is_active;
};

struct efuse_lock_options_s {
	int secureboot;
	int sdp;
	int jtag;
} efuse_lock_options_default = {0, 0, 0};

typedef struct efuse_lock_options_s efuse_lock_options;

struct efuse_data {
	struct fusemap *fuses;
	enum efuse_regs reg_current;
	union hashval {
		uint8_t byte[32];
		uint32_t word[8];
		uint64_t lword[4];
	} hexbin;
	uint32_t lockstat;
	int fd;
	bool force;
};

enum efuse_flags {
	EFUSE_HASH_WRITE,
	EFUSE_HASH_READ,
	EFUSE_REVOKE_WRITE,
	EFUSE_REVOKE_READ,
	EFUSE_END
};

enum efuse_op_flag {
	IO_READ,
	IO_WRITE,
	IO_LOCK
};

static efuse_lock_options lockopt;

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
		 "  -v --version    print version of the program\n"
		 "  path to nvmem\n"
		 "  for i.MX6UL: /sys/bus/nvmem/devices/imx-ocotp0/nvmem\n"
	);
	//printf("\tl:	Lock hash\n");
	//printf("\tu:	Unlock hash\n");
}

static struct efuse_data *efuse;

void str_to_hex(char *dest, char *src, size_t n)
{
	char c;

	int i;
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

static int _read(int fd, uint8_t *buf, int offset, size_t len)
{
	int size;
	lseek(fd, offset, SEEK_SET);

	size = read(fd, buf, len);
	if (size < 0) {
		perror("Error");
		return errno;
	}
	return size;
}

static int _write(int fd, uint8_t *buf, int offset, int len)
{
	int size;
	lseek(fd, offset, SEEK_SET);

	size = write(fd, buf, len);
	if (size < 0) {
		perror("Error");
		return errno;
	}
	return size;
}

int read_hash_from_file(struct efuse_data *efuse, char *file)
{
	struct fusemap *fuse = &efuse->fuses[efuse->reg_current];
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

	printf("This will irrecoverably burn the value ");

	for (i = 0; i < len; i++)
		printf("%.2x ", data[i]);

	printf(" to address 0x%x. Do you want to continue? [Y/N]: ", reg);

	ret = scanf("%c", &input);

	ret = input == 'y' || input == 'Y' ? 1 : 0;

	return ret;
}

int efuse_read(struct efuse_data *efuse, uint8_t *buf)
{
	struct fusemap *fuse = &efuse->fuses[efuse->reg_current];
	int ret;

	ret = _read(efuse->fd, (uint8_t*)buf, fuse->reg, fuse->size);

	return ret < 0 ? ret : 0;
}

int efuse_write(struct efuse_data *efuse, uint8_t *buf)
{
	struct fusemap *fuse = &efuse->fuses[efuse->reg_current];
	int ret;

	if (efuse->force || user_confirmation(buf, fuse->reg, fuse->size)) {
		ret = _write(efuse->fd, buf, fuse->reg, fuse->size);
		printf("Done!\n");
	} else {
		printf("Burn efuse aborted. \n");
	}

	return ret;
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

	return 0;
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
	add_fuse("CFG5", BANK_WORD_OFFSET(0, 6), 4, 100, NULL, NULL),
	add_fuse("SRK", BANK_WORD_OFFSET(3, 0), 32, 14, NULL, NULL),
	add_fuse("MAC", BANK_WORD_OFFSET(4, 2), 6, 8, NULL, NULL),
	add_fuse("Revoke", BANK_WORD_OFFSET(5, 7), 1, 100, efuse_revoke_status, efuse_revoke_update),
	{NULL}
};

void efuse_io(struct efuse_data *efuse, enum efuse_op_flag opflag)
{
	struct fusemap *fuse;
	int ret;
	uint8_t *data = NULL;

	for (efuse->reg_current = 0; efuse->reg_current < EFUSE_REGS_END; efuse->reg_current++) {
		fuse = &efuse->fuses[efuse->reg_current];
		if (!fuse->is_active)
			continue;

		data = calloc(1, fuse->size*sizeof(char));
		if (data == NULL) {
			perror("Error");
			return;
		}
		if (opflag == IO_READ) {
			ret = fuse->read ? fuse->read(efuse, (uint32_t*)data)
							: efuse_read(efuse, data);
			if (ret < 0) {
				printf("Failed to read %s\n", fuse->name);
				goto efuse_io_exit;
			}

			printf("%s: ", fuse->name);
			for (int i = 0; i < fuse->size; i++)
				printf("%.2x ", *(uint8_t*)(data+i));
			printf("\n");
		} else if (opflag == IO_WRITE) {
			printf("%s: Write operation\n", fuse->name);

			if (fuse->write) {
				ret = fuse->write(efuse, (uint8_t*)fuse->arg);
			} else {
				str_to_hex((char*)efuse->hexbin.byte, fuse->arg,
						(fuse->size == 1) ? fuse->size : fuse->size<<1);
				ret = efuse_write(efuse, efuse->hexbin.byte);
			}
		}
efuse_io_exit:
		if (data)
			free(data);
	}
}

/*
 * @TODO - Rework the lock function
 * This hardcoded stuff was only written on demand. Think of a
 * generic approch, instead
 */
void efuse_io_lock(struct efuse_data *efuse)
{
	uint32_t reg_lock = 0, reg_cfg5 = 0;
	int reg;

	printf("%s\n", __func__);
	printf("jtag: %d\n", lockopt.jtag);
	if (lockopt.secureboot) {
		_read(efuse->fd, (uint8_t*)&reg_lock, 0, 4);
		reg_lock |= BIT(14); // SRK_LOCK

		_read(efuse->fd, (uint8_t*)&reg_cfg5, BANK_WORD_OFFSET(0, 6), 4);
		reg_cfg5 |= BITMAP(2, 1); // SEC_CONFIG (1x -> security on)
		reg = BANK_WORD_OFFSET(0, 6);
	}
	if (lockopt.sdp) {
		if (!reg_cfg5)
			_read(efuse->fd, (uint8_t*)&reg_cfg5, BANK_WORD_OFFSET(0, 6), 4);
		reg_cfg5 |= BIT(17); // SDP_DISABLE
		reg = BANK_WORD_OFFSET(0, 6);
	}
	if (lockopt.jtag) {
		if (!reg_cfg5)
			_read(efuse->fd, (uint8_t*)&reg_cfg5, BANK_WORD_OFFSET(0, 6), 4);
		reg_cfg5 |= BIT(20); // SJC_DISABLE
		reg = BANK_WORD_OFFSET(0, 6);
	}

	if (reg_lock) {
		if (efuse->force || user_confirmation((uint8_t*)&reg_lock, reg, 4)) {
		_write(efuse->fd, (uint8_t*)&reg_lock, 0, 4);
		} else {
			goto efuse_io_lock_ret_fail;
		}
	}

	if (reg_cfg5) {
		if (efuse->force || user_confirmation((uint8_t*)&reg_cfg5, reg, 4)) {
			_write(efuse->fd, (uint8_t*)&reg_cfg5, reg, 4);
		} else {
			goto efuse_io_lock_ret_fail;
		}
	}

	printf("Done!\n");
	return;

efuse_io_lock_ret_fail:
	printf("Burn efuse aborted.\n");
}

struct efuse_data * efuse_data_init(struct fusemap *fuses)
{
	struct efuse_data *efuse_data;

	efuse_data = calloc(1, sizeof(struct efuse_data));
	if (efuse_data == NULL) {
		perror("Failed to allocate memory");
		goto efuse_init_ret;
	}

	efuse_data->reg_current = 0;
	efuse_data->force = false;
	efuse_data->fuses = fuses;

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
	{"secureboot", no_argument, &lockopt.secureboot, true},
	{"sdp", no_argument, &lockopt.sdp, true},
	{"jtag", no_argument, &lockopt.jtag, true},
	{0}
};

int main(int argc, char** argv)
{
	int opt;
	int efuseoptind;
	char *ofile = NULL;
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
	
	efuse = efuse_data_init(imx6ull_fuses);
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
				struct fusemap *fuse = &efuse->fuses[SRK];
				fuse->arg = strdup(optarg);
				if (!fuse->arg) {
					printf("Cannot allocate memory\n");
					goto free_file;
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

	if (optind == argc || !argv[optind+1]) {
		printf("path to nvmem is missing\n");
		print_help();
		return_code = EXIT_FAILURE;
		goto main_free_mem;
	}

	ofile = strdup(argv[optind+1]);
	if (!ofile) {
		printf("Cannot allocate memory\n");
		return_code = EXIT_FAILURE;
		goto free_file;
	}

	printf("fuse device: %s\n", ofile);

	efuse->fd = open(ofile, O_RDWR, 0);
	if (efuse->fd < 0) {
		perror("Error");
		return_code = EXIT_FAILURE;
		goto main_exit;
	}

	/* Read lock status registers */
	size = _read(efuse->fd, (uint8_t*)&efuse->lockstat, 0, 4);
	printf("lockstat: %x\n", efuse->lockstat);

	if (ioflag == IO_LOCK)
		efuse_io_lock(efuse);
	else
		efuse_io(efuse, ioflag);

	if (close(efuse->fd) < 0) {
		perror("Error");
		return_code = EXIT_FAILURE;
		goto free_file;
	}

free_file:
	if (ofile)
		free(ofile);

main_free_mem:
	for(struct fusemap *fuse = efuse->fuses; fuse->name; fuse++) {
		if (fuse->arg)
			free(fuse->arg);
	}

	if (efuse)
		free(efuse);
main_exit:
	return return_code;
}
