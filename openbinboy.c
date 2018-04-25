/* (C) 2018 [anp/hsw]; Licensed under GPLv2 or later; mailto:sysop@880.ru */
/* crc32 code (C) openssh team */
/* hexDump code taken from public stackoverflow forums for debugging only (unknown license?) */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <getopt.h>
#include <time.h>		/* strftime */

#ifdef WIN32
# include <winsock2.h>		/* you will also need to link to ws2_32 library */
#else
# include <arpa/inet.h>
#endif

/* print value with offset in structure */
#define OFFSET_PRINT(x,y) (size_t)&x.y - (size_t)&x, x.y
#define OFFSET_PRINT_STRING(x,y) (size_t)&x.y - (size_t)&x, x.y

/* global swicthes for options */
int opt_info=0, opt_extract=0, opt_assemble=0, opt_oldcrc=0;
int opt_bigendian=0;

size_t next_unit_pos=0; // source file position for recursive checking of headers

// non-static options used during image creation
typedef struct firmware_params {
	uint32_t kern_load_addr;	// 0x80000000
	uint32_t kern_entry;		// kernel entry point - 0x80000000
	char devid[16];			// actual size is 12 (or 14 if padding0 is wrongly detected)
	unsigned int devid_bin;

        uint32_t bootloader_offset;
        uint32_t bootloader_part_size;
        uint32_t kernel_offset;
        uint32_t kernel_part_size;
        uint32_t rootfs_offset;
        uint32_t rootfs_part_size;
        uint32_t branding_offset;
        uint32_t branding_part_size;
} firmware_params_t;

typedef struct unit_header {
	/* firmware part, not flashed */
	char devid[12];			// device id like "LVA6E3804001"
	char padding0[2];
	uint16_t payload_crc16;		// jboot checksum of payload
	char padding1[8];
	uint32_t blocksize;		// always 0x10000
	uint32_t timestamp;		// (unixtime - 0x35016f00) / 4
	uint32_t flashpos1;		// absolute position in flash to write (#1)
	uint32_t partition_size;	// partition size (count of bytes to erase on flash)
	uint32_t flashpos2;		// absolute position in flash to write (#2)
	uint32_t payload_size;		// squashfs size / kernel header + kernel size
	char padding3[16];
	uint32_t magic;			// always 0x00024842
	uint32_t type;			// maybe bit mask? (0x00010000 - bootloader, 0x04040000 - kernel, 0x00080000 - rootfs, 0x00050000 / 0x04050000 - branding)
	char padding4[4];
	uint16_t devid_bin;		// device id? (38 6E for LVA6E3804001 and TLW6E3804001 / 24 6E for DLK6E2414001)
	uint16_t header_crc16;		// inverted jboot checksum of whole header with checksum field zeroed
} unit_header_t;

// magic for container type detection
#define MAGIC_BOOTLOADER	0x00010000
#define MAGIC_KERNEL		0x04040000
#define MAGIC_ROOTFS		0x00080000
#define MAGIC_BRANDING		0x00050000
#define MAGIC_BRANDING2		0x04050000
// static header magic
#define MAGIC_UNIT		0x00024842

// firmware defaults
#define BLOCKSIZE		0x00010000
#define DEFAULT_DEVID		"LVA6E3804001"
#define DEFAULT_DEVID_BIN	0x6e38
#define DEFAULT_KERN_LOAD	0x80000000 // kernel load address
#define DEFAULT_KERN_ENTRY	0x80000000 // kernel entry point

#define FLASH_BASE		0xbc000000 // flash address space start
#define DEFAULT_KERNEL_PTR	0x00010000
#define DEFAULT_ROOTFS_PTR	0x00180000
#define DEFAULT_BRANDING_PTR	0x00f10000

typedef struct kernel_header {
	/* kernel image part, flashed */
	uint32_t magic;			// FF 04 24 2B
	uint32_t timestamp;		// (unixtime - 0x35016f00) / 4
	uint32_t ksize2;		// size of kernel conatiner from magic2 to end of payload
	uint16_t kern_crc16;		// jboot_crc16 from magic2 to end of payload
	uint16_t hdr_crc16;		// ~jboot_crc16 from magic to hdr_crc16
	uint32_t magic2;		// 24 21 03 02
	uint32_t kern_load_addr;	// 0x80000000
	uint32_t kern_size;		// kernel payload size
	uint32_t kern_crc32;		// kernel payload crc - htonl(apple_crc32(x)))
	uint32_t kern_entry;		// kernel entry point - 0x80000000
	uint32_t rootfs_load_addr;	// 0xBC180000 (0xBC000000 == flash base)
	uint32_t rootfs_size;		// rootfs payload size
	uint32_t rootfs_crc32;		// rootfs payload crc
	uint32_t hdr_crc32;		// crc32 from magic2 to magic3 with zeroed crc field
	uint32_t magic3;		// 28 00 00 00
} kernel_header_t;


typedef struct branding_header {
	/* branding image part, not exist on TLW6E3804001 and new versions of LVA6E3804001, always on dlink and zyxel */
	uint32_t magic;			// FF 05 24 2B
	uint32_t timestamp;		// (unixtime - 0x35016f00) / 4 (little endian on ZXL6E2425001, big endian on others)
	uint32_t payload_size;		// branding payload size       (little endian on ZXL6E2425001, big endian on others)
	uint16_t payload_crc16;		// jboot_crc16 of payload
	uint16_t hdr_crc16;		// ~jboot_crc16 from magic to hdr_crc16 with "FF 05 24 2B" replaced to "05 05 24 2B"
} branding_header_t;

/* crc32 from openssh */
static const uint32_t crc32tab[] = {
        0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL,
        0x076dc419L, 0x706af48fL, 0xe963a535L, 0x9e6495a3L,
        0x0edb8832L, 0x79dcb8a4L, 0xe0d5e91eL, 0x97d2d988L,
        0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L, 0x90bf1d91L,
        0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
        0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L,
        0x136c9856L, 0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL,
        0x14015c4fL, 0x63066cd9L, 0xfa0f3d63L, 0x8d080df5L,
        0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L, 0xa2677172L,
        0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
        0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L,
        0x32d86ce3L, 0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L,
        0x26d930acL, 0x51de003aL, 0xc8d75180L, 0xbfd06116L,
        0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L, 0xb8bda50fL,
        0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
        0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL,
        0x76dc4190L, 0x01db7106L, 0x98d220bcL, 0xefd5102aL,
        0x71b18589L, 0x06b6b51fL, 0x9fbfe4a5L, 0xe8b8d433L,
        0x7807c9a2L, 0x0f00f934L, 0x9609a88eL, 0xe10e9818L,
        0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
        0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL,
        0x6c0695edL, 0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L,
        0x65b0d9c6L, 0x12b7e950L, 0x8bbeb8eaL, 0xfcb9887cL,
        0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L, 0xfbd44c65L,
        0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
        0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL,
        0x4369e96aL, 0x346ed9fcL, 0xad678846L, 0xda60b8d0L,
        0x44042d73L, 0x33031de5L, 0xaa0a4c5fL, 0xdd0d7cc9L,
        0x5005713cL, 0x270241aaL, 0xbe0b1010L, 0xc90c2086L,
        0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
        0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L,
        0x59b33d17L, 0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL,
        0xedb88320L, 0x9abfb3b6L, 0x03b6e20cL, 0x74b1d29aL,
        0xead54739L, 0x9dd277afL, 0x04db2615L, 0x73dc1683L,
        0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
        0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L,
        0xf00f9344L, 0x8708a3d2L, 0x1e01f268L, 0x6906c2feL,
        0xf762575dL, 0x806567cbL, 0x196c3671L, 0x6e6b06e7L,
        0xfed41b76L, 0x89d32be0L, 0x10da7a5aL, 0x67dd4accL,
        0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
        0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L,
        0xd1bb67f1L, 0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL,
        0xd80d2bdaL, 0xaf0a1b4cL, 0x36034af6L, 0x41047a60L,
        0xdf60efc3L, 0xa867df55L, 0x316e8eefL, 0x4669be79L,
        0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
        0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL,
        0xc5ba3bbeL, 0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L,
        0xc2d7ffa7L, 0xb5d0cf31L, 0x2cd99e8bL, 0x5bdeae1dL,
        0x9b64c2b0L, 0xec63f226L, 0x756aa39cL, 0x026d930aL,
        0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
        0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L,
        0x92d28e9bL, 0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L,
        0x86d3d2d4L, 0xf1d4e242L, 0x68ddb3f8L, 0x1fda836eL,
        0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L, 0x18b74777L,
        0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
        0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L,
        0xa00ae278L, 0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L,
        0xa7672661L, 0xd06016f7L, 0x4969474dL, 0x3e6e77dbL,
        0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L, 0x37d83bf0L,
        0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
        0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L,
        0xbad03605L, 0xcdd70693L, 0x54de5729L, 0x23d967bfL,
        0xb3667a2eL, 0xc4614ab8L, 0x5d681b02L, 0x2a6f2b94L,
        0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL, 0x2d02ef8dL
};

uint32_t apple_crc32(const void *buf,  size_t size, uint32_t crc)
{
    const uint8_t *p;

    p = buf;
    crc = crc ^ ~0U;

    while (size--)
        crc = crc32tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);

    return crc ^ ~0U;
}

uint16_t jboot_crc16(void *data, int size, uint16_t start_val)
{
  uint32_t counter;
  uint16_t  *ptr;

  counter = start_val;
  ptr = data;
  while ( size > 1 )
  {
    counter += *ptr;
    ++ptr;
    while ( counter >> 16 )
      counter = (uint16_t) counter + (counter >> 16);
    size -= 2;
  }
  if ( size > 0 )
    counter += *(uint8_t *)ptr;
  while ( counter >> 16 )
    counter = (uint16_t) counter + (counter >> 16);
  return counter;
}

void hexDump (char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).
    
        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}


void unit_header_print(unit_header_t unit_header) {
    printf("\n");
    printf("Header information (original order is little endian):\n");
    printf("-- Device information:\n");
    printf("0x%04x, device ID (text)              : %s\n",   		OFFSET_PRINT_STRING(unit_header, devid));
    hexDump("padding 0", &unit_header.padding0, sizeof(unit_header.padding0));
    printf("0x%04x, jboot crc16 of payload        : 0x%04x\n",		OFFSET_PRINT(unit_header, payload_crc16));
    hexDump("padding 1", &unit_header.padding1, sizeof(unit_header.padding1));
    printf("0x%04x, blocksize                     : 0x%08x, %u\n",	OFFSET_PRINT(unit_header, blocksize), unit_header.blocksize);
    printf("0x%04x, timestamp (raw)               : 0x%08x\n",		OFFSET_PRINT(unit_header, timestamp));
    printf("        timestamp (decoded, unixtime) : %u\n", (unit_header.timestamp * 4) + 0x35016f00);
    printf("0x%04x, flash position #1             : 0x%08x, %u\n",	OFFSET_PRINT(unit_header, flashpos1), unit_header.flashpos1);
    printf("0x%04x, partition size                : 0x%08x, %u\n",	OFFSET_PRINT(unit_header, partition_size), unit_header.partition_size);
    printf("0x%04x, flash position #2             : 0x%08x, %u\n",	OFFSET_PRINT(unit_header, flashpos2), unit_header.flashpos2);
    printf("0x%04x, payload size                  : 0x%08x, %u\n",	OFFSET_PRINT(unit_header, payload_size), unit_header.payload_size);
    hexDump("padding 3", &unit_header.padding3, sizeof(unit_header.padding3));
    printf("0x%04x, magic                         : 0x%08x\n",		OFFSET_PRINT(unit_header, magic));
    printf("0x%04x, container type                : 0x%08x\n",		OFFSET_PRINT(unit_header, type));
    hexDump("padding 4", &unit_header.padding4, sizeof(unit_header.padding4));
    printf("0x%04x, device ID (binary)            : 0x%04x\n",		OFFSET_PRINT(unit_header, devid_bin));
    printf("0x%04x, jboot crc16 of header         : 0x%04x\n",		OFFSET_PRINT(unit_header, header_crc16));
};

void kernel_header_print(kernel_header_t kernel_header) {
    printf("\n");
    printf("0x%04x, magic                         : 0x%08x\n",		OFFSET_PRINT(kernel_header, magic));
    printf("0x%04x, timestamp (raw)               : 0x%08x\n",		OFFSET_PRINT(kernel_header, timestamp));
    printf("        timestamp (decoded, unixtime) : %u\n", (kernel_header.timestamp * 4) + 0x35016f00);
    printf("0x%04x, ksize2                        : 0x%08x, %u\n",	OFFSET_PRINT(kernel_header, ksize2), kernel_header.ksize2);
    printf("0x%04x, kernel_crc16                  : 0x%04x\n",		OFFSET_PRINT(kernel_header, kern_crc16));
    printf("0x%04x, header_crc16                  : 0x%04x\n",		OFFSET_PRINT(kernel_header, hdr_crc16));
    printf("0x%04x, magic2                        : 0x%08x\n",		OFFSET_PRINT(kernel_header, magic2));
    printf("0x%04x, kern_load_addr                : 0x%08x\n",		OFFSET_PRINT(kernel_header, kern_load_addr));
    printf("0x%04x, kern_size                     : 0x%08x, %u\n",	OFFSET_PRINT(kernel_header, kern_size), kernel_header.kern_size);
    printf("0x%04x, kern_crc32                    : 0x%08x\n",		OFFSET_PRINT(kernel_header, kern_crc32));
    printf("0x%04x, kern_entry                    : 0x%08x\n",		OFFSET_PRINT(kernel_header, kern_entry));
    printf("0x%04x, rootfs_load_addr              : 0x%08x\n",		OFFSET_PRINT(kernel_header, rootfs_load_addr));
    printf("0x%04x, rootfs_size                   : 0x%08x, %u\n",	OFFSET_PRINT(kernel_header, rootfs_size), kernel_header.rootfs_size);
    printf("0x%04x, rootfs_crc32                  : 0x%08x\n",		OFFSET_PRINT(kernel_header, rootfs_crc32));
    printf("0x%04x, hdr_crc32                     : 0x%08x\n",		OFFSET_PRINT(kernel_header, hdr_crc32));
    printf("0x%04x, magic3                        : 0x%08x\n",		OFFSET_PRINT(kernel_header, magic3));
};

void branding_header_print(branding_header_t branding_header) {
    printf("\n");
    if (opt_bigendian) printf("** Big endian option specified!!\n");
    printf("0x%04x, magic                         : 0x%08x\n",		OFFSET_PRINT(branding_header, magic));
    printf("0x%04x, timestamp (raw)               : 0x%08x\n",		OFFSET_PRINT(branding_header, timestamp));
 if (opt_bigendian) {
    printf("        timestamp (decoded, unixtime) : %u\n", (htonl(branding_header.timestamp) * 4) + 0x35016f00);
    printf("0x%04x, payload size                  : 0x%08x, %u\n",	OFFSET_PRINT(branding_header, payload_size), htonl(branding_header.payload_size));
 } else {
    printf("        timestamp (decoded, unixtime) : %u\n", (branding_header.timestamp * 4) + 0x35016f00);
    printf("0x%04x, payload size                  : 0x%08x, %u\n",	OFFSET_PRINT(branding_header, payload_size), branding_header.payload_size);
 }
    printf("0x%04x, payload_crc16                 : 0x%04x\n",		OFFSET_PRINT(branding_header, payload_crc16));
    printf("0x%04x, header_crc16                  : 0x%04x\n",		OFFSET_PRINT(branding_header, hdr_crc16));
};

int data_extract(unsigned char* extract_ptr, size_t extract_size, char name[]) {
	printf("--\n");
	printf("Extracting unit %s payload at position %zu, size %zu ...\n\n", name, next_unit_pos, extract_size);

	FILE* fd_extract = fopen(name,"wb");
	if (fd_extract == 0) {
	    perror("Cannot open unit file for write");
	    return 100;
	}
	fseek(fd_extract, 0, SEEK_SET);
	fwrite(extract_ptr, extract_size, 1, fd_extract);
	fclose(fd_extract);
	return 0;
}

int kernel_sanity_check(unsigned char *src_mem, size_t input_size) {
    int retcode = 0;

    kernel_header_t kernel_header;
    memcpy(&kernel_header, src_mem, sizeof(kernel_header)); // fill unit header from input

    // print header information
    kernel_header_print(kernel_header);

    size_t calc_data_size = sizeof(kernel_header) + kernel_header.kern_size;

    printf("-- Container checks:\n");
    printf("Maximum data size of unit   ");
    if (calc_data_size <= input_size) {
	printf("OK        : %zu bytes\n", calc_data_size);
    } else {
	printf("MISMATCH  : ***** calculated %zu bytes, filesize %zu bytes\n", calc_data_size, input_size);
	retcode+=100;
    }

    // data size mismatch is fatal error!
    if (retcode > 0) goto exit;

    uint32_t calc_kernel_crc = apple_crc32(src_mem + sizeof(kernel_header), kernel_header.kern_size, 0);
    uint32_t calc_rootfs_crc = apple_crc32(src_mem + sizeof(kernel_header) + kernel_header.kern_size + sizeof(unit_header_t), kernel_header.rootfs_size, 0);

    // make copy of header for wierd crc16 calculations
    size_t crc16_area2_size	= (size_t)&kernel_header.hdr_crc16 - (size_t)&kernel_header.magic;

    uint8_t *hdrcopy16 = malloc(crc16_area2_size);

    memcpy(hdrcopy16, src_mem, crc16_area2_size);
    memset(hdrcopy16, 0x04, 1); // replace 0xFF in firmware header to 0x04 found in actual flash dump

    uint16_t calc_hdr_crc16 = ~jboot_crc16(hdrcopy16, crc16_area2_size, 0);
    free(hdrcopy16);
    // crc16 of header finished

    // crc16 of kernel containter start
    size_t crc16_area3_offset	= (size_t)&kernel_header.magic2 - (size_t)&kernel_header.magic;

    uint16_t calc_kern_crc16 = jboot_crc16(src_mem + crc16_area3_offset, kernel_header.ksize2, 0);
    if (opt_oldcrc) calc_kern_crc16 -= 0x00FF; // old jboot crc
    // crc16 of kernel containter finished

    // make copy of header for crc32 calculations
    size_t crc32_area2_size	= (size_t)&kernel_header.magic3 - (size_t)&kernel_header.magic2 + sizeof(kernel_header.hdr_crc32);

    uint8_t *hdrcopy32 = malloc(crc32_area2_size);

    memcpy(hdrcopy32, src_mem + crc16_area3_offset, crc32_area2_size);
    memset(hdrcopy32 + 0x20, 0x00, 4); // wipe out stored CRC for calculations

    uint32_t calc_hdr_crc32 = apple_crc32(hdrcopy32, crc32_area2_size, 0);
    free(hdrcopy32);
    // crc32 of header finished

    printf("-- CRC calculations:\n");
    printf("Kernel calculated checksum ");
    if (calc_kernel_crc == kernel_header.kern_crc32) {
	printf("OK         : 0x%08x\n", calc_kernel_crc);
    } else {
	printf("MISMATCH   : ***** calc 0x%08x, header 0x%08x\n", calc_kernel_crc, kernel_header.kern_crc32);
	retcode++;
    }

    printf("RootFS calculated checksum ");
    if (calc_rootfs_crc == kernel_header.rootfs_crc32) {
	printf("OK         : 0x%08x\n", calc_rootfs_crc);
    } else {
	printf("MISMATCH   : ***** calc 0x%08x, header 0x%08x\n", calc_rootfs_crc, kernel_header.rootfs_crc32);
	retcode++;
    }

    printf("HDR-16 calculated checksum ");
    if (calc_hdr_crc16 == kernel_header.hdr_crc16) {
	printf("OK         : 0x%04x\n", calc_hdr_crc16);
    } else {
	printf("MISMATCH   : ***** calc 0x%04x, header 0x%04x\n", calc_hdr_crc16, kernel_header.hdr_crc16);
	retcode++;
    }

    printf("KRN-16 calculated checksum ");
    if (calc_kern_crc16 == kernel_header.kern_crc16) {
	printf("OK         : 0x%04x\n", calc_kern_crc16);
    } else {
	printf("MISMATCH   : ***** calc 0x%04x, header 0x%04x\n", calc_kern_crc16, kernel_header.kern_crc16);
	retcode++;
    }

    printf("HDR-32 calculated checksum ");
    if (calc_hdr_crc32 == kernel_header.hdr_crc32) {
	printf("OK         : 0x%08x\n", ntohl(calc_hdr_crc32));
    } else {
	printf("MISMATCH   : ***** calc 0x%08x, header 0x%08x\n", calc_hdr_crc32, kernel_header.hdr_crc32);
	retcode++;
    }

    exit:
    return retcode;
}

int branding_sanity_check(unsigned char *src_mem, size_t input_size) {
    int retcode = 0;

    branding_header_t branding_header;
    memcpy(&branding_header, src_mem, sizeof(branding_header)); // fill unit header from input

    if (branding_header.magic != 0x242b05ff &&
	branding_header.magic != 0x242b0505) {
	    printf("** Branding unit contains no magic, assuming raw data...\n");
	    goto exit;
    }

    // print header information
    branding_header_print(branding_header);

    size_t payload_size = opt_bigendian ? htonl(branding_header.payload_size) : branding_header.payload_size;
    size_t calc_data_size = sizeof(branding_header) + payload_size;

    printf("-- Container checks:\n");
    printf("Maximum data size of unit   ");
    if (calc_data_size <= input_size) {
	printf("OK        : %zu bytes\n", calc_data_size);
    } else {
	printf("MISMATCH  : ***** calculated %zu bytes, filesize %zu bytes\n", calc_data_size, input_size);
	retcode+=100;
    }

    // data size mismatch is fatal error!
    if (retcode > 0) goto exit;

    uint16_t calc_payload_crc16 = jboot_crc16(src_mem + sizeof(branding_header), payload_size, 0);

    // make copy of header for wierd crc16 calculations
    int crc16_area2_size	= sizeof(branding_header) - sizeof(branding_header.hdr_crc16);
    memset(&branding_header, 0x05, 1); // replace 0xFF in firmware header to 0x05 found in actual flash dump

    uint16_t calc_hdr_crc16 = ~jboot_crc16(&branding_header, crc16_area2_size, 0);
    // crc16 of header finished

    printf("Payload calculated crc16   ");
    if (calc_payload_crc16 == branding_header.payload_crc16) {
	printf("OK         : 0x%04x\n", calc_payload_crc16);
    } else {
	printf("MISMATCH   : ***** calc 0x%04x, header 0x%04x\n", calc_payload_crc16, branding_header.payload_crc16);
	retcode++;
    }

    printf("Header  calculated crc16   ");
    if (calc_hdr_crc16 == branding_header.hdr_crc16) {
	printf("OK         : 0x%04x\n", calc_hdr_crc16);
    } else {
	printf("MISMATCH   : ***** calc 0x%04x, header 0x%04x\n", calc_hdr_crc16, branding_header.hdr_crc16);
	retcode++;
    }

    exit:
    return retcode;
}

int unit_sanity_check(unsigned char *src_mem, size_t input_size) {
    int retcode = 0;
    char unit_filename[32];

    unit_header_t unit_header;
    memcpy(&unit_header, src_mem, sizeof(unit_header)); // fill unit header from input

    // print header information
    unit_header_print(unit_header);

    size_t calc_data_size = sizeof(unit_header) + unit_header.payload_size;

    printf("-- Container checks:\n");

    printf("Maximum data size of unit   ");
    if (calc_data_size <= input_size) {
	printf("OK        : %zu bytes\n", calc_data_size);
    } else {
	printf("MISMATCH  : ***** calculated %zu bytes, filesize %zu bytes\n", calc_data_size, input_size);
	retcode+=100;
    }

    printf("Payload ");
    if (unit_header.partition_size >= unit_header.payload_size) {
        printf("fits ");
    } else {
        printf("DOES NOT FIT ");
        retcode+=100;
    }
    printf("partition.\n");

    // data size mismatch is fatal error!
    if (retcode > 0) goto exit;

    uint16_t calc_payload_crc16 = jboot_crc16(src_mem + sizeof(unit_header), unit_header.payload_size, 0);

    if (opt_oldcrc &&
	(unit_header.type == MAGIC_KERNEL || unit_header.type == MAGIC_BOOTLOADER)
    ) calc_payload_crc16 -= 0x00FF; // old jboot crc

    printf("Payload calculated checksum ");
    if (calc_payload_crc16 == unit_header.payload_crc16) {
	printf("OK        : 0x%04x\n", calc_payload_crc16);
    } else {
	printf("MISMATCH  : ***** calc 0x%04x, header 0x%04x\n", calc_payload_crc16, unit_header.payload_crc16);
	retcode++;
    }

    // make copy of header for crc16 calculations
    unit_header_t hdrcopy16;
    memcpy(&hdrcopy16, &unit_header, sizeof(unit_header));
    hdrcopy16.header_crc16 = 0x0000; // clear CRC in firmware header
    uint16_t calc_header_crc16 = ~jboot_crc16(&hdrcopy16, sizeof(unit_header), 0);
    // crc16 of header finished

    printf("Header  calculated checksum ");
    if (calc_header_crc16 == unit_header.header_crc16) {
	printf("OK        : 0x%04x\n", calc_header_crc16);
    } else {
	printf("MISMATCH  : ***** calc 0x%04x, header 0x%04x\n", calc_header_crc16, unit_header.header_crc16);
	retcode++;
    }

    // detect container type
    switch (unit_header.type) {
	case MAGIC_KERNEL:
	    printf("---\n");
	    printf("Kernel header was detected (or start of firmware), parsing it...\n");

	    retcode += kernel_sanity_check(src_mem + sizeof(unit_header), input_size - sizeof(unit_header));

	    sprintf(unit_filename, "kernel.bin");

	    break;
	;;
	case MAGIC_BOOTLOADER:
	    printf("---\n");
	    printf("Bootloader unit was detected...\n");

	    sprintf(unit_filename, "bootloader.bin");

	    break;
	;;
	case MAGIC_ROOTFS:
	    printf("---\n");
	    printf("RootFS unit was detected...\n");

	    sprintf(unit_filename, "rootfs.bin");

	    break;
	;;
	case MAGIC_BRANDING:
	case MAGIC_BRANDING2:
	    printf("---\n");
	    printf("Branding unit was detected...\n");

	    retcode += branding_sanity_check(src_mem + sizeof(unit_header), input_size - sizeof(unit_header));

	    sprintf(unit_filename, "branding.bin");

	    break;
	;;
	default:
	    printf("---\n");
	    printf("Unknown unit ID %08x was detected!! Exiting!!\n", unit_header.type);

	    retcode++;

	    sprintf(unit_filename, "%08x.bin", unit_header.type);

	    break;
	;;
    }

    if (opt_extract) {
	retcode += data_extract(src_mem + sizeof(unit_header), unit_header.payload_size, unit_filename);
    }


    // set offset for next run
    next_unit_pos += sizeof(unit_header) + unit_header.payload_size;

    exit:
    return retcode;
}

void branding_header_make(unsigned char *src_mem, size_t input_size, uint32_t unixtime) {

    branding_header_t branding_header;
    memset(&branding_header, 0, sizeof(branding_header));

    branding_header.timestamp = (unixtime - 0x35016f00) / 4;

    branding_header.magic = 0x2b2405ff;
    branding_header.payload_size = input_size - sizeof(branding_header);

    // payload CRC
    branding_header.payload_crc16 = jboot_crc16(src_mem + sizeof(branding_header), branding_header.payload_size, 0);

    // wierd crc16 calculations
    int crc16_area2_size	= sizeof(branding_header) - sizeof(branding_header.hdr_crc16);
    memset(&branding_header, 0x05, 1); // replace 0xFF in firmware header to 0x05 found in actual flash dump

    branding_header.hdr_crc16 = ~jboot_crc16(&branding_header, crc16_area2_size, 0);

    memset(&branding_header, 0xFF, 1); // revert after calculation
    // crc16 of header finished

    // write branding header
    memcpy(src_mem, &branding_header, sizeof(branding_header));
}

void kernel_header_make(unsigned char *src_mem, size_t kernel_size, size_t rootfs_size, uint32_t unixtime, firmware_params_t firmware_params) {

    kernel_header_t kernel_header;
    memset(&kernel_header, 0, sizeof(kernel_header));

    kernel_header.timestamp = (unixtime - 0x35016f00) / 4;

    kernel_header.magic  = 0x2b2404ff;
    kernel_header.magic2 = 0x02032124;
    kernel_header.magic3 = 0x00000028;

    kernel_header.kern_load_addr	= firmware_params.kern_load_addr ? firmware_params.kern_load_addr : DEFAULT_KERN_LOAD;
    kernel_header.kern_entry		= firmware_params.kern_entry ? firmware_params.kern_entry : DEFAULT_KERN_ENTRY;

    kernel_header.rootfs_load_addr	= FLASH_BASE + DEFAULT_ROOTFS_PTR;

    kernel_header.kern_size = kernel_size;
    kernel_header.rootfs_size = rootfs_size;

    // payload CRC
    kernel_header.kern_crc32 = apple_crc32(src_mem + sizeof(kernel_header), kernel_header.kern_size, 0);
    kernel_header.rootfs_crc32 = apple_crc32(src_mem + sizeof(kernel_header) + kernel_header.kern_size + sizeof(unit_header_t), kernel_header.rootfs_size, 0);

    // header crc32 calculations
    size_t crc32_area2_size	= (size_t)&kernel_header.magic3 - (size_t)&kernel_header.magic2 + sizeof(kernel_header.hdr_crc32);
    kernel_header.hdr_crc32	= apple_crc32(&kernel_header.magic2, crc32_area2_size, 0);
    // crc32 of header finished

    // copy header for next calculations
    memcpy(src_mem, &kernel_header, sizeof(kernel_header));

    // crc16 of kernel containter start
    size_t crc16_area3_offset	= (size_t)&kernel_header.magic2 - (size_t)&kernel_header.magic;

    kernel_header.ksize2 = sizeof(kernel_header) - crc16_area3_offset + kernel_header.kern_size;

    kernel_header.kern_crc16 = jboot_crc16(src_mem + crc16_area3_offset, kernel_header.ksize2, 0);
    if (opt_oldcrc) kernel_header.kern_crc16 -= 0x00FF; // old jboot crc
    // crc16 of kernel containter finished

    // copy header for next calculations
    memcpy(src_mem, &kernel_header, sizeof(kernel_header));

    // make copy of header for wierd crc16 calculations
    size_t crc16_area2_size	= (size_t)&kernel_header.hdr_crc16 - (size_t)&kernel_header.magic;

    memset(src_mem, 0x04, 1); // replace to original value for calculation
    kernel_header.hdr_crc16 = ~jboot_crc16(src_mem, crc16_area2_size, 0);
    memset(src_mem, 0xFF, 1); // replace to flash value for dump
    // crc16 of header finished

    // write kernel header
    memcpy(src_mem, &kernel_header, sizeof(kernel_header));
}

void kernel_unit_make(unsigned char *src_mem, size_t kernel_size, size_t rootfs_size, uint32_t unixtime, firmware_params_t firmware_params) {

    unit_header_t unit_header;
    memset(&unit_header, 0, sizeof(unit_header));

    unit_header.timestamp = (unixtime - 0x35016f00) / 4;

    // first try: static entries
    unit_header.blocksize	= BLOCKSIZE;
    unit_header.flashpos1	= DEFAULT_KERNEL_PTR;
    unit_header.flashpos2	= DEFAULT_KERNEL_PTR;

    memcpy(&unit_header.devid, &firmware_params.devid, sizeof(unit_header.devid));
    unit_header.devid_bin	= (uint16_t)firmware_params.devid_bin;

    unit_header.magic		= MAGIC_UNIT;
    unit_header.payload_size	= sizeof(kernel_header_t) + kernel_size;
    unit_header.partition_size	= (unit_header.payload_size % BLOCKSIZE) ? ((unit_header.payload_size / BLOCKSIZE) + 1) * BLOCKSIZE : unit_header.payload_size; // grow partition to fit whole block
    unit_header.type		= MAGIC_KERNEL;

    // store for dynamic sizing
    firmware_params.kernel_offset	= unit_header.flashpos1;
    firmware_params.kernel_part_size	= unit_header.partition_size;

    kernel_header_make(src_mem + sizeof(unit_header_t), kernel_size, rootfs_size, unixtime, firmware_params);

    // payload crc
    unit_header.payload_crc16 = jboot_crc16(src_mem + sizeof(unit_header), unit_header.payload_size, 0);
    if (opt_oldcrc) unit_header.payload_crc16 -= 0x00FF; // old jboot crc

    // header crc
    unit_header.header_crc16 = ~jboot_crc16(&unit_header, sizeof(unit_header), 0);

    // write unit header
    memcpy(src_mem, &unit_header, sizeof(unit_header));
}

void rootfs_unit_make(unsigned char *src_mem, size_t rootfs_size, uint32_t unixtime, firmware_params_t firmware_params) {

    unit_header_t unit_header;
    memset(&unit_header, 0, sizeof(unit_header));

    unit_header.timestamp = (unixtime - 0x35016f00) / 4;

    // first try: static entries
    unit_header.blocksize	= BLOCKSIZE;
    unit_header.flashpos1	= DEFAULT_ROOTFS_PTR;
    unit_header.flashpos2	= DEFAULT_ROOTFS_PTR;

    unit_header.magic		= MAGIC_UNIT;
    unit_header.payload_size	= rootfs_size;
    unit_header.partition_size	= (unit_header.payload_size % BLOCKSIZE) ? ((unit_header.payload_size / BLOCKSIZE) + 1) * BLOCKSIZE : unit_header.payload_size; // grow partition to fit whole block
    unit_header.type		= MAGIC_ROOTFS;

    // store for dynamic sizing
    firmware_params.rootfs_offset	= unit_header.flashpos1;
    firmware_params.rootfs_part_size	= unit_header.partition_size;

    memcpy(&unit_header.devid, &firmware_params.devid, sizeof(unit_header.devid));
    unit_header.devid_bin	= (uint16_t)firmware_params.devid_bin;

    // payload crc
    unit_header.payload_crc16 = jboot_crc16(src_mem + sizeof(unit_header), unit_header.payload_size, 0);

    // header crc
    unit_header.header_crc16 = ~jboot_crc16(&unit_header, sizeof(unit_header), 0);

    // write unit header
    memcpy(src_mem, &unit_header, sizeof(unit_header));
}

void bootloader_unit_make(unsigned char *src_mem, size_t bootloader_size, uint32_t unixtime, firmware_params_t firmware_params) {

    unit_header_t unit_header;
    memset(&unit_header, 0, sizeof(unit_header));

    unit_header.timestamp = (unixtime - 0x35016f00) / 4;

    // first try: static entries
    unit_header.blocksize	= BLOCKSIZE;
    unit_header.flashpos1	= 0x00000000;
    unit_header.flashpos2	= 0x00000000;
    unit_header.partition_size	= 0x00010000;

    unit_header.magic		= MAGIC_UNIT;
    unit_header.payload_size	= bootloader_size;
    unit_header.type		= MAGIC_BOOTLOADER;

    // store for dynamic sizing
    firmware_params.bootloader_offset	= unit_header.flashpos1;
    firmware_params.bootloader_part_size= unit_header.partition_size;

    memcpy(&unit_header.devid, &firmware_params.devid, sizeof(unit_header.devid));
    unit_header.devid_bin	= (uint16_t)firmware_params.devid_bin;

    // payload crc
    unit_header.payload_crc16 = jboot_crc16(src_mem + sizeof(unit_header), unit_header.payload_size, 0);
    if (opt_oldcrc) unit_header.payload_crc16 -= 0x00FF; // old jboot crc

    // header crc
    unit_header.header_crc16 = ~jboot_crc16(&unit_header, sizeof(unit_header), 0);

    // write unit header
    memcpy(src_mem, &unit_header, sizeof(unit_header));
}

void branding_unit_make(unsigned char *src_mem, size_t branding_size, uint32_t unixtime, firmware_params_t firmware_params) {

    unit_header_t unit_header;
    memset(&unit_header, 0, sizeof(unit_header));

    unit_header.timestamp = (unixtime - 0x35016f00) / 4;

    // first try: static entries
    unit_header.blocksize	= BLOCKSIZE;
    unit_header.flashpos1	= DEFAULT_BRANDING_PTR;
    unit_header.flashpos2	= DEFAULT_BRANDING_PTR;

    unit_header.magic		= MAGIC_UNIT;

    unit_header.payload_size	= branding_size;
    unit_header.partition_size	= (unit_header.payload_size % BLOCKSIZE) ? ((unit_header.payload_size / BLOCKSIZE) + 1) * BLOCKSIZE : unit_header.payload_size; // grow partition to fit whole block
    unit_header.type		= MAGIC_BRANDING;

    // store for dynamic sizing
    firmware_params.branding_offset	= unit_header.flashpos1;
    firmware_params.branding_part_size	= unit_header.partition_size;

    memcpy(&unit_header.devid, &firmware_params.devid, sizeof(unit_header.devid));
    unit_header.devid_bin	= (uint16_t)firmware_params.devid_bin;

    // payload crc
    unit_header.payload_crc16 = jboot_crc16(src_mem + sizeof(unit_header), unit_header.payload_size, 0);

    // header crc
    unit_header.header_crc16 = ~jboot_crc16(&unit_header, sizeof(unit_header), 0);

    // write unit header
    memcpy(src_mem, &unit_header, sizeof(unit_header));
}


int main(int argc, char *argv[]) {
    char *input_name=NULL;
    char *input_kernel_name=NULL, *input_rootfs_name=NULL;
    char *input_branding_name=NULL;
    char *input_bootloader_name=NULL;
    char *output_name=NULL;
    char *profile_name=NULL;

    firmware_params_t firmware_params;
    memset(&firmware_params, 0, sizeof(firmware_params));

    uint32_t unixtime=0;

    int retcode=0;

    int opt_make_branding=0;
    int opt_make_firmware=0;
    int opt_branding_add=0;
    int opt_bootloader_add=0;

    int c;
    while ( 1 ) {
        c = getopt(argc, argv, "cei:x:t:hnu:b:k:r:o:L:E:I:V:");
        if (c == -1)
                break;

        switch (c) {
                case 'c':  // old style CRC
                        opt_oldcrc++;
                        break;
                case 'e':  // big endian headers
                        opt_bigendian++;
                        break;
                case 'i':  // print info
			input_name = optarg;
                        opt_info++;
			break;
                case 'x':  // print info and extract payloads
			input_name = optarg;
                        opt_extract++;
			break;
                case 't':  // unixtime
			if (!sscanf(optarg, "%10u", &unixtime)) goto print_usage;
			break;
                case 'h':  // make branding header
                        opt_make_branding++;
			break;
                case 'n':  // make kernel header
                        opt_make_firmware++;
			break;
                case 'u':  // specify bootloader name
			input_bootloader_name = optarg;
			opt_bootloader_add++;
			break;
                case 'b':  // specify branding name
			input_branding_name = optarg;
			opt_branding_add++;
			break;
                case 'k':  // specify kernel name
			input_kernel_name = optarg;
			break;
                case 'r':  // specify kernel name
			input_rootfs_name = optarg;
			break;
                case 'o':  // output file
			output_name = optarg;
			break;
                case 'L':  // kernel load address
			if (!sscanf(optarg, "0x%08x", &firmware_params.kern_load_addr)) goto print_usage;
			break;
                case 'E':  // kernel entry point
			if (!sscanf(optarg, "0x%08x", &firmware_params.kern_entry)) goto print_usage;
			break;
                case 'I':  // devid (text)
			if (!sscanf(optarg, "%12s", &firmware_params.devid[0])) goto print_usage;
			break;
                case 'V':  // devid(binary)
			if (!sscanf(optarg, "0x%04x", &firmware_params.devid_bin)) goto print_usage;
			break;

                default:
                        break;
                }
    }

    // add default values if not specified
    if (!firmware_params.devid[0]) {
	char defaultid[] = DEFAULT_DEVID;
	memcpy(&firmware_params.devid, &defaultid, sizeof(firmware_params.devid));
    }
    if (!firmware_params.devid_bin) firmware_params.devid_bin = DEFAULT_DEVID_BIN;

    /* чтение и разбор прошивки */
    if (opt_info || opt_extract) {
	FILE* source_file = fopen(input_name,"r");
	if (source_file == 0) {
    	    perror("Cannot open file for read");
    	    return 100;
	}
    
	fseek(source_file, 0, SEEK_END);
	size_t input_size = ftell(source_file);

	unsigned char *src_mem = malloc(input_size);
	memset(src_mem, 0, input_size);

	fseek(source_file, 0, SEEK_SET);
	fread(src_mem, input_size, 1, source_file);
	fclose(source_file);

	while (retcode <= 100 && next_unit_pos < input_size) {
	    retcode += unit_sanity_check(src_mem + next_unit_pos, input_size - next_unit_pos);
	}

	free(src_mem);
	goto exit;
    }
    else if (opt_make_branding && input_branding_name && output_name) {

	FILE* source_file = fopen(input_branding_name,"r");
	if (source_file == 0) {
	    perror("Cannot open file for read");
	    return 100;
	}

	fseek(source_file, 0, SEEK_END);
	size_t input_size = ftell(source_file);
	size_t result_size = input_size + sizeof(branding_header_t);

	if (!unixtime) unixtime = time(NULL);

	unsigned char *result_mem = malloc(result_size);
	memset(result_mem, 0, result_size);

	fseek(source_file, 0, SEEK_SET);
	fread(result_mem + sizeof(branding_header_t), input_size, 1, source_file);
	fclose(source_file);

	branding_header_make(result_mem, result_size, unixtime);
	retcode += branding_sanity_check(result_mem, result_size);

	if (retcode == 0) {
	    retcode += data_extract(result_mem, result_size, output_name);
	}
	free(result_mem);
	goto exit;
    }
    else if (opt_make_firmware && input_kernel_name && input_rootfs_name && output_name) {

	size_t bootloader_size = 0, bootloader_pointer = 0;
	size_t kernel_size = 0, kernel_pointer = 0;
	size_t rootfs_size = 0, rootfs_pointer = 0;
	size_t branding_size = 0, branding_pointer = 0;
	size_t result_size = 0, result_pointer = 0;

	FILE *bootloader_file = NULL;
	FILE *kernel_file = NULL;
	FILE *rootfs_file = NULL;
	FILE *branding_file = NULL;

	if (!unixtime) unixtime = time(NULL);

if (opt_bootloader_add) {
	bootloader_file = fopen(input_bootloader_name,"r");
	if (bootloader_file == 0) {
	    perror("Cannot open bootloader file for read");
	    return 100;
	}
	fseek(bootloader_file, 0, SEEK_END);
	bootloader_size = ftell(bootloader_file);

	result_size += sizeof(unit_header_t) + bootloader_size; // add bootloader and its header
}

	kernel_file = fopen(input_kernel_name,"r");
	if (kernel_file == 0) {
	    perror("Cannot open kernel file for read");
	    return 100;
	}
	fseek(kernel_file, 0, SEEK_END);
	kernel_size = ftell(kernel_file);

	result_size += sizeof(unit_header_t) + sizeof(kernel_header_t) + kernel_size; // add kernel and unit + kernel header

	rootfs_file = fopen(input_rootfs_name,"r");
	if (rootfs_file == 0) {
	    perror("Cannot open rootfs file for read");
	    return 100;
	}
	fseek(rootfs_file, 0, SEEK_END);
	rootfs_size = ftell(rootfs_file);

	result_size += sizeof(unit_header_t) + rootfs_size; // add rootfs and its header

if (opt_branding_add) {
	branding_file = fopen(input_branding_name,"r");
	if (branding_file == 0) {
	    perror("Cannot open branding file for read");
	    return 100;
	}
	fseek(branding_file, 0, SEEK_END);
	branding_size = ftell(branding_file);

	result_size += sizeof(unit_header_t) + branding_size; // add branding (header added via "-h" option if needed)
}

	unsigned char *result_mem = malloc(result_size);
	memset(result_mem, 0, result_size);

	// 1. bootloader
if (opt_bootloader_add) {
	bootloader_pointer = result_pointer;
	result_pointer += sizeof(unit_header_t);
	fseek(bootloader_file, 0, SEEK_SET);
	fread(result_mem + result_pointer, bootloader_size, 1, bootloader_file);
	fclose(bootloader_file);

	bootloader_unit_make(result_mem + bootloader_pointer, bootloader_size, unixtime, firmware_params);

	result_pointer += bootloader_size;
}

	// 2. kernel
	kernel_pointer = result_pointer;
	result_pointer += sizeof(unit_header_t) + sizeof(kernel_header_t);
	fseek(kernel_file, 0, SEEK_SET);
	fread(result_mem + result_pointer, kernel_size, 1, kernel_file);
	fclose(kernel_file);
	result_pointer += kernel_size;

	// 3. rootfs
	rootfs_pointer = result_pointer;
	result_pointer += sizeof(unit_header_t);
	fseek(rootfs_file, 0, SEEK_SET);
	fread(result_mem + result_pointer, rootfs_size, 1, rootfs_file);
	fclose(rootfs_file);
	result_pointer += rootfs_size;

	// kernel contains rootfs CRC, so order is matter
	rootfs_unit_make(result_mem + rootfs_pointer, rootfs_size, unixtime, firmware_params);
	kernel_unit_make(result_mem + kernel_pointer, kernel_size, rootfs_size, unixtime, firmware_params);

	// 4. branding
if (opt_branding_add) {
	branding_pointer = result_pointer;
	result_pointer += sizeof(unit_header_t);
	fseek(branding_file, 0, SEEK_SET);
	fread(result_mem + result_pointer, branding_size, 1, branding_file);
	fclose(branding_file);
	result_pointer += branding_size;

	branding_unit_make(result_mem + branding_pointer, branding_size, unixtime, firmware_params);
}

	// self-check sequence
	while (retcode <= 100 && next_unit_pos < result_size) {
	    retcode += unit_sanity_check(result_mem + next_unit_pos, result_size - next_unit_pos);
	}

	if (retcode == 0) {
	    retcode += data_extract(result_mem, result_size, output_name);
	}
	free(result_mem);
	goto exit;
    }
    else {
	print_usage:
	fprintf(stderr, "Usage:\n"
	"%s { [-c] -x input.bin | [-c] -i input.bin | [-c] [-p profile] -n -k kernel.bin -r rootfs.bin [-b branding.bin] [-u bootloader.bin] -o output.bin  }\n",
	argv[0]);
	fprintf(stderr, "  -c      Use old style jboot CRC for some calculations (DWA-921 and others)\n");
	fprintf(stderr, "  -e      Use big endian for all calculations\n");
	fprintf(stderr, "  -i      Print headers and do sanity check on whole firmware or single container\n");
	fprintf(stderr, "  -x      Extract payloads from whole firmware to bootloader.bin+kernel.bin+rootfs.bin+branding.bin\n");
	fprintf(stderr, "  -t      Use specified unixtime for inclusion to image header\n");
	fprintf(stderr, "  -h      Add branding header to input file { [-c] [-e] [-t unixtime ] -b input.bin -o output.bin }\n");
	fprintf(stderr, "  -n      Assemble whole firmware { -n [-c] [-e] [-t unixtime ] -k kernel.bin -r rootfs.bin [-u bootloader.bin] [-b branding.bin ] -o output.bin }\n");
	fprintf(stderr, "  -L      Kernel load address for firmware creation (default 0x80000000)\n");
	fprintf(stderr, "  -E      Kernel entry point for firmware creation (default 0x80000000)\n");
	fprintf(stderr, "  -I      Device ID (text) for build firmware (default \"LVA6E3804001\")\n");
	fprintf(stderr, "  -V      Device ID (binary) for build firmware (0x6e38)\n");
	retcode++;
    }

    exit:
    return retcode;
};
