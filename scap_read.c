#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <scap_savefile.h>
#include <scap_reader.h>
#include <scap.h>

#define BYTE_ORDER_MAGIC 0x1A2B3C4D
#define SHB_BLOCK_TYPE 0x0A0D0D0A

#define NS_PER_MS 1000000

typedef struct
{
	uint32_t byte_order_magic;
	uint16_t major_version;
	uint16_t minor_version;
	uint64_t section_length;
} section_header;

typedef struct
{
	uint64_t ts_ns;    // Timestamp, in nanoseconds from epoch
	uint64_t tid;      // tid of the thread that generated this event
	uint32_t len;      // Event length, including this header
	uint16_t type;     // Event type
	uint32_t nparams;  // Number of parameters to the event
} event_header;

#pragma pack(1)
typedef struct
{
	uint16_t cpuid;
	uint32_t flags;
	event_header header;
} event_section_header_flags;

#pragma pack(1)
typedef struct
{
	uint16_t cpuid;
	event_header header;
} event_section_header_no_flags;

////////////////////////////
// SCAP file reader implementation

struct bufscap_handle
{
	const uint8_t* buf;
	int64_t offset;
	int64_t len;
};

int bufscap_read(struct scap_reader* r, void* target, uint32_t len)
{
	struct bufscap_handle* bsh = (struct bufscap_handle*)r->handle;
	const uint8_t* const inbuf = bsh->buf;
	uint8_t* outbuf = (uint8_t*)target;

	if (!inbuf || !outbuf)
	{
		return 0;
	}

	uint32_t remaining_len = bsh->len - bsh->offset;
	if (remaining_len < len)
	{
		len = remaining_len;
	}

	memcpy(outbuf, &inbuf[bsh->offset], len);
	bsh->offset += len;
	return len;
}

int64_t bufscap_offset(struct scap_reader* r)
{
	struct bufscap_handle* bsh = (struct bufscap_handle*)r->handle;
	return bsh->offset;
}

int64_t bufscap_tell(struct scap_reader* r)
{
	// I think this is the right thing to do for this handle type...
	return bufscap_offset(r);
}

int64_t bufscap_seek(struct scap_reader* r, int64_t offset, int whence)
{
	struct bufscap_handle* bsh = (struct bufscap_handle*)r->handle;

	int64_t start = 0;
	switch (whence)
	{
	case SEEK_SET:
		start = 0;
		break;
	case SEEK_CUR:
		start = bsh->offset;
		break;
	case SEEK_END:
		start = bsh->len;
		break;
	}

	if (offset + start > bsh->len)
	{
		bsh->offset = bsh->len;
	}
	else
	{
		bsh->offset = offset + start;
	}

	return bsh->offset;
}

const char* bufscap_error(struct scap_reader* r, int* errnum)
{
	// We never have errors :D
	errnum = 0;
	return 0;
}

int bufscap_close(struct scap_reader* r)
{
	// Don't delete anything
	return 0;
}

scap_reader_t* build_reader_from_buffer(const uint8_t* const buf, int64_t len)
{
	uint8_t* rd_buf = malloc(sizeof(scap_reader_t) + sizeof(struct bufscap_handle));
	scap_reader_t* ret = (scap_reader_t*)rd_buf;

	struct bufscap_handle* handle = (struct bufscap_handle*)(rd_buf + sizeof(*ret));
	handle->buf = buf;
	handle->len = len;
	handle->offset = 0;
	ret->handle = handle;

	ret->read   = bufscap_read;
	ret->offset = bufscap_offset;
	ret->tell   = bufscap_tell;
	ret->seek   = bufscap_seek;
	ret->error  = bufscap_error;
	ret->close  = bufscap_close;

	return ret;
}

void free_reader(scap_reader_t* r)
{
	free(r);
}

////////////////////////////
// Globals
uint64_t g_first_ns = 0;
uint64_t g_last_ns = 0;
bool g_verbose = false;
bool g_print_procs = false;
bool g_print_threads = false;
bool g_print_events = false;
uint64_t g_pid_list[64] = {0};
uint32_t g_pl_len = 0;
char* g_arg_search = NULL;
char* g_comm_search = NULL;

////////////////////////////
// Block handlers

extern int32_t scap_read_proclist(scap_reader_t* r, uint32_t block_length, uint32_t block_type, struct scap_proclist *proclist, char *error);

void print_event(const event_header* const pevent)
{
	if (g_print_events && pevent)
	{
		if (g_first_ns == 0)
		{
			g_first_ns = pevent->ts_ns;
		}
		g_last_ns = pevent->ts_ns;
		if (g_verbose)
		{
			printf("\tEvent type=%u, ts=%llu, tid=%llu, len=%u\n",
				   pevent->type,
				   (long long unsigned)pevent->ts_ns,
				   (long long unsigned)pevent->tid,
				   pevent->len);
		}
	}
}

void print_proc(void* context, scap_t* handle, int64_t tid, scap_threadinfo* tinfo, scap_fdinfo* fdinfo)
{
	if (!g_print_procs && !g_print_threads && g_pl_len == 0)
	{
		return;
	}

	if (g_pl_len > 0)
	{
		// Only proceed if pid is in pid list
		bool found = false;
		for (uint32_t i = 0; i < g_pl_len; ++i)
		{
			if (g_pid_list[i] == (uint64_t)tid || g_pid_list[i] == (uint64_t)tinfo->pid)
			{
				found = true;
				break;
			}
		}
		if (!found)
		{
			return;
		}
	}
	else if (g_print_procs)
	{
		// Only proceed if thread is main thread for process
		if (tid != tinfo->pid)
		{
			return;
		}
	}

	if (g_comm_search)
	{
		if (strcmp(g_comm_search, tinfo->comm) != 0)
		{
			return;
		}
	}

	printf("\tProc %s has PID %lli, TID %lli, PTID %lli, flags %x\n",
	       tinfo->comm,
		   (long long)tinfo->pid,
		   (long long)tid,
		   (long long)tinfo->ptid,
		   tinfo->flags);

	if (g_arg_search)
	{
		uint32_t len = strlen(g_arg_search);
		for (uint32_t i = 0; i < tinfo->args_len; ++i)
		{
			if (memcmp(&tinfo->args[i], g_arg_search, len) == 0)
			{
				printf("\t\tArg %s\n", &tinfo->args[i]);
				break;
			}
		}
	}
}

void handle_event(block_header* bh, const uint8_t* const buffer, uint32_t len)
{
	// Flags
	event_section_header_flags* esh = (event_section_header_flags*)buffer;
	if (g_verbose)
	{
		printf("\tcpuid=%hu flags=0x%x", esh->cpuid, esh->flags);
	}
	print_event(&esh->header);
}

void handle_event_no_flags(block_header* bh, const uint8_t* const buffer, uint32_t len)
{
	// No flags
	event_section_header_no_flags* esh = (event_section_header_no_flags*)buffer;
	if (g_verbose)
	{
		printf("\tcpuid=%hu flags=0x0", esh->cpuid);
	}
	print_event(&esh->header);
}

void handle_proc_list(block_header* bh, const uint8_t* const buffer, uint32_t len)
{
	struct scap_proclist pl;
	pl.m_proc_callback = print_proc;
	scap_reader_t* sr = build_reader_from_buffer(buffer, len);
	scap_read_proclist(sr, len, bh->block_type, &pl, NULL);
}

////////////////////
// Parse through the scap file
int32_t scap_read(const char* filename)
{
	FILE* f = NULL;
	int ret = 0;
	uint32_t buf_len = 10 * 1024 * 1024;  // 10m should be enough for anybody, right?
	uint8_t* readbuf = malloc(buf_len);
	block_header bh;
	section_header sh;
	uint32_t bt;  // Block trailer
	uint32_t num_events = 0;

	// Open the file
	f = fopen(filename, "rb");
	if (!f)
	{
		fprintf(stderr, "Could not open file %s: %d (%s)\n", filename, errno, strerror(errno));
		ret = 1;
		goto done;
	}

	// Read the section header block
	if (fread(&bh, 1, sizeof(bh), f) != sizeof(bh) ||
	    fread(&sh, 1, sizeof(sh), f) != sizeof(sh) ||
	    fread(&bt, 1, sizeof(bt), f) != sizeof(bt))
	{
		fprintf(stderr, "Error reading from file %s: %d (%s)\n", filename, errno, strerror(errno));
		ret = 1;
		goto done;
	}
	else
	{
		printf("block_header: block_type=0x%x, block_total_len=%u\n", bh.block_type, bh.block_total_length);
		printf("section_header_block: \n\tbyte_order_magic=0x%x,\n\tversion=%d.%d\n",
		       sh.byte_order_magic,
		       sh.major_version,
		       sh.minor_version);
		printf("bt=%u\n", bt);

		// Do some sanity checking on the header
		if (bh.block_type != SHB_BLOCK_TYPE)
		{
			fprintf(stderr,
			        "Error reading section header: unexpected block type (%x != %x)\n",
			        bh.block_type,
			        SHB_BLOCK_TYPE);
		}

		if (sh.byte_order_magic != BYTE_ORDER_MAGIC)
		{
			fprintf(stderr,
			        "Error reading section header: byte order magic mismatch (%x != %x)\n",
			        sh.byte_order_magic,
			        BYTE_ORDER_MAGIC);
		}
	}

	// Read all blocks in the capture
	while (1)
	{
		//
		// Read block header
		//
		if (fread(&bh, 1, sizeof(bh), f) != sizeof(bh))
		{
			ret = 0;
			goto done;
		}
		else if (g_verbose)
		{
			printf("block_header: block_type=0x%x, block_total_len=%u\n", bh.block_type, bh.block_total_length);
		}

		//
		// Read the whole block up to the trailer
		//
		int expected_len = bh.block_total_length - sizeof(bh) - sizeof(bt);
		if (expected_len > buf_len)
		{
			// We're going to need a bigger boat
			free(readbuf);
			readbuf = malloc(expected_len);
			if (!readbuf)
			{
				fprintf(stderr, "Could not allocate %d bytes of buffer memory\n", expected_len);
				ret = 1;
				goto done;
			}
		}
		int read_len = fread(readbuf, 1, expected_len, f);
		if (read_len != expected_len)
		{
			fprintf(stderr, "Could not read block (expected length of %d, got length of %d)\n", expected_len, read_len);
			ret = 1;
			goto done;
		}

		//
		// Process the block
		//
		switch (bh.block_type)
		{
		case EVF_BLOCK_TYPE:
		case EVF_BLOCK_TYPE_V2:
		case EVF_BLOCK_TYPE_V2_LARGE:
			++num_events;
			handle_event(&bh, readbuf, read_len);
			break;
		case EV_BLOCK_TYPE:
		case EV_BLOCK_TYPE_V2:
		case EV_BLOCK_TYPE_V2_LARGE:
			++num_events;
			handle_event_no_flags(&bh, readbuf, read_len);
			break;
		case PL_BLOCK_TYPE_V1:
		case PL_BLOCK_TYPE_V2:
		case PL_BLOCK_TYPE_V3:
		case PL_BLOCK_TYPE_V4:
		case PL_BLOCK_TYPE_V5:
		case PL_BLOCK_TYPE_V6:
		case PL_BLOCK_TYPE_V7:
		case PL_BLOCK_TYPE_V8:
		case PL_BLOCK_TYPE_V9:
		case PL_BLOCK_TYPE_V1_INT:
		case PL_BLOCK_TYPE_V2_INT:
		case PL_BLOCK_TYPE_V3_INT:
			handle_proc_list(&bh, readbuf, read_len);
			break;
		default:
			// Carry on
		}

		//
		// Read the trailer
		//
		read_len = fread(&bt, 1, sizeof(bt), f);
		if (read_len != sizeof(bt))
		{
			fprintf(stderr, "Could not read block trailer: %d (%s)\n", errno, strerror(errno));
			ret = 1;
			goto done;
		}
		if (g_verbose)
		{
			printf("block trailer: %u\n", bt);
		}
		if (bt != bh.block_total_length)
		{
			fprintf(stderr,
			        "Malformed block: length mismatch between header and trailer (%u != %u)\n",
			        bh.block_total_length,
			        bt);
		}
	}

done:
	if (ret == 0)
	{
		printf("File is correctly formed and contains %u events between %llu and %llu (%llu ms)\n",
				num_events,
				(long long unsigned)g_first_ns,
				(long long unsigned)g_last_ns,
				(long long unsigned)((g_last_ns - g_first_ns) / NS_PER_MS));
	}
	if (readbuf)
	{
		free(readbuf);
	}
	return ret;
}

///////////////////
// User interface (lol)
void usage(const char* progname)
{
	printf("Usage: %s [-v] [-p|P] [-e|E] [-t|-T] <scap file>\n", progname);
	printf("          -e: Do not print events\n");
	printf("          -E: Print events\n");
	printf("          -p: Do not print processes\n");
	printf("          -P: Print processes\n");
	printf("          -t: Do not print threads\n");
	printf("          -T: Print threads\n");
}

int main(int argc, char** argv)
{
	// Command line parsing (this is garbage, I know)
	for (int i = 1; i < argc; ++i)
	{
		if (argv[i][0] == '-')
		{
			switch (argv[i][1])
			{
			case 'v':
				g_verbose = true;
				break;
			case 'p':
				g_print_procs = false;
				break;
			case 'P':
				g_print_procs = true;
				break;
			case 't':
				g_print_threads = false;
				break;
			case 'T':
				g_print_threads = true;
				break;
			case 'e':
				g_print_events = false;
				break;
			case 'E':
				g_print_events = true;
				break;
			case 'l':
				g_pid_list[g_pl_len++] = strtoull(argv[++i], NULL, 10);
				break;
			case 'a':
				g_arg_search = argv[++i];
				break;
			case 'n':
				g_comm_search = argv[++i];
				break;
			default:
				fprintf(stderr, "Unknown switch %s\n", argv[i]);
				usage(argv[0]);
				return -1;
			}
		}
		else
		{
			printf("Capture file %s\n=======================================\n", argv[i]);
			scap_read(argv[i]);
		}
	}
	return 0;
}
