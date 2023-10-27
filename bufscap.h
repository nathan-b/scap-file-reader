/************************************
 * SCAP file reader
 *
 * Reads an scap file from a memory buffer
 */

#include <stdint.h>

#include <scap_reader.h>

struct bufscap_handle
{
	const uint8_t* buf;
	int64_t offset;
	int64_t len;
};

extern int bufscap_read(struct scap_reader* r, void* target, uint32_t len);

extern int64_t bufscap_offset(struct scap_reader* r);

extern int64_t bufscap_tell(struct scap_reader* r);

extern int64_t bufscap_seek(struct scap_reader* r, int64_t offset, int whence);

extern const char* bufscap_error(struct scap_reader* r, int* errnum);

extern int bufscap_close(struct scap_reader* r);

extern scap_reader_t* build_reader_from_buffer(const uint8_t* const buf, int64_t len);

extern void free_reader(scap_reader_t* r);
