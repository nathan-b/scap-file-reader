#include <stdint.h>
#include <string.h>

#include "bufscap.h"

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

/*******************
 * SCAP reader
 */

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
