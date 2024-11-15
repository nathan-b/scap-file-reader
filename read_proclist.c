#include "scap_redefs.h"

#include <assert.h>
#include <scap_const.h>
#include <scap_limits.h>
#include <scap_procs.h>
#include <scap_reader.h>
#include <scap_savefile.h>
#include <stdbool.h>
#include <stdint.h>

#define CHECK_READ_SIZE_ERR(read_size, expected_size, error)                          \
	if (read_size != expected_size)                                                   \
	{                                                                                 \
		fprintf(stderr,                                                               \
		        "expecting %d bytes, read %d at %s, line %d. Is the file truncated?", \
		        (int)expected_size,                                                   \
		        (int)read_size,                                                       \
		        __FILE__,                                                             \
		        __LINE__);                                                            \
		return SCAP_FAILURE;                                                          \
	}

int32_t scap_read_proclist(scap_reader_t* r,
                           uint32_t block_length,
                           uint32_t block_type,
                           struct scap_proclist* proclist,
                           char* error)
{
	size_t readsize;
	size_t subreadsize = 0;
	size_t totreadsize = 0;
	size_t padding_len;
	uint16_t stlen;
	uint32_t padding;
	int32_t uth_status = SCAP_SUCCESS;
	uint32_t toread;
	int fseekres;

	while (((int32_t)block_length - (int32_t)totreadsize) >= 4)
	{
		struct scap_threadinfo tinfo;

		tinfo.fdlist = NULL;
		tinfo.flags = 0;
		tinfo.vmsize_kb = 0;
		tinfo.vmrss_kb = 0;
		tinfo.vmswap_kb = 0;
		tinfo.pfmajor = 0;
		tinfo.pfminor = 0;
		tinfo.env_len = 0;
		tinfo.vtid = -1;
		tinfo.vpid = -1;
		tinfo.cgroups.len = 0;
		tinfo.filtered_out = 0;
		tinfo.root[0] = 0;
		tinfo.sid = -1;
		tinfo.vpgid = -1;
		tinfo.pgid = -1;
		tinfo.clone_ts = 0;
		tinfo.pidns_init_start_ts = 0;
		tinfo.tty = 0;
		tinfo.exepath[0] = 0;
		tinfo.loginuid = UINT32_MAX;
		tinfo.exe_writable = false;
		tinfo.cap_inheritable = 0;
		tinfo.cap_permitted = 0;
		tinfo.cap_effective = 0;
		tinfo.exe_upper_layer = false;
		tinfo.exe_ino = 0;
		tinfo.exe_ino_ctime = 0;
		tinfo.exe_ino_mtime = 0;
		tinfo.exe_from_memfd = false;
		tinfo.exe_lower_layer = false;

		//
		// len
		//
		uint32_t sub_len = 0;
		switch (block_type)
		{
		case PL_BLOCK_TYPE_V1:
		case PL_BLOCK_TYPE_V1_INT:
		case PL_BLOCK_TYPE_V2:
		case PL_BLOCK_TYPE_V2_INT:
		case PL_BLOCK_TYPE_V3:
		case PL_BLOCK_TYPE_V3_INT:
		case PL_BLOCK_TYPE_V4:
		case PL_BLOCK_TYPE_V5:
		case PL_BLOCK_TYPE_V6:
		case PL_BLOCK_TYPE_V7:
		case PL_BLOCK_TYPE_V8:
			break;
		case PL_BLOCK_TYPE_V9:
			readsize = r->read(r, &(sub_len), sizeof(uint32_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);

			subreadsize += readsize;
			break;
		default:
			fprintf(stderr, "corrupted process block type (fd1)");
			assert(false);
			return SCAP_FAILURE;
		}

		//
		// tid
		//
		readsize = r->read(r, &(tinfo.tid), sizeof(uint64_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

		subreadsize += readsize;

		//
		// pid
		//
		readsize = r->read(r, &(tinfo.pid), sizeof(uint64_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

		subreadsize += readsize;

		//
		// ptid
		//
		readsize = r->read(r, &(tinfo.ptid), sizeof(uint64_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

		subreadsize += readsize;

		switch (block_type)
		{
		case PL_BLOCK_TYPE_V1:
		case PL_BLOCK_TYPE_V1_INT:
		case PL_BLOCK_TYPE_V2:
		case PL_BLOCK_TYPE_V2_INT:
		case PL_BLOCK_TYPE_V3:
		case PL_BLOCK_TYPE_V3_INT:
		case PL_BLOCK_TYPE_V4:
		case PL_BLOCK_TYPE_V5:
			break;
		case PL_BLOCK_TYPE_V6:
		case PL_BLOCK_TYPE_V7:
		case PL_BLOCK_TYPE_V8:
		case PL_BLOCK_TYPE_V9:
			readsize = r->read(r, &(tinfo.sid), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

			subreadsize += readsize;
			break;
		default:
			fprintf(stderr, "corrupted process block type (fd1)");
			assert(false);
			return SCAP_FAILURE;
		}

		//
		// vpgid
		//
		switch (block_type)
		{
		case PL_BLOCK_TYPE_V1:
		case PL_BLOCK_TYPE_V1_INT:
		case PL_BLOCK_TYPE_V2:
		case PL_BLOCK_TYPE_V2_INT:
		case PL_BLOCK_TYPE_V3:
		case PL_BLOCK_TYPE_V3_INT:
		case PL_BLOCK_TYPE_V4:
		case PL_BLOCK_TYPE_V5:
		case PL_BLOCK_TYPE_V6:
		case PL_BLOCK_TYPE_V7:
			break;
		case PL_BLOCK_TYPE_V8:
		case PL_BLOCK_TYPE_V9:
			readsize = r->read(r, &(tinfo.vpgid), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

			subreadsize += readsize;
			break;
		default:
			fprintf(stderr, "corrupted process block type (fd1)");
			assert(false);
			return SCAP_FAILURE;
		}

		//
		// comm
		//
		readsize = r->read(r, &(stlen), sizeof(uint16_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

		if (stlen > SCAP_MAX_PATH_SIZE)
		{
			fprintf(stderr, "invalid commlen %d", stlen);
			return SCAP_FAILURE;
		}

		subreadsize += readsize;

		readsize = r->read(r, tinfo.comm, stlen);
		CHECK_READ_SIZE_ERR(readsize, stlen, error);

		// the string is not null-terminated on file
		tinfo.comm[stlen] = 0;

		subreadsize += readsize;

		//
		// exe
		//
		readsize = r->read(r, &(stlen), sizeof(uint16_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

		if (stlen > SCAP_MAX_PATH_SIZE)
		{
			fprintf(stderr, "invalid exelen %d", stlen);
			return SCAP_FAILURE;
		}

		subreadsize += readsize;

		readsize = r->read(r, tinfo.exe, stlen);
		CHECK_READ_SIZE_ERR(readsize, stlen, error);

		// the string is not null-terminated on file
		tinfo.exe[stlen] = 0;

		subreadsize += readsize;

		switch (block_type)
		{
		case PL_BLOCK_TYPE_V1:
		case PL_BLOCK_TYPE_V1_INT:
		case PL_BLOCK_TYPE_V2:
		case PL_BLOCK_TYPE_V2_INT:
		case PL_BLOCK_TYPE_V3:
		case PL_BLOCK_TYPE_V3_INT:
		case PL_BLOCK_TYPE_V4:
		case PL_BLOCK_TYPE_V5:
		case PL_BLOCK_TYPE_V6:
			break;
		case PL_BLOCK_TYPE_V7:
		case PL_BLOCK_TYPE_V8:
		case PL_BLOCK_TYPE_V9:
			//
			// exepath
			//
			readsize = r->read(r, &(stlen), sizeof(uint16_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

			if (stlen > SCAP_MAX_PATH_SIZE)
			{
				fprintf(stderr, "invalid exepathlen %d", stlen);
				return SCAP_FAILURE;
			}

			subreadsize += readsize;

			readsize = r->read(r, tinfo.exepath, stlen);
			CHECK_READ_SIZE_ERR(readsize, stlen, error);

			// the string is not null-terminated on file
			tinfo.exepath[stlen] = 0;

			subreadsize += readsize;

			break;
		default:
			fprintf(stderr, "corrupted process block type (fd1)");
			assert(false);
			return SCAP_FAILURE;
		}

		//
		// args
		//
		readsize = r->read(r, &(stlen), sizeof(uint16_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

		if (stlen > SCAP_MAX_ARGS_SIZE)
		{
			fprintf(stderr, "invalid argslen %d", stlen);
			return SCAP_FAILURE;
		}

		subreadsize += readsize;

		readsize = r->read(r, tinfo.args, stlen);
		CHECK_READ_SIZE_ERR(readsize, stlen, error);

		// the string is not null-terminated on file
		tinfo.args[stlen] = 0;
		tinfo.args_len = stlen;

		subreadsize += readsize;

		//
		// cwd
		//
		readsize = r->read(r, &(stlen), sizeof(uint16_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

		if (stlen > SCAP_MAX_PATH_SIZE)
		{
			fprintf(stderr, "invalid cwdlen %d", stlen);
			return SCAP_FAILURE;
		}

		subreadsize += readsize;

		readsize = r->read(r, tinfo.cwd, stlen);
		CHECK_READ_SIZE_ERR(readsize, stlen, error);

		// the string is not null-terminated on file
		tinfo.cwd[stlen] = 0;

		subreadsize += readsize;

		//
		// fdlimit
		//
		readsize = r->read(r, &(tinfo.fdlimit), sizeof(uint64_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

		subreadsize += readsize;

		//
		// flags
		//
		readsize = r->read(r, &(tinfo.flags), sizeof(uint32_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);

		subreadsize += readsize;

		//
		// uid
		//
		readsize = r->read(r, &(tinfo.uid), sizeof(uint32_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);

		subreadsize += readsize;

		//
		// gid
		//
		readsize = r->read(r, &(tinfo.gid), sizeof(uint32_t));
		CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);

		subreadsize += readsize;

		switch (block_type)
		{
		case PL_BLOCK_TYPE_V1:
		case PL_BLOCK_TYPE_V1_INT:
			break;
		case PL_BLOCK_TYPE_V2:
		case PL_BLOCK_TYPE_V2_INT:
		case PL_BLOCK_TYPE_V3:
		case PL_BLOCK_TYPE_V3_INT:
		case PL_BLOCK_TYPE_V4:
		case PL_BLOCK_TYPE_V5:
		case PL_BLOCK_TYPE_V6:
		case PL_BLOCK_TYPE_V7:
		case PL_BLOCK_TYPE_V8:
		case PL_BLOCK_TYPE_V9:
			//
			// vmsize_kb
			//
			readsize = r->read(r, &(tinfo.vmsize_kb), sizeof(uint32_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);

			subreadsize += readsize;

			//
			// vmrss_kb
			//
			readsize = r->read(r, &(tinfo.vmrss_kb), sizeof(uint32_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);

			subreadsize += readsize;

			//
			// vmswap_kb
			//
			readsize = r->read(r, &(tinfo.vmswap_kb), sizeof(uint32_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);

			subreadsize += readsize;

			//
			// pfmajor
			//
			readsize = r->read(r, &(tinfo.pfmajor), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

			subreadsize += readsize;

			//
			// pfminor
			//
			readsize = r->read(r, &(tinfo.pfminor), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

			subreadsize += readsize;

			if(block_type == PL_BLOCK_TYPE_V3 ||
				block_type == PL_BLOCK_TYPE_V3_INT ||
				block_type == PL_BLOCK_TYPE_V4 ||
				block_type == PL_BLOCK_TYPE_V5 ||
				block_type == PL_BLOCK_TYPE_V6 ||
				block_type == PL_BLOCK_TYPE_V7 ||
				block_type == PL_BLOCK_TYPE_V8 ||
				block_type == PL_BLOCK_TYPE_V9)
			{
				//
				// env
				//
				readsize = r->read(r, &(stlen), sizeof(uint16_t));
				CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

				if (stlen > SCAP_MAX_ENV_SIZE)
				{
					fprintf(stderr, "invalid envlen %d", stlen);
					return SCAP_FAILURE;
				}

				subreadsize += readsize;

				readsize = r->read(r, tinfo.env, stlen);
				CHECK_READ_SIZE_ERR(readsize, stlen, error);

				// the string is not null-terminated on file
				tinfo.env[stlen] = 0;
				tinfo.env_len = stlen;

				subreadsize += readsize;
			}

			if(block_type == PL_BLOCK_TYPE_V4 ||
			   block_type == PL_BLOCK_TYPE_V5 ||
			   block_type == PL_BLOCK_TYPE_V6 ||
			   block_type == PL_BLOCK_TYPE_V7 ||
			   block_type == PL_BLOCK_TYPE_V8 ||
			   block_type == PL_BLOCK_TYPE_V9)
			{
				//
				// vtid
				//
				readsize = r->read(r, &(tinfo.vtid), sizeof(int64_t));
				CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

				subreadsize += readsize;

				//
				// vpid
				//
				readsize = r->read(r, &(tinfo.vpid), sizeof(int64_t));
				CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);

				subreadsize += readsize;

				//
				// cgroups
				//
				readsize = r->read(r, &(stlen), sizeof(uint16_t));
				CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

				if (stlen > SCAP_MAX_CGROUPS_SIZE)
				{
					snprintf(error, SCAP_LASTERR_SIZE, "invalid cgroupslen %d", stlen);
					return SCAP_FAILURE;
				}
				tinfo.cgroups.len = stlen;

				subreadsize += readsize;

				readsize = r->read(r, tinfo.cgroups.path, stlen);
				CHECK_READ_SIZE_ERR(readsize, stlen, error);

				subreadsize += readsize;

				if (block_type == PL_BLOCK_TYPE_V5 ||
				   block_type == PL_BLOCK_TYPE_V6 ||
 				   block_type == PL_BLOCK_TYPE_V7 ||
					 block_type == PL_BLOCK_TYPE_V8 ||
				   block_type == PL_BLOCK_TYPE_V9)
				{
					readsize = r->read(r, &(stlen), sizeof(uint16_t));
					CHECK_READ_SIZE_ERR(readsize, sizeof(uint16_t), error);

					if (stlen > SCAP_MAX_PATH_SIZE) {
						snprintf(error, SCAP_LASTERR_SIZE, "invalid rootlen %d", stlen);
						return SCAP_FAILURE;
					}

					subreadsize += readsize;

					readsize = r->read(r, tinfo.root, stlen);
					CHECK_READ_SIZE_ERR(readsize, stlen, error);

					// the string is not null-terminated on file
					tinfo.root[stlen] = 0;

					subreadsize += readsize;
				}
			}
			break;
		default:
			fprintf(stderr, "corrupted process block type (fd1)");
			assert(false);
			return SCAP_FAILURE;
		}

		// If new parameters are added, sub_len can be used to
		// see if they are available in the current capture.
		// For example, for a 32bit parameter:
		//
		// if(sub_len && (subreadsize + sizeof(uint32_t)) <= sub_len)
		// {
		//    ...
		// }
		// In 0.10.x libs tag, 2 fields were added to the scap file producer,
		// written in the middle of the proclist entry, breaking forward compatibility
		// for old scap file readers.
		// Detect this hacky behavior, and manage it.
		// Added fields:
		// * exe_upper_layer
		// * exe_ino
		// * exe_ino_ctime
		// * exe_ino_mtime
		// * pidns_init_start_ts (in the middle)
		// * tty (in the middle)
		// So, to check if we need to enable the "pre-0.10.x hack",
		// we need to check if remaining data to be read is <= than
		// sum of sizes for fields existent in libs < 0.10.x, ie:
		// * loginuid (4B)
		// * exe_writable (1B)
		// * cap_inheritable (8B)
		// * cap_permitted (8B)
		// * cap_effective (8B)
		// TOTAL: 29B
		bool pre_0_10_0 = false;
		if (sub_len - subreadsize <= 29)
		{
			pre_0_10_0 = true;
		}

		if (!pre_0_10_0)
		{
			// Ok we are in libs >= 0.10.x; read the fields that
			// were added interleaved in libs 0.10.0

			//
			// pidns_init_start_ts
			//
			if (sub_len && (subreadsize + sizeof(uint64_t)) <= sub_len)
			{
				readsize = r->read(r, &(tinfo.pidns_init_start_ts), sizeof(uint64_t));
				CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);
				subreadsize += readsize;
			}

			//
			// tty
			//
			if (sub_len && (subreadsize + sizeof(uint32_t)) <= sub_len)
			{
				readsize = r->read(r, &(tinfo.tty), sizeof(uint32_t));
				CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);
				subreadsize += readsize;
			}
		}

		//
		// loginuid (auid)
		//
		if (sub_len && (subreadsize + sizeof(uint32_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.loginuid), sizeof(uint32_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint32_t), error);
			subreadsize += readsize;
		}

		//
		// exe_writable
		//
		if (sub_len && (subreadsize + sizeof(uint8_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.exe_writable), sizeof(uint8_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint8_t), error);
			subreadsize += readsize;
		}

		//
		// Capabilities
		//
		if (sub_len && (subreadsize + sizeof(uint64_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.cap_inheritable), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);
			subreadsize += readsize;
		}

		if (sub_len && (subreadsize + sizeof(uint64_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.cap_permitted), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);
			subreadsize += readsize;
		}

		if (sub_len && (subreadsize + sizeof(uint64_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.cap_effective), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);
			subreadsize += readsize;
		}

		// exe_upper_layer
		if (sub_len && (subreadsize + sizeof(uint8_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.exe_upper_layer), sizeof(uint8_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint8_t), error);
			subreadsize += readsize;
		}

		// exe_ino
		if (sub_len && (subreadsize + sizeof(uint64_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.exe_ino), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);
			subreadsize += readsize;
		}

		// exe_ino_ctime
		if (sub_len && (subreadsize + sizeof(uint64_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.exe_ino_ctime), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);
			subreadsize += readsize;
		}

		// exe_ino_mtime
		if (sub_len && (subreadsize + sizeof(uint64_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.exe_ino_mtime), sizeof(uint64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint64_t), error);
			subreadsize += readsize;
		}

		// exe_from_memfd
		if (sub_len && (subreadsize + sizeof(uint8_t)) <= sub_len)
		{
			uint8_t exe_from_memfd = 0;
			readsize = r->read(r, &exe_from_memfd, sizeof(uint8_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint8_t), error);
			subreadsize += readsize;
			tinfo.exe_from_memfd = (exe_from_memfd != 0);
		}

		// exe_lower_layer
		if (sub_len && (subreadsize + sizeof(uint8_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.exe_lower_layer), sizeof(uint8_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(uint8_t), error);
			subreadsize += readsize;
		}

		// pgid
		if (sub_len && (subreadsize + sizeof(int64_t)) <= sub_len)
		{
			readsize = r->read(r, &(tinfo.pgid), sizeof(int64_t));
			CHECK_READ_SIZE_ERR(readsize, sizeof(int64_t), error);
			subreadsize += readsize;
		}

		//
		// All parsed. Add the entry to the table, or fire the notification callback
		//
		if (proclist->m_proc_callback == NULL)
		{
			//
			// All parsed. Allocate the new entry and copy the temp one into into it.
			//
			struct scap_threadinfo* ntinfo = (scap_threadinfo*)malloc(sizeof(scap_threadinfo));
			if (ntinfo == NULL)
			{
				fprintf(stderr, "process table allocation error (fd1)");
				return SCAP_FAILURE;
			}

			// Structure copy
			*ntinfo = tinfo;

			/*
			HASH_ADD_INT64(proclist->m_proclist, tid, ntinfo);
			*/
			if (uth_status != SCAP_SUCCESS)
			{
				free(ntinfo);
				fprintf(stderr, "process table allocation error (fd2)");
				return SCAP_FAILURE;
			}
		}
		else
		{
			int ret = proclist->m_proc_callback(proclist->m_proc_callback_context, error, tinfo.tid, &tinfo, NULL, NULL);
			if (ret == SCAP_FAILURE)
			{
				return ret;
			}
		}

		if (sub_len && subreadsize != sub_len)
		{
			if (subreadsize > sub_len)
			{
				fprintf(
				    stderr,
				    "corrupted input file. Had read %lu bytes, but proclist entry have length %u.",
				    subreadsize,
				    sub_len);
				return SCAP_FAILURE;
			}
			toread = sub_len - subreadsize;
			fseekres = (int)r->seek(r, (long)toread, SEEK_CUR);
			if (fseekres == -1)
			{
				fprintf(stderr, "corrupted input file. Can't skip %u bytes.", (unsigned int)toread);
				return SCAP_FAILURE;
			}
			subreadsize = sub_len;
		}

		totreadsize += subreadsize;
		subreadsize = 0;
	}

	//
	// Read the padding bytes so we properly align to the end of the data
	//
	if (totreadsize > block_length)
	{
		fprintf(stderr, "scap_read_proclist read more %lu than a block %u", totreadsize, block_length);
		assert(false);
		return SCAP_FAILURE;
	}
	padding_len = block_length - totreadsize;

	readsize = (size_t)r->read(r, &padding, (unsigned int)padding_len);
	CHECK_READ_SIZE_ERR(readsize, padding_len, error);

	return SCAP_SUCCESS;
}
