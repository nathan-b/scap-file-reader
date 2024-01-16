// It's awful that I have to copy / paste some of this stuff, but maintaining
// compatibility with the falco libs is the greater nightmare....

#ifndef SCAP_REDEFS_H
#define SCAP_REDEFS_H

#include <scap_limits.h>

typedef enum scap_fd_type
{
	SCAP_FD_UNINITIALIZED = -1,
	SCAP_FD_UNKNOWN = 0,
	SCAP_FD_FILE = 1,
	SCAP_FD_DIRECTORY = 2,
	SCAP_FD_IPV4_SOCK = 3,
	SCAP_FD_IPV6_SOCK = 4,
	SCAP_FD_IPV4_SERVSOCK = 5,
	SCAP_FD_IPV6_SERVSOCK = 6,
	SCAP_FD_FIFO = 7,
	SCAP_FD_UNIX_SOCK = 8,
	SCAP_FD_EVENT = 9,
	SCAP_FD_UNSUPPORTED = 10,
	SCAP_FD_SIGNALFD = 11,
	SCAP_FD_EVENTPOLL = 12,
	SCAP_FD_INOTIFY = 13,
	SCAP_FD_TIMERFD = 14,
	SCAP_FD_NETLINK = 15,
	SCAP_FD_FILE_V2 = 16,
	SCAP_FD_BPF = 17,
	SCAP_FD_USERFAULTFD = 18,
	SCAP_FD_IOURING = 19,
}scap_fd_type;


typedef struct scap_fdinfo
{
	int64_t fd; ///< The FD number, which uniquely identifies this file descriptor.
	uint64_t ino; ///< The inode.
	scap_fd_type type; ///< This file descriptor's type.
	union
	{
		struct
		{
		  uint32_t sip; ///< Source IP
		  uint32_t dip; ///< Destination IP
		  uint16_t sport; ///< Source port
		  uint16_t dport; ///< Destination port
		  uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv4info; ///< Information specific to IPv4 sockets
		struct
		{
			uint32_t sip[4]; ///< Source IP
			uint32_t dip[4]; ///< Destination IP
			uint16_t sport; ///< Source Port
			uint16_t dport; ///< Destination Port
			uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv6info; ///< Information specific to IPv6 sockets
		struct
		{
		  uint32_t ip; ///< Local IP
		  uint16_t port; ///< Local Port
		  uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv4serverinfo; ///< Information specific to IPv4 server sockets, e.g. sockets used for bind().
		struct
		{
			uint32_t ip[4]; ///< Local IP
			uint16_t port; ///< Local Port
			uint8_t l4proto; ///< Transport protocol. See \ref scap_l4_proto.
		} ipv6serverinfo; ///< Information specific to IPv6 server sockets, e.g. sockets used for bind().
		struct
		{
			uint64_t source; ///< Source socket endpoint
		  	uint64_t destination; ///< Destination socket endpoint
			char fname[SCAP_MAX_PATH_SIZE]; ///< Name associated to this unix socket
		} unix_socket_info; ///< Information specific to unix sockets
		struct
		{
			uint32_t open_flags; ///< Flags associated with the file
			char fname[SCAP_MAX_PATH_SIZE]; ///< Name associated to this file
			uint32_t mount_id; ///< The id of the vfs mount the file is in until we find dev major:minor
			uint32_t dev; ///< Major/minor number of the device containing this file
		} regularinfo; ///< Information specific to regular files
		char fname[SCAP_MAX_PATH_SIZE];  ///< The name for file system FDs
	}info;
}scap_fdinfo;

typedef struct scap_threadinfo
{
	uint64_t tid; ///< The thread/task id.
	uint64_t pid; ///< The id of the process containing this thread. In single thread processes, this is equal to tid.
	uint64_t ptid; ///< The id of the thread that created this thread.
	uint64_t sid; ///< The session id of the process containing this thread.
	uint64_t vpgid; ///< The process group of this thread, as seen from its current pid namespace
	char comm[SCAP_MAX_PATH_SIZE+1]; ///< Command name (e.g. "top")
	char exe[SCAP_MAX_PATH_SIZE+1]; ///< argv[0] (e.g. "sshd: user@pts/4")
	char exepath[SCAP_MAX_PATH_SIZE+1]; ///< full executable path
	bool exe_writable; ///< true if the original executable is writable by the same user that spawned it.
	bool exe_upper_layer; //< True if the original executable belongs to upper layer in overlayfs
	bool exe_from_memfd;  //< True if the original executable is stored in pathless memory referenced by a memfd
	char args[SCAP_MAX_ARGS_SIZE+1]; ///< Command line arguments (e.g. "-d1")
	uint16_t args_len; ///< Command line arguments length
	char env[SCAP_MAX_ENV_SIZE+1]; ///< Environment
	uint16_t env_len; ///< Environment length
	char cwd[SCAP_MAX_PATH_SIZE+1]; ///< The current working directory
	int64_t fdlimit; ///< The maximum number of files this thread is allowed to open
	uint32_t flags; ///< the process flags.
	uint32_t uid; ///< user id
	uint32_t gid; ///< group id
	uint64_t cap_permitted; ///< permitted capabilities
	uint64_t cap_effective; ///< effective capabilities
	uint64_t cap_inheritable; ///< inheritable capabilities
	uint64_t exe_ino; ///< executable inode ino
	uint64_t exe_ino_ctime; ///< executable inode ctime (last status change time)
	uint64_t exe_ino_mtime; ///< executable inode mtime (last modification time)
	uint64_t exe_ino_ctime_duration_clone_ts; ///< duration in ns between executable inode ctime (last status change time) and clone_ts
	uint64_t exe_ino_ctime_duration_pidns_start; ///< duration in ns between pidns start ts and executable inode ctime (last status change time) if pidns start predates ctime
	uint32_t vmsize_kb; ///< total virtual memory (as kb)
	uint32_t vmrss_kb; ///< resident non-swapped memory (as kb)
	uint32_t vmswap_kb; ///< swapped memory (as kb)
	uint64_t pfmajor; ///< number of major page faults since start
	uint64_t pfminor; ///< number of minor page faults since start
	int64_t vtid;  ///< The virtual id of this thread.
	int64_t vpid; ///< The virtual id of the process containing this thread. In single thread threads, this is equal to vtid.
	uint64_t pidns_init_start_ts; ///<The pid_namespace init task start_time ts.
	char cgroups[SCAP_MAX_CGROUPS_SIZE];
	uint16_t cgroups_len;
	char root[SCAP_MAX_PATH_SIZE+1];
	int filtered_out; ///< nonzero if this entry should not be saved to file
	scap_fdinfo* fdlist; ///< The fd table for this process
	uint64_t clone_ts; ///< When the clone that started this process happened.
	int32_t tty; ///< Number of controlling terminal
  int32_t loginuid; ///< loginuid (auid)
}scap_threadinfo;

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

#endif
