package proc

/*
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
	int  pid;
	int  found;
	int  remote_port;
	char name[512];
	char path[2048];
} cf_proc_result;

// 按本地端口号反查发起连接的进程。遍历系统所有进程的文件描述符，
// 找出持有该本地端口的 TCP/UDP socket。
static void cf_lookup_port(cf_proc_result *out, int target_port, int want_udp) {
	out->found = 0;
	out->pid = 0;
	out->name[0] = 0;
	out->path[0] = 0;

	int pids[8192];
	int count = proc_listallpids(pids, (int)sizeof(pids));
	if (count <= 0) return;

	// 进程数量可能在两次系统调用间增长，不能越过固定数组边界。
	if (count > (int)(sizeof(pids) / sizeof(pids[0]))) count = (int)(sizeof(pids) / sizeof(pids[0]));
	for (int i = 0; i < count; i++) {
		int pid = pids[i];
		if (pid <= 0) continue;

		int bufSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, 0, 0);
		if (bufSize <= 0) continue;

		struct proc_fdinfo *fds = (struct proc_fdinfo *)malloc((size_t)bufSize);
		if (!fds) continue;

		int nFds = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, bufSize);
		if (nFds > 0) {
			int fdCount = nFds / (int)sizeof(struct proc_fdinfo);
			for (int f = 0; f < fdCount; f++) {
				if (fds[f].proc_fdtype != PROX_FDTYPE_SOCKET) continue;

				struct socket_fdinfo si;
				int r = proc_pidfdinfo(pid, fds[f].proc_fd, PROC_PIDFDSOCKETINFO, &si, PROC_PIDFDSOCKETINFO_SIZE);
				if (r <= 0) continue;

				int family = si.psi.soi_family;
				int kind = si.psi.soi_kind;
				int matched = 0;

				if (!want_udp && family == AF_INET && kind == SOCKINFO_TCP) {
					int lport = (int)ntohs(si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
					if (lport == target_port) {
						out->remote_port = (int)ntohs(si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport);
						matched = 1;
					}
				} else if (want_udp && family == AF_INET && kind == SOCKINFO_IN) {
					int lport = (int)ntohs(si.psi.soi_proto.pri_in.insi_lport);
					if (lport == target_port) {
						out->remote_port = (int)ntohs(si.psi.soi_proto.pri_in.insi_fport);
						matched = 1;
					}
				}

				if (matched) {
					out->found = 1;
					out->pid = pid;
					proc_name(pid, out->name, (int)sizeof(out->name));
					proc_pidpath(pid, out->path, (int)sizeof(out->path));
					free(fds);
					return;
				}
			}
		}
		free(fds);
	}
}
*/
import "C"

import (
	"sync"
	"time"
)

// Identity 描述一条连接背后的 macOS 进程。
type Identity struct {
	PID        int32
	Name       string
	Path       string
	ResolvedAt time.Time
}

// Resolver 按本地端口反查进程，带短时缓存，避免高频遍历全系统 fd。
type Resolver struct {
	mu       sync.Mutex
	cache    map[uint64]Identity
	ttl      time.Duration
	negative map[uint64]time.Time
}

// NewResolver 创建短时缓存的进程识别器。
// param ttl 为正负缓存期限，非正数使用三秒；返回依赖 libproc 的解析器。
func NewResolver(ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = 3 * time.Second
	}
	return &Resolver{
		cache:    make(map[uint64]Identity),
		ttl:      ttl,
		negative: make(map[uint64]time.Time),
	}
}

// Lookup 根据本地端口与协议反查进程。isUDP 区分 TCP/UDP。
// param localPort/isUDP 为源端口及协议；返回零值时表示未能定位到进程，失败缓存到期后重新查询。
func (r *Resolver) Lookup(localPort uint16, isUDP bool) Identity {
	key := (uint64(localPort) << 1)
	if isUDP {
		key |= 1
	}

	r.mu.Lock()
	if id, ok := r.cache[key]; ok && time.Since(id.ResolvedAt) < r.ttl {
		r.mu.Unlock()
		return id
	}
	if missedAt, ok := r.negative[key]; ok {
		// 失败缓存必须过期，否则短连接复用该端口后永远无法识别应用。
		if time.Since(missedAt) < r.ttl {
			r.mu.Unlock()
			return Identity{}
		}
		delete(r.negative, key)
	}
	r.mu.Unlock()

	var result C.cf_proc_result
	C.cf_lookup_port(&result, C.int(localPort), boolToInt(isUDP))

	id := Identity{ResolvedAt: time.Now()}
	if result.found != 0 {
		id.PID = int32(result.pid)
		id.Name = C.GoString(&result.name[0])
		id.Path = C.GoString(&result.path[0])
	}

	r.mu.Lock()
	if result.found != 0 {
		r.cache[key] = id
		delete(r.negative, key)
	} else {
		r.negative[key] = time.Now()
	}
	r.mu.Unlock()

	return id
}

// boolToInt 为 libproc 包装转换协议标志。
// param b 为布尔值；返回 C 整数 1 或 0，无失败分支。
func boolToInt(b bool) C.int {
	if b {
		return 1
	}
	return 0
}
