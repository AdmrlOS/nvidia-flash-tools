# Native recovery session (offline implementation, unqualified)

Build on Linux with an AArch64 cross compiler and static libcrypto in its sysroot:

```
/absolute/path/to/aarch64-linux-musl-gcc -O2 -Wall -Wextra -Werror -static recovery-io.c -lcrypto -pthread -ldl -o dist/recovery-io
```

Invocation inside selected RAM recovery only:
`recovery-io session /dev/nvmeNnM MAJOR MINOR CAPACITY 0 512 SERIAL MODEL SYSFS_DEVICE`
The process holds its one O_RDWR|O_EXCL|O_NOFOLLOW descriptor until Q/EOF/failure.
Before every operation it rechecks fstat rdev, ioctls, sysfs identity/path,
namespace/partition holders, mountinfo and swap block identities.

Requests: `>cQI32s` (45 bytes), operation R/W/Q, offset, length, SHA256.
R/W require aligned nonzero length <=4MiB within capacity. W is followed by
exactly length bytes; hash is checked before the first pwrite; fsync and readback
follow. Replies: `>I32s` then payload; R payload is actual read bytes; W payload
is SHA256 of actual readback. Q has zero offset/length and closes with status.
Malformed/truncated frames, wrong hashes or changed identities abort the session.

Host authenticates helper source/binary against release recovery.helper records,
pushes only bounded helper into an unpredictable mktemp private RAM directory,
checks remote SHA256, launches a no-PTY binary pipe, and retains that process.
The owned adapter requires negotiated `shell_v2` and `shell,v2,raw:`. It
multiplexes binary stdin/stdout separately from stderr, sends close-stdin, and
requires exactly one one-byte zero remote exit followed by EOF. Missing,
nonzero, duplicate, malformed or truncated exit framing fails native unlock;
legacy `shell:` EOF is never success. Each complete operation (including
feature negotiation/connect/status/body/exit) shares one monotonic deadline.
SYNC push resolves existing directories to source basename, preserves ordinary
source permissions (never special bits), and refuses symlink/special ancestors
and destinations using remote lstat. This is trusted selected RAM staging, not
an atomic no-follow remote filesystem API: SYNC cannot prevent a hostile target
from replacing paths after STAT. Hardware target trust remains a prerequisite.
It never uses shell dd or reopens the namespace per chunk. Chunk protocol hashes
are integrity checks, not remote attestation; trust rests on authenticated selected
RAM image, physical USB/ECID and the native binary pin.

package.py now builds a reproducible static aarch64 engineering bundle with
actual source/binary pins in engineering-manifest.json and engineering-release.json.
The original release.json remains unchanged; generated provenance grants no
approval or hardware qualification. Native host integration is exercised against
a locally compiled C subprocess and retained real regular-file FD, with only
block identity/sysfs boundaries mocked. No real block device is opened.


Timing: host requests have one 120s absolute operation deadline (all pipe phases).
The ADB shell bridge and host session have a distinct four-hour total install
budget. Bridge idle waits and complete frames are bounded to 120s; receiving
partial bytes cannot restart a frame deadline. Only complete frame/chunk progress
refreshes idle time, never total lifetime. Recovery helper syscall stalls are not
claimed independently interruptible; the host aborts/terminates on its deadline.

Output backpressure is charged to the same absolute shell frame operation deadline, including time already spent reading its header/body. It never receives a fresh frame budget. Real prefilled nonreading stdout/stderr pipe regressions enforce this with shortened limits.
