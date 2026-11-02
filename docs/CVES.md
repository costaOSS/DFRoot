# Page-cache primitives and the rest of the CVE set

DFRoot began as one bug: CVE-2026-43284 ("DirtyFrag"), an AES-CBC ESP
decrypt that runs in place over an skb whose frags are pipe pages, so the
decrypt writes back into a file's page cache. Everything below either
reaches the same place by another route or is listed because it looks
tempting and is not reachable from an app process.

Every primitive here writes page cache through an `O_RDONLY` descriptor
that the process is already allowed to open. DFRoot consumes the patched
bytes from cache (execve, insmod, dlopen), so the disk copy is never part
of the chain.

## Selection

`libdfroot.so` takes
`--primitive auto|xfrm|copyfail|dirtycow|dirtypipe`, and `--probe` to
report what the kernel and sandbox allow without patching anything:

```
./libdfroot.so --probe
./libdfroot.so --probe --primitive dirtycow    # exit 0 = usable
./libdfroot.so --probe --primitive dirtypipe   # exit 0 = usable
```

`auto` tries CopyFail, then Dirty COW, then XFRM. Dirty Pipe is only used if explicitly
requested with `--primitive dirtypipe` because it cannot write at a page
boundary or across one (ruling out the page-aligned KO image). A primitive
that probes
usable but fails mid-patch is abandoned after the first failed block and
the run continues on XFRM.

## Implemented

| CVE | Bug | Granularity | App-reachable? |
|---|---|---|---|
| CVE-2026-43284 | DirtyFrag: XFRM ESP AES-CBC decrypt in place over spliced pipe pages | 16 bytes, key-derived | yes, via `IpSecManager` (API 28+); needs the crash_dump bridge for `vendor_file` |
| CVE-2026-31431 | CopyFail: `authencesn` ESN helper stores a 4-byte sequence word past the destination | 4 bytes | only if the app sandbox permits `socket(AF_ALG, ...)`; probe decides |
| CVE-2016-5195 | Dirty COW: COW race in `get_user_pages` writes the page cache | any length, page-chunked | yes on every kernel before 4.8.3 / 4.7.9 / 4.4.26, including 3.x; needs a readable fd and `/proc/self/mem` |
| CVE-2022-0847 | Dirty Pipe: `pipe_buffer` with `PIPE_BUF_FLAG_CAN_MERGE` over a page-cache page | any length within one page | yes on unpatched 5.8-5.16 kernels; needs an open fd |

### CVE-2026-31431 — CopyFail

`aead` / `authencesn(hmac(sha256),cbc(aes))` is a decrypt-in-place AEAD.
Its ESN helper writes the 4-byte sequence number at
`dst + assoclen - 4`, i.e. four bytes past the data it was handed. When
the destination skb is built from pages spliced out of a file, those four
bytes land in the file's page cache.

The published PoC splices `off + 4` bytes from the start of the file, so the
stray word lands at `off` and everything before it is scrambled on the way.
This port applies the same placement rule (the word is the last four bytes of
the stream) to a four-byte slice at `off`: O(1), and nothing else in the file
changes. A `pread` readback gates every word; if a kernel places it
differently the write is rejected and the caller falls back to XFRM instead of
risking the prefix. Word granularity is four bytes.

Why it usually is not the app's answer: Android's app seccomp policy and
its SELinux `app_domain` rules restrict `socket()` address families, and
`AF_ALG` is not among the app-allowed families. `--probe` reports this as
`blocked` and selection moves on. It is still worth carrying because the
probe is authoritative per device, some vendor policies differ, and the
same code is the natural fit for a domain that does allow `AF_ALG`.

### CVE-2016-5195 — Dirty COW

A `MAP_PRIVATE` read-only mapping of the target file is raced against a
write through `/proc/self/mem`. The write takes the COW slow path while
`MADV_DONTNEED` drops the private copy, and the kernel writes into the
page cache page instead of a private one. Only a readable descriptor is
needed; there is no page-boundary restriction, so unlike Dirty Pipe it can
carry the page-aligned KO image.

```
dirtycow_write(fd, off, src, len):
  for each page touched:
    map  = mmap(file page, PROT_READ, MAP_PRIVATE, fd)
    thread: while (!stop) madvise(map, PAGE, MADV_DONTNEED)
    repeat up to 4000x:
      pwrite(/proc/self/mem, src, n, map + in_page)
      if pread(fd, ..., off) == src: done
```

Introduced in 2.6.22 and fixed in 4.8.3, 4.7.9 and 4.4.26. Every 4.x
release before its branch fix is vulnerable, and so is 3.x. This is the
only page-cache write primitive that exists on 4.x: CopyFail needs the
`authencesn` ESN helper (2026 code), DirtyFrag needs the ESP in-place path,
and Dirty Pipe needs 5.8+.

It is a race, so failures are possible. Verification is a `pread` of the
page cache after every page, and one page that refuses to land abandons
the primitive for XFRM. It needs the app sandbox to allow writing its own
`/proc/self/mem`; the probe is a `uname` check only, so an explicit
`--primitive dirtycow` run can still fail mid-patch on a hardened vendor
policy and fall back.

### CVE-2022-0847 — Dirty Pipe

Fill and drain a pipe so every `pipe_buffer` has `CAN_MERGE`, then
`splice()` one byte from `off - 1` so the buffer points at that page, and
`write()` appends at `off`. It cannot start on a page boundary and cannot
cross one, so writes are chunked. Works on 5.8 through the fixes in
5.10.102, 5.15.25 and 5.16.11; the 5.8, 5.9 and 5.11-5.14 branches are
end-of-life and never got the fix.

This is the strongest app-side fallback: it needs only `pipe`, `splice`,
`write` and `pread`, all of which the sandbox permits.

### CVE-2026-43284 — DirtyFrag (baseline)

The existing path. The app asks `IpSecManager` for a UDP encapsulation
socket and an SPI, installs a transport-mode AES-CBC transform, and sends
16-byte ESP packets whose ciphertext is the page it wants to change. The
IV is chosen so the in-place decrypt produces the desired bytes:

```
IV = AES_DEC(key, old_content) XOR desired
```

System files are spliced directly. `vendor_file` is not readable by
`untrusted_app`, so `splicehelper` is patched into `crash_dump64`, which
runs in the `crash_dump` domain and can open it; the helper splices the
vendor page into the pipe and the ESP write lands on it.

## Handoff mode

CopyFail and Dirty Pipe need a descriptor for the file they write. For
system files that is just `open(path, O_RDONLY)`. For `vendor_file` the
app cannot open it, so `splicehelper` gains mode `"h"`: it opens the path,
then sends the descriptor back over `fd 1` with `SCM_RIGHTS`.

The socket is required. `spawn_crash_dump` clones with
`CLONE_VFORK | CLONE_VM` but no `CLONE_FILES`, so the child has its own
descriptor table and a `dup2` in the child is invisible to the parent.
`SCM_RIGHTS` passes the open file description, not a path, so no new
permission check happens on use.

Order of operations (unchanged by the primitives):

1. `patch_helper` — `crash_dump64` page cache, direct fd.
2. `patch_ko` — `vendor_file` page cache; with a page-cache primitive this
   uses the handed-off fd, otherwise the XFRM helper splice.
3. `patch_hook` — `libc++.so`, direct fd.


## Kernel 4.x (4.0 - 4.20, LTS 4.4 / 4.9 / 4.14 / 4.19)

Last releases: 4.20.17, 4.19.325, 4.14.336, 4.9.337, 4.4.302. All are
end-of-life upstream; Android vendor trees on these branches froze much
earlier, usually at their launch LTS level plus a security-patch stream.

Only one bug on that range plugs into DFRoot's model directly:

| CVE | Reachable from an app | Notes |
|---|---|---|
| CVE-2016-5195 Dirty COW | yes | page-cache write, all 4.x before 4.8.3 / 4.7.9 / 4.4.26; implemented here as `dirtycow` |

Everything else on 4.x that gives kernel memory access needs a full chain
(KASLR leak plus arbitrary write), not a file write, so it cannot replace
the current patch stage. They are catalogued for completeness; a port
would add a new exploit stage, not a primitive.

| CVE | Bug | Affected 4.x | Fix boundary | App trigger |
|---|---|---|---|---|
| CVE-2019-2215 | binder UAF in `binder_thread_release` / epoll | 4.4, 4.9, 4.14, 4.19 | Oct 2019 ASB; upstream f5cb779 in 4.14.150 / 4.19.75 / 4.9.196 | yes, binder + `BINDER_THREAD_EXIT` |
| CVE-2019-2025 | binder race in `binder_transaction` | 4.4, 4.9, 4.14 | Sep 2019 upstream, Jan 2020 ASB | yes, binder |
| CVE-2020-0041 | binder out-of-bounds write | 4.14, 4.19 | Mar 2020 ASB | yes, binder |
| CVE-2020-0423 | binder UAF | 4.14, 4.19 | Oct 2020 ASB | yes, binder |
| CVE-2021-0920 | `unix_gc` UAF (garbage collector vs. inflight sockets) | 4.14, 4.19, 5.x | Nov 2021 ASB; 4.19.219 / 4.14.256 | yes, `AF_UNIX` |
| CVE-2023-20938 | binder UAF in `binder_transaction_buffer_release` | 4.14, 4.19, 5.x | Feb 2023 ASB | yes, binder |
| CVE-2017-1000112 | UDP fragmentation offload writes past skb tail | before 4.13 | fixed in 4.13 (stable backports) | yes, plain UDP, no caps |
| CVE-2017-7533 | inotify/fsnotify race corrupts a slab object | before 4.12.4 | 4.12.4 / 4.9.40 / 4.4.84 | yes, inotify + rename race |
| CVE-2017-6074 | DCCP double free | before 4.10 | 4.9.6 / 4.4.40 era | DCCP sockets; module often absent |
| CVE-2016-8655 | `AF_PACKET` race in `packet_set_ring` | before 4.9 | 4.8.12 / 4.4.36 era | needs `CAP_NET_RAW`, so not an app |
| CVE-2020-0069 | MediaTek `cmdq` ioctl | MTK SoCs, no upstream fix | vendor | yes on MediaTek; the MtkSu path |

The 4.x LKM problem is separate from the primitive: DFRoot ships
prebuilt KOs only for the GKI KMIs (5.10 and later). A 4.x Android
kernel is a vendor kernel with its own `vermagic` and, usually,
`CONFIG_MODVERSIONS` CRCs, so there is no prebuilt KO that can load. Root
on 4.x therefore needs the KO rebuilt against that device's kernel tree.
The LKM itself is mostly portable: `kallsyms_lookup_name` is exported
through 4.14/4.19 (and reachable by kprobe), kprobes exist, and
`selinux_state` exists from 4.13; on 4.4/4.9 the equivalent is the
`selinux_enforcing` global, which needs a small ifdef. KernelSU on 4.x
has the same shape: its LKM mode targets GKI 5.10+, so on 4.x it must be
built into the kernel, not loaded as a module.

## Catalog only — not reachable from an app

| CVE | Why not |
|---|---|
| CVE-2026-43500 | RxRPC: needs uid 1000 and a keyring the app cannot create |
| CVE-2026-46300 | Fragnesia: needs a user namespace plus `CAP_NET_ADMIN` |
| CVE-2026-46331 | `act_pedit`: needs `CAP_NET_ADMIN` in the netns |
| CVE-2026-31694 | FUSE readdir out-of-bounds read; no write primitive |
| CVE-2026-46242 | "Bad Epoll"; public app-usable PoC not established |
| CVE-2026-0091 | no public app-usable PoC |
| CVE-2026-58766 | no public app-usable PoC |
| CVE-2026-58728 | no public app-usable PoC |
| CVE-2026-0029 | no public app-usable PoC |
| CVE-2023-0386 | overlayfs copy-up; needs unprivileged userns, disabled on Android |
| CVE-2024-1086 | nf_tables; needs unprivileged userns, disabled on Android |

These stay on the watch list. A CVE becomes useful here only when it (a)
writes page cache or another object reachable from an app, (b) is
triggerable with the syscalls the sandbox leaves open, and (c) has a
published, working trigger for the kernel branch in question.

## Limits

- All four primitives fail closed if the file's page is not cacheable or
  the descriptor is not readable.
- CopyFail is 4-byte granular and needs a writable AF_ALG endpoint;
  Dirty COW is a race (page-verified, retried) and needs a writable
  `/proc/self/mem`; Dirty Pipe is page-bound and cannot cross page
  boundaries or start on one (opt-in only, unsuitable for the KO image);
  XFRM needs `IpSecManager` to build the transform.
- `auto` and `xfrm` always build an ESP transform, so a page-cache failure
  degrades to ESP mid-run. An explicitly selected `copyfail`, `dirtycow`
  or `dirtypipe` run builds one too when the device allows it, but
  continues if it does not; on such a device a mid-run failure ends the
  run instead of degrading.
- Restoring the original bytes in `cleanup()` uses the selected primitive.
  If it was abandoned mid-run, restore falls back to XFRM and may be a
  no-op on a kernel where XFRM is fixed. That leaves the patched page in
  cache, which is the intended state for the running exploit; a reboot
  clears it.
