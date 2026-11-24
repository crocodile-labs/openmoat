# ADR-128: A microVM tier for `openmoat run`

Status: proposed (design; only the flag, the image definition and the score entries are
built) · Date: 2026-11-24 · Builds on ADR-018 (tiers), ADR-020 (the proxy), ADR-075 (the
guard relay), ADR-077 (full boundary), ADR-089 (the run's boundary record), ADR-108 (the
protection score) and ADR-115 (a tier's score that names what is missing)

## Context

Every tier of `openmoat run` shares the host's kernel. Seatbelt, Landlock, seccomp and
bubblewrap's namespaces narrow what a process may ask the kernel for; a kernel bug, a
missed system call or a path the profile forgot is a way out, and Seatbelt is
deprecated by its vendor. A virtual machine adds a boundary of another kind: the agent
and every command it starts run on a kernel of their own, and reach the host only
through the devices the VM monitor gives them.

Lightweight VM monitors start in well under a second: Firecracker and cloud-hypervisor
boot a Linux guest on KVM in about 125 ms of monitor time (Firecracker's published
figure; a guest's own init and the agent's start come on top), and Apple's
Virtualization.framework boots a Linux guest on macOS 12 and later with `VZLinuxBootLoader`,
shares folders with virtiofs (`VZVirtioFileSystemDeviceConfiguration`) and offers
host-to-guest sockets (`VZVirtioSocketDevice`). Coding-agent sandboxes elsewhere use the
same shape (a microVM per session, the project shared in, network through a proxy).

What makes it hard for OpenMoat is not the monitor but the hook. The agent's hook runs
`openmoat guard` as a child process and the guard reads the policy, the lock and the
audit log under `~/.moat`; inside a VM there is no `~/.moat`, and there must not be one
the agent can write.

## Decision

1. **A fourth tier, chosen with `--vm`.** `openmoat run --vm -- <agent>` asks for the
   microVM tier; it never starts by default, and `--vm` with `--isolate`, `--no-isolate`
   or `--listen` is a usage error. Where it cannot start, it refuses (exit 64) and says
   why, never falling back to another tier, since a person who asked for a VM must not
   get less without being told. Until the tier is built it refuses everywhere, naming
   what this system would use and what the policy's image definition says.

2. **What the VM monitor is, per platform.** macOS: Apple Virtualization.framework
   (macOS 12 or later, Apple silicon or Intel), started from the `openmoat` binary itself
   with the `com.apple.security.virtualization` entitlement. Linux: Firecracker, or
   cloud-hypervisor where Firecracker's device model lacks what is needed (virtiofs), on
   KVM (`/dev/kvm` readable and writable by the person). Windows and other systems: no VM
   tier (Hyper-V is not covered by this design).

3. **What the VM sees.** A read-only root image and kernel from the policy's
   `sandbox.vm.image` (below), the project shared in by virtiofs at its own path, the
   run's `--write` paths and a temporary directory, and nothing else of the host: no home
   directory, no agent configuration outside the project, no `~/.moat`. Paths the policy
   denies inside the project are hidden as the Isolated tier hides them (ADR-080). The
   agent's own state directory (`~/.claude`) is a VM-local copy the run makes from the
   files the agent needs to start, and its writes go back only through `--write`.

4. **Network only through OpenMoat's proxy.** The guest gets no network device. A vsock
   port is the one way out: the guest's init serves a loopback HTTP proxy port inside
   the VM that forwards to `openmoat proxy` on the host over vsock, as the Isolated
   tier's Unix socket does (ADR-080). DNS is the proxy's. A `--listen` port is not
   offered.

5. **The hook still reaches `openmoat guard`.** Inside the VM the agent's hook runs a
   small `openmoat guard` client that sends the hook's payload over a second vsock port
   to the guard relay on the host (ADR-075's relay, which already serves sandboxed
   agents through a socket and a per-run token) and prints the host's answer. The
   policy, the lock and the audit log stay on the host. A guest that cannot reach the
   relay denies every call (invariant 4).

6. **The image is pinned by the policy.** `sandbox.vm` in the person's own policy:

   ```yaml
   sandbox:
     vm:
       image:
         kernel: { path: ~/.local/share/openmoat/vm/vmlinux, sha256: <64 hex> }
         rootfs: { path: ~/.local/share/openmoat/vm/rootfs.ext4, sha256: <64 hex> }
         initrd: { path: …, sha256: … }        # optional
         cmdline: "quiet"                       # optional, appended to OpenMoat's own
       memory_mib: 2048                         # 256 to 65536, default 2048
       cpus: 2                                  # 1 to 64, default 2
   ```

   Paths are absolute or `~/…`; each digest is checked before the boot, and a file that
   does not match refuses the run. `cmdline` cannot carry `init=`, `rdinit=` or a
   control character: OpenMoat's own init (which mounts the project and serves the
   proxy and guard ports) must be the guest's first process. OpenMoat downloads no image:
   the person builds or fetches one and names it; a reference image's build recipe is
   future work. The policy lock pins the definition like the rest of the policy.

7. **The score.** The VM tier has its own table, since its boundary is of another kind
   (a score compares runs on one platform and tier, ADR-108):

   | Feature | Weight | Meaning |
   |---|---|---|
   | `vm_hypervisor` | 35 | the agent runs on a kernel of its own (KVM, Virtualization.framework) |
   | `vm_project_only` | 20 | the guest sees the project and `--write` paths, no home |
   | `vm_proxy_network` | 25 | no network device; only the vsock port to the proxy |
   | `vm_guard_relay` | 10 | the hook reaches `openmoat guard` on the host over vsock |
   | `vm_image_pinned` | 10 | kernel and root image match `sandbox.vm.image`'s digests |

   Each is named as not built until it is, so `--vm` scores 0/100 today with every
   feature named.

8. **Start-up cost.** Measured, not promised: the run records the monitor's start, the
   guest's init and the agent's first hook call in the boundary record, and `openmoat
   bench` gains a row for them once the tier starts anything.

## What is built now

The flag and its refusal (`commands/run/vm.rs`, the host check per platform in
`commands/run/vm/`), the `sandbox.vm` model and its lint (`openmoat-core` `vm.rs`, the
JSON schema), and the score entries (`boundary/vm.rs`). Nothing boots.

## What is left

The VM monitor's start on each platform, the guest's init and its image recipe, the
virtiofs share and the denied-path view, the vsock proxy and guard bridges, the guest
side of `openmoat guard`, the digest check at boot, the boundary record's VM fields, the
macOS entitlement in the release build, measurements, and end-to-end tests that need a
hypervisor (none runs in CI today).

## Alternatives considered

- **Containers (Docker, Podman) as the tier.** They share the kernel too, need a daemon
  or rootless setup, and the agent often has the Docker socket (`containers` denies it
  for that reason).
- **gVisor.** A user-space kernel on Linux only; no macOS answer.
- **A bundled image download.** A download path is an update channel that needs signing,
  pinning and a release process of its own; naming local files with their digests is
  the smallest safe step.
- **Running the guard inside the VM.** It would need the policy and lock inside, which
  the agent's kernel could then change; the host keeps both.

## Consequences

- `openmoat run --vm` exists and refuses with a clear message on every system; the
  docs mark the tier as design.
- `sandbox.vm` is checked by `openmoat policy lint` now, so a definition written today is
  read the same way once the tier boots.
- Score tables gain a VM row; Linux, macOS and Windows scores are unchanged.
