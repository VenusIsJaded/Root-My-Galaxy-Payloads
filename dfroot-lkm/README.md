# dfroot-lkm

The kernel module the universal root's chain loads, built one per KMI.

## Where it comes from

[DFRoot](https://github.com/diabl0w/DFRoot) at `e47ea6e` — the commit that removed the libc patch from
that chain and moved the privileged half into this module. The chain's shellcode now `insmod`s it and does
nothing else; the module forces SELinux permissive, defeats defex with two kprobes
(`task_defex_user_exec`, `get_dc_target_dpath`), runs the daemon's `late-load` from kernel context with
`call_usermodehelper`, writes `/dev/dfm0` on success or `/dev/dfm1` on failure, and returns `-E2BIG` so it
unloads itself. There is no `module_exit` and no unload path.

## What differs from that revision

Three things about the command, and nothing else in it:

1. **The daemon path.** Upstream names their own package (`/data/user_de/0/df.root/ksud`); this names
   `/data/user_de/0/dev.rushiranpise.rmgnext/ksud`, which is where the app stages the daemon it downloaded
   — the same path the chain's shellcode read before this change.
2. **`package_name` is a module parameter**, not a compiled-in literal. One chain serves KernelSU,
   KernelSU-Next and ReSukiSU, and the manager the daemon is told to serve is what the app chose for this
   run; a literal here would crown upstream's manager for all three.
3. **`--ro-partitions` and `--soft-reboot` are not passed.** Both are options of upstream's KernelSU fork
   rather than of the daemons built here, and both behaviours already exist in the app: the read-only
   partition wall, and *Auto soft restart*. Passing them would make the daemon refuse its own command line.

Five further differences are about a run having to end in an *answer* rather than in silence — the
markers are the only channel the chain's parent side can read, and a run that leaves neither is the
failure that costs a diagnostic round to interpret:

4. **Every failure ends in `/dev/dfm1`.** Upstream's early exits — no `kallsyms_lookup_name`, no SELinux
   symbol, no usermode-helper symbols — returned before the command ran, leaving no marker at all. Each
   of those paths now writes `/dev/dfm1` first.
5. **The markers are cleared before the command runs.** `/dev` is per-boot but a payload run is not the
   only one per boot — the P0 supervisor keeps attempting after a stack writer has run — so a leftover
   `/dev/dfm0` would be read as this run's success. The command clears both, then writes exactly one.
6. **A run that ends without `/dev/dfm0` is retried**, three attempts half a second apart, keyed on the
   marker rather than the helper's exit status (the shell ends in `touch` either way). The command is
   idempotent — it re-stages the daemon each attempt, and `late-load` skips the module load when KernelSU
   is already present — so a partial failure is safe to re-run.
7. **A truncated command never runs.** `snprintf`'s return is checked against the buffer; a command that
   did not fit is refused with `/dev/dfm1` rather than executed half-built.
8. **Quiet by default, tidy on success.** The `pr_*` lines sit behind a `debug` module parameter (default
   off), because the log lines themselves are the most obvious thing a rooted run leaves in the kernel
   ring buffer. On success the shell also removes the daemon's log and the stage file — the log exists so
   a *refusal* can be read later, and a rooted run does not need to leave one in `/data/local/tmp`. On
   failure both stay for the diagnostic round.

Two portability fallbacks sit underneath all of that, because one build serves KMIs that do not agree:
`selinux_enforcing` is written when a kernel has no `selinux_state`, and `call_usermodehelper` is used
when the setup/exec pair cannot be resolved. Marker plumbing resolves `filp_open`/`filp_close` through
kprobes before anything else, so the failure paths in (4) work even where `kallsyms_lookup_name` itself
is unavailable.

## Building it

The workflow is `.github/workflows/dfroot-lkm.yml`: a matrix over the eight KMIs, each inside
`ghcr.io/ylarod/ddk-min:<kmi>-<release>`, then the same size diet upstream applies — `-Os`, unwind tables
dropped, `llvm-objcopy --strip-unneeded` and the `-R` removals — because the module is written through the
exploit page by page and its size is a page count.

The artifacts are `dirtyfrag-<kmi>.ko`, and they belong in the app's
`app/src/main/cpp/dfroot/ko/`, which is where the chain embeds them from (`.incbin`, see that directory's
`CMakeLists.txt`). Nothing here is device-specific: one build covers every device whose kernel belongs to
that KMI.

The workflow also checks what a rebase could silently undo — that the built module still names **this**
app's daemon path and carries **neither** of the two fork-only flags — because all three of those live in
strings that a merge resolves without a conflict.
