// DFRoot's late-load LKM, built for the universal root.
//
// From https://github.com/diabl0w/DFRoot at e47ea6e ("Major refactor: Remove libc
// patching -> use insmod directly in libc++ Move most heavy lifting to custom LKM"),
// where the chain stopped patching libc, stopped exec'ing a daemon from its shellcode
// and stopped running modprobe: the shellcode now insmods this module, and this module
// does the privileged half in kernel context.
//
// Three things differ from that revision about the command it runs, and they are the
// whole of this file's difference from upstream's *intent*:
//
//   1. the daemon path. Upstream names their own package (`/data/user_de/0/df.root/ksud`);
//      the chain reads the daemon the app stages, which is under this app's id.
//   2. `package_name` is a module parameter rather than a compiled-in literal. This
//      project's chain drives one library for three KernelSU projects, and the manager
//      the daemon is told to serve is a value the app chooses per run - a literal here
//      would grant root to whichever manager upstream ships.
//   3. the `--ro-partitions` and `--soft-reboot` arguments are not passed. Both are
//      options of upstream's KernelSU fork rather than of the daemons this project's
//      payload repository builds, and both behaviours already exist in the app (the
//      read-only partition wall, and Auto soft restart) - so passing them would make
//      the daemon fail to parse its own command line.
//
// And one thing this chain has to do that upstream's does not: **stage the daemon**.
//
// The daemon built for this project runs `late-load` in two halves. Its first act is to
// rename `/data/local/tmp/.ksud-stage` onto `/data/adb/ksud`, because the install has to
// happen before loading the module changes this process's security context; that file is
// the daemon's own bytes, put there by whoever wants it installed. The payload flow
// stages it as part of every run, and an install **consumes** it - so a universal run,
// which is the other flow entirely, found nothing to rename and exited non-zero before
// it did anything at all. That is what `/dev/dfm1` was saying.
//
// So this command writes it as well, from the daemon the app staged: this runs as root,
// with the app's data directory readable, which is the one place that can. The same
// three facts the payload flow's staging pass keep apply here - the file is the daemon
// this run resolved, it is executable, and it is where that daemon's own `late-load`
// looks for it.
//
// The markers are upstream's and unchanged: /dev/dfm0 for "late-load completed",
// /dev/dfm1 for "it did not", which is what the chain's parent side reports on. The
// daemon's own output goes to a file beside the stage file, because a usermode helper
// has no stdout: without that redirect a refusal is a bare non-zero exit code, which is
// what made the staging bug above take a whole diagnostic round to find.
//
// On top of that, five things this file does that the upstream revision does not, each
// about a run having to end in an *answer* rather than in silence:
//
//   4. **Every failure ends in /dev/dfm1.** Upstream's early exits - no kallsyms, no
//      SELinux symbol, no usermode helper symbols - returned before the command ran, so
//      no marker existed and the chain's parent could not tell "the module never ran the
//      daemon" from "the daemon refused". The markers are the only channel a usermode
//      helper leaves behind; a run that produces neither is exactly the failure that
//      costs a diagnostic round to interpret.
//   5. **The markers are cleared before the command runs.** `/dev` is per-boot but a
//      payload run is not the only one per boot - the P0 supervisor keeps attempting
//      after a stack writer has run - so a leftover `/dev/dfm0` from an earlier run on
//      the same boot would be read as this run's success. The command clears both first
//      and then writes exactly one.
//   6. **A run that ends without /dev/dfm0 is retried.** Three attempts, half a second
//      apart. The command is idempotent by construction - it re-stages the daemon each
//      attempt, and the daemon's own `late-load` skips the module load when KernelSU is
//      already there - so re-running it after a partial failure is safe. The trigger is
//      the marker, not the helper's return code: the shell ends in `touch` either way,
//      so its exit status never carried the answer.
//   7. **A truncated command never runs.** The command buffer is sized for the longest
//      package name the parameter accepts; `snprintf`'s return is checked, and a command
//      that did not fit is refused rather than run half-built.
//   8. **Quiet by default, tidy on success.** The `pr_*` lines are behind a `debug`
//      module parameter (default off) because the log lines themselves are the most
//      obvious thing a rooted run leaves in the kernel ring buffer; the markers and the
//      log file are the channels meant to be read. On success the daemon's log and the
//      stage file are removed - the log exists so a *refusal* can be read later, and a
//      run that rooted the phone does not need to leave one in /data/local/tmp. On
//      failure both stay exactly where they were.
//
// Two portability fallbacks sit underneath all of that, because this file is built once
// per KMI and the KMIs do not agree: `selinux_enforcing` is accepted when a kernel has no
// `selinux_state`, and `call_usermodehelper` is used when the setup/exec pair cannot be
// resolved.

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/delay.h>

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef void *(*umh_setup_t)(const char *path, char **argv, char **envp, gfp_t gfp,
			     void *init, void *cleanup, void *data);
typedef int (*umh_exec_t)(void *info, int wait);
typedef int (*umh_call_t)(const char *path, char **argv, char **envp, int wait);
typedef struct file *(*filp_open_t)(const char *filename, int flags, umode_t mode);
typedef int (*filp_close_t)(struct file *filp, void *id);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DFRoot LKM");

/* The manager the daemon is told to serve. The app passes the flavour's package. */
static char package_name[64] = "me.weishu.kernelsu";
module_param_string(package_name, package_name, sizeof(package_name), 0);

/* Off by default: the markers and the log file are the channels meant to be read, and
 * every line this module prints is a line a detector can read too. `debug=1` restores
 * them for a run that needs to see what happened. */
static bool debug;
module_param(debug, bool, 0);

/* The daemon this chain stages and runs, and where its own `late-load` looks for it. */
#define DAEMON "/data/user_de/0/dev.rushiranpise.rmgnext/ksud"
#define STAGE "/data/local/tmp/.ksud-stage"
#define DAEMON_LOG "/data/local/tmp/dfroot-ksud.log"

/* Upstream's markers, and what the chain's parent side reports on. */
#define MARK_OK "/dev/dfm0"
#define MARK_FAIL "/dev/dfm1"

#define RUN_ATTEMPTS 3
#define RUN_DELAY_MSEC 500

static unsigned long kprobes_lookup(const char *name) {
	struct kprobe kp = { .symbol_name = name };
	unsigned long addr;
	if (register_kprobe(&kp) < 0) return 0;
	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

static int defex_pre_handler(struct kprobe *p, struct pt_regs *regs) {
	regs->regs[0] = 0;
	regs->pc = regs->regs[30];
	return 1;
}

static struct kprobe kp_user_exec = { .symbol_name = "task_defex_user_exec", .pre_handler = defex_pre_handler };
static struct kprobe kp_dc_path   = { .symbol_name = "get_dc_target_dpath",  .pre_handler = defex_pre_handler };

/* The usermode helper entry points, resolved once in init. */
static umh_setup_t g_umh_setup;
static umh_exec_t  g_umh_exec;
static umh_call_t  g_umh_call;

/* Marker plumbing, for the paths where the command never ran. `filp_open` on /dev is
 * enough to create or test one and is resolved the same way everything else here is. */
static filp_open_t  g_filp_open;
static filp_close_t g_filp_close;

static void __nocfi marker_touch(const char *path) {
	struct file *f;
	if (!g_filp_open) return;
	f = g_filp_open(path, O_CREAT | O_WRONLY, 0644);
	if (IS_ERR(f)) return;
	if (g_filp_close) g_filp_close(f, NULL);
}

static bool __nocfi marker_exists(const char *path) {
	struct file *f;
	if (!g_filp_open) return false;
	f = g_filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f)) return false;
	if (g_filp_close) g_filp_close(f, NULL);
	return true;
}

/*
 * One attempt: the usermode helper with the two defex kprobes armed across it.
 *
 * Return codes are deliberately ignored here. The shell ends in `touch` whichever way
 * the daemon went, so its exit status is zero on failure too - the marker is the answer,
 * and `dirtyfrag_init` reads that instead.
 */
static void __nocfi run_umh(const char *sh, char **argv, char **envp) {
	bool kp1 = register_kprobe(&kp_user_exec) == 0;
	bool kp2 = register_kprobe(&kp_dc_path) == 0;

	if (g_umh_setup && g_umh_exec) {
		void *info = g_umh_setup(sh, argv, envp, GFP_KERNEL, NULL, NULL, NULL);
		if (info) {
			struct subprocess_info *si = (struct subprocess_info *)info;
			int ret;
			si->path = sh;
			ret = g_umh_exec(info, UMH_WAIT_PROC);
			if (ret && debug)
				pr_err("dfroot: umh_exec failed: %d\n", ret);
		} else if (debug) {
			pr_err("dfroot: umh_setup returned NULL\n");
		}
	} else if (g_umh_call) {
		int ret = g_umh_call(sh, argv, envp, UMH_WAIT_PROC);
		if (ret && debug)
			pr_err("dfroot: call_usermodehelper failed: %d\n", ret);
	}

	if (kp1) unregister_kprobe(&kp_user_exec);
	if (kp2) unregister_kprobe(&kp_dc_path);
}

static int __nocfi __init dirtyfrag_init(void) {
	kallsyms_lookup_name_t kln;
	unsigned long selinux;
	/* 512, not 256: the command carries two paths and the manager's package name. */
	static char cmd[512];
	static const char sh[] = "/system/bin/sh";
	static char *envp[] = { "HOME=/", "PATH=/sbin:/vendor/bin:/system/bin", NULL };
	static char *argv[] = { (char *)sh, "-c", cmd, NULL };
	int len, attempt;

	/* Through kprobes directly, and before the kln gate: the marker plumbing has to work
	 * even on the path where `kallsyms_lookup_name` itself could not be resolved. */
	g_filp_open  = (filp_open_t)kprobes_lookup("filp_open");
	g_filp_close = (filp_close_t)kprobes_lookup("filp_close");

	kln = (kallsyms_lookup_name_t)kprobes_lookup("kallsyms_lookup_name");

	if (!kln) {
		marker_touch(MARK_FAIL);
		return -EINVAL;
	}

	selinux = kln("selinux_state");
	if (selinux) {
		/* struct selinux_state leads with `bool enforcing` where the kernel has it. */
		WRITE_ONCE(*(bool *)selinux, false);
	} else {
		/* Older layouts carry the flag as a plain int instead. */
		selinux = kln("selinux_enforcing");
		if (!selinux) {
			marker_touch(MARK_FAIL);
			return -EINVAL;
		}
		WRITE_ONCE(*(int *)selinux, 0);
	}
	if (debug)
		pr_info("dfroot: selinux permissive\n");

	g_umh_setup = (umh_setup_t)kln("call_usermodehelper_setup");
	g_umh_exec  = (umh_exec_t)kln("call_usermodehelper_exec");
	g_umh_call  = (umh_call_t)kln("call_usermodehelper");
	if (!g_umh_call && (!g_umh_setup || !g_umh_exec)) {
		if (debug)
			pr_err("dfroot: umh symbols missing (setup=%px exec=%px call=%px)\n",
			       g_umh_setup, g_umh_exec, g_umh_call);
		marker_touch(MARK_FAIL);
		return -EINVAL;
	}

	/*
	 * Stage, then load.
	 *
	 * `cp` rather than `mv`: the daemon the app staged is the only copy of those bytes, and a run
	 * that failed before `late-load` renamed the stage file would otherwise have left the app with
	 * nothing to stage again. The daemon renames it itself as its first act, which is what consumes
	 * it.
	 *
	 * The markers are cleared first (see the header), and the success branch removes the log and
	 * the stage file; the failure branch leaves both for the diagnostic round that follows.
	 */
	len = snprintf(cmd, sizeof(cmd),
			 "rm -f %s %s"
			 " && cp %s %s && chmod 0755 %s"
			 " && %s late-load --package-name %s > %s 2>&1"
			 " && { rm -f %s %s; touch %s; } || touch %s",
			 MARK_OK, MARK_FAIL,
			 DAEMON, STAGE, STAGE,
			 DAEMON, package_name, DAEMON_LOG,
			 STAGE, DAEMON_LOG, MARK_OK, MARK_FAIL);
	if (len < 0 || len >= (int)sizeof(cmd)) {
		/* Refuse rather than run half of the command. */
		if (debug)
			pr_err("dfroot: command truncated (%d)\n", len);
		marker_touch(MARK_FAIL);
		return -E2BIG;
	}

	for (attempt = 0; attempt < RUN_ATTEMPTS; attempt++) {
		if (attempt)
			msleep(RUN_DELAY_MSEC);
		run_umh(sh, argv, envp);
		if (marker_exists(MARK_OK))
			break;
	}

	if (!marker_exists(MARK_OK)) {
		marker_touch(MARK_FAIL);
		if (debug)
			pr_err("dfroot: no success marker after %d attempt(s)\n", RUN_ATTEMPTS);
	}

	/* Return random error to unload module. */
	return -E2BIG;
}

/* No module_exit: we never unload; saves .exit sections. */
module_init(dirtyfrag_init);
