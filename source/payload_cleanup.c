#include "payload_cleanup.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <unistd.h>

/* ki_stat == SZOMB, from FreeBSD's kernel-only sys/proc.h.  The SDK's userspace
 * headers do not expose that header (including it fails without the kernel
 * build environment), so spell out the one value we need. */
#define KINFO_STAT_ZOMB 5

/* Include after sys/user.h: the SDK's machine/pmap.h declares pmap_*_index()
 * functions whose names collide with the succinct macros in utils.h.  Putting
 * the system header first lets the macros be defined afterwards without
 * rewriting those declarations.  INKERNEL comes from machine/param.h (pulled
 * in by sys/user.h) and has a different definition there, so drop it first to
 * keep the include clean. */
#undef INKERNEL
#include "utils.h"

/* Matched case-insensitively as a substring of ki_comm.  Keep this list
 * conservative: it must never match a PS5 system process or elfldr itself. */
static const struct conflicting_payload {
  const char *needle;
  const char *label;
} conflicting_payloads[] = {
    {"etahen", "etaHEN"},
    {"kstuff", "kstuff"},
};

static int ascii_lower(int c) {
  return (c >= 'A' && c <= 'Z') ? (c - 'A' + 'a') : c;
}

static int contains_ci(const char *haystack, const char *needle) {
  if (!haystack || !needle || !*needle)
    return 0;

  for (; *haystack; haystack++) {
    const char *h = haystack;
    const char *n = needle;
    while (*h && *n && ascii_lower((unsigned char)*h) ==
                             ascii_lower((unsigned char)*n)) {
      h++;
      n++;
    }
    if (!*n)
      return 1;
  }
  return 0;
}

static int pid_is_running(const struct kinfo_proc *procs, size_t procs_len,
                          pid_t pid) {
  for (size_t off = 0; off + sizeof(int) <= procs_len;) {
    const struct kinfo_proc *ki =
        (const struct kinfo_proc *)((const char *)procs + off);
    int struct_size = ki->ki_structsize;

    if (struct_size < (int)sizeof(struct kinfo_proc) ||
        off + (size_t)struct_size > procs_len)
      break;
    off += (size_t)struct_size;

    if (ki->ki_pid == pid)
      return ki->ki_stat != KINFO_STAT_ZOMB; /* killed but not yet reaped */  }
  return 0;
}

static int read_process_list(struct kinfo_proc **out, size_t *out_len) {
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};

  for (int attempt = 0; attempt < 3; attempt++) {
    size_t len = 0;
    if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0)
      return -1;
    if (len == 0) {
      errno = ENOMEM; /* no process list: report something meaningful */
      return -1;
    }

    struct kinfo_proc *buf = malloc(len);
    if (!buf)
      return -1;

    size_t got = len;
    if (sysctl(mib, 4, buf, &got, NULL, 0) == 0) {
      *out = buf;
      *out_len = got;
      return 0;
    }

    free(buf);
    /* The process list grew between the size query and the fetch.  FreeBSD
     * reports the new size in got, so retry with it. */
    if (errno != ENOMEM)
      return -1;
  }
  return -1;
}

int cleanup_conflicting_payloads(void) {
  struct kinfo_proc *procs = NULL;
  size_t procs_len = 0;
  pid_t self = getpid();
  int found = 0;
  int killed = 0;
  int failed = 0;
  pid_t killed_pids[16];
  size_t killed_count = 0;

  if (read_process_list(&procs, &procs_len) != 0) {
    notify("Could not enumerate processes to check for conflicting payloads "
           "(%s). Continuing anyway.\n", strerror(errno));
    return 0;
  }

  /* SIGKILL of another payload's process needs the same elevated authid that
   * cpuset_setaffinity() needs later.  Do not abort if it is refused: a
   * payload launched by elfldr is usually already root, and kill() can still
   * succeed. */
  kernel_set_ucred_authid(self, 0x4800000000000007);

  for (size_t off = 0; off + sizeof(int) <= procs_len;) {
    struct kinfo_proc *ki = (struct kinfo_proc *)((char *)procs + off);
    int struct_size = ki->ki_structsize;

    if (struct_size < (int)sizeof(struct kinfo_proc) ||
        off + (size_t)struct_size > procs_len)
      break;
    off += (size_t)struct_size;

    if (ki->ki_pid <= 1 || ki->ki_pid == self)
      continue;

    /* ki_comm is NUL-terminated by the kernel, but a truncated/garbage entry
     * should never make us read past the returned buffer. */
    ki->ki_comm[sizeof(ki->ki_comm) - 1] = '\0';

    const char *label = NULL;
    for (size_t i = 0; i < sizeof(conflicting_payloads) / sizeof(conflicting_payloads[0]);
         i++) {
      if (contains_ci(ki->ki_comm, conflicting_payloads[i].needle)) {
        label = conflicting_payloads[i].label;
        break;
      }
    }
    if (!label)
      continue;

    found++;
    notify("Stopping conflicting payload %s (pid %d)...\n", label, ki->ki_pid);

    if (kill(ki->ki_pid, SIGKILL) == 0) {
      killed++;
      if (killed_count < sizeof(killed_pids) / sizeof(killed_pids[0]))
        killed_pids[killed_count++] = ki->ki_pid;
      notify("Stopped %s (pid %d).\n", label, ki->ki_pid);
    } else {
      failed++;
      notify("Could not stop %s (pid %d): %s\n", label, ki->ki_pid,
             strerror(errno));
    }
  }

  free(procs);
  procs = NULL;

  /* SIGKILL is asynchronous: give the scheduler a moment before claiming the
   * console is clean, then re-enumerate by pid so a failure is visible.  A
   * re-enumeration (rather than a per-pid KERN_PROC_PID lookup) also lets us
   * ignore zombies: a killed payload whose parent never reaps it still shows
   * up in the process table, but it is no longer running. */
  if (killed_count) {
    usleep(200000);
    if (read_process_list(&procs, &procs_len) == 0) {
      for (size_t i = 0; i < killed_count; i++) {
        if (pid_is_running(procs, procs_len, killed_pids[i])) {
          failed++;
          notify("Payload pid %d is still alive after SIGKILL.\n",
                 killed_pids[i]);
        }
      }
    }
    free(procs);
  }

  if (!found) {
    notify("No conflicting payloads (etaHEN/kstuff) are running.\n");
    return 0;
  }

  notify("Payload cleanup: %d found, %d stopped, %d kill failure(s).\n", found,
         killed, failed);

  if (failed) {
    notify("Warning: at least one conflicting payload could not be stopped. "
           "Reboot, jailbreak fresh, and run only the Linux loader.\n");
  } else {
    notify("Note: stopping a payload does not undo kernel patches it already "
           "applied. If arming fails or the console freezes, reboot and "
           "jailbreak fresh without etaHEN/kstuff.\n");
  }

  return found;
}
