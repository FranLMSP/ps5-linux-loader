#ifndef PAYLOAD_CLEANUP_H
#define PAYLOAD_CLEANUP_H

/*
 * Best-effort cleanup of payloads that are known to interfere with the Linux
 * loader (etaHEN, kstuff and their variants).
 *
 * The loader is a second-stage payload: it already runs inside a jailbroken
 * console.  If another payload is still active it may have installed kernel
 * hooks/patches that race with hv_defeat_13xx() or keep the console awake when
 * it should enter rest mode.  Killing those processes stops their userland
 * activity, but it cannot undo kernel patches that were already applied -- a
 * fresh reboot is still the only way to get a completely clean kernel.
 *
 * Call this after setup_env() has confirmed that kernel access works and
 * before fetch_linux()/prepare_resume().
 *
 * Returns the number of conflicting processes that were found (0 if none).
 */
int cleanup_conflicting_payloads(void);

#endif /* PAYLOAD_CLEANUP_H */
