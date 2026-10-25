#include "hv_defeat_13xx.h"
#include "loader.h"
#include "prepare_resume.h"
#include "utils.h"
#include <unistd.h>

int main(void) {
  if (setup_env()) {
    notify("Something went wrong while initiating.\nPlease make sure your fw "
           "is supported.");
    return -1;
  }

  if (fetch_linux(&linux_i)) {
    notify("Something went wrong while installing linux files.\n");
    return -1;
  }

  void *shellcode_kernel;
  size_t shellcode_kernel_len;
  if (prepare_resume(&shellcode_kernel, &shellcode_kernel_len)) {
    notify("Something went wrong while preparing resume.\n");
    return -1;
  }

  /* The HV patch addresses are NOT optional and are NOT covered by offsets_present().
   * boot_linux.c patches the hypervisor's vmexit handler with
   *     memcpy(PHYS_TO_DMAP(args.hv_handle_vmexit_pa), shellcode_jmp, ...)
   * so a table that leaves HV_HANDLE_VMEXIT_PA at 0 would write that jmp into physical page
   * zero. Refuse here instead -- a table derived from x86_kernel.elf alone CANNOT contain
   * this value, because it lives in the hypervisor image. */
  if (!env_offset.HV_HANDLE_VMEXIT_PA || !env_offset.HV_CODE_CAVE_PA) {
    notify("fw %x: HV patch addresses missing from the offset table "
           "(HV_HANDLE_VMEXIT_PA=%lx HV_CODE_CAVE_PA=%lx).\n"
           "These live in the HYPERVISOR image, not x86_kernel.elf, and cannot be derived "
           "from the kernel. Refusing to arm rather than patching physical page 0.",
           fw, (unsigned long)env_offset.HV_HANDLE_VMEXIT_PA,
           (unsigned long)env_offset.HV_CODE_CAVE_PA);
    goto err;
  }

  /* Two 12.xx tables are weaker than the others; say so at arm time rather than letting a
   * failed boot hide which table was used. Neither warning fires on 12.00/12.02/12.20/12.70. */
  if (fw == 0x1260)
    notify("fw 12.60: the public release has no dedicated table; using the 12.70 offsets. "
           "If this boot fails, suspect this alias first.\n");
  else if (fw == 0x1240)
    notify("fw 12.40: the public release's table is byte-identical to 12.20 and is untested. "
           "If this boot fails, that copy is the first suspect.\n");

  /* 12.xx and 13.xx (base + Pro, differentiated at runtime by SoC id inside hv_defeat_13xx).
   * Hook the kernel's own AP-start call (khook) rather than exploiting an MSR intercept.
   * 12.xx needs the same route: the MSR 0x1B (APIC_BASE) intercept used by hv_defeat_1160 was
   * removed between 11.00 and 12.00. See source/hv_defeat_13xx.c for the route; the fields come
   * from off_1200/off_1202/off_1220/off_1240/off_1270 or off_1360 in source/offsets.c. The
   * function refuses to arm unless all required offsets are present. */
  if ((0x1200 <= fw) && (fw < 0x1400)) {
    if (hv_defeat_13xx(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else {
    goto err;
  }

  notify("Finished preparation. Going to rest mode in 5 seconds.\nPlease wait "
         "for the orange light to stop "
         "blinking and then wakeup to Linux :)\n");

  sleep(5);
  enter_rest_mode();

  while (1) {
    sleep(30);
  }

  return 0;

err:
  notify("Something went wrong while defeating Hypervisor.\nPlease make sure "
         "your fw is supported.");
  return -1;
}
