/*
 * Copyright (c) 2013-2019, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>

#include <arch_helpers.h>
#include <arch_features.h>
#include <bl1/bl1.h>
#include <bl2/bl2.h>
#include <common/bl_common.h>
#include <common/debug.h>
#include <drivers/auth/auth_mod.h>
#include <drivers/console.h>
#include <lib/extensions/pauth.h>
#include <plat/common/platform.h>

#include "bl2_private.h"
#include <lib/mmio.h>

extern void rcar_dma_init(void);
extern void rcar_dma_exec(uintptr_t dst, uint32_t src, uint32_t len);

#ifdef __aarch64__
#define NEXT_IMAGE	"BL31"
#else
#define NEXT_IMAGE	"BL32"
#endif

#define LOC_CR7_CODE_ADDR      0x70000000

#define LOC_CPG_CPGWPR         0xe6150900
#define LOC_CPG_CPGWPCR        0xe6150904

#define LOC_RST_CR7BAR         0xe6160070

#define LOC_APMU_CR7PSTR       0xe6153040

#define LOC_SYSC_PWRSR7        0xe6180240
#define LOC_SYSC_PWRONCR7      0xe618024c


#define LOC_CR7_WBCTLR         0xf0100000
#define LOC_CR7_WBPWRCTLR      0xf0100f80

#define LOC_MSSR_BASE          0xe6150000
#define LOC_MSSR_SRCR2         0xe61500B0
#define LOC_MSSR_SRSTCLR2      0xe6150948

#define FLASH_BASE             (0x08000000U)
#define FLASH_RTOS_IMAGE_ADDR  (0x02000000U) // Reserve above for others BL33
#define FLASH_RTOS_IMAGESIZE   (32*1024*1024) // All remain flash memory size
#define FLASH_RTOS_MMAP_ADDR   (FLASH_BASE + FLASH_RTOS_IMAGE_ADDR)

static void locCPGReadModWriteRegSet(uint32_t Addr, uint32_t Mask){
    uint32_t val;

    mmio_write_32(LOC_CPG_CPGWPCR, 0xa5a50000);    /* Clear register protection */
    val = mmio_read_32(Addr) | Mask;         /* Generate value */
    mmio_write_32(LOC_CPG_CPGWPR, ~val);          /* Unlock write */
    mmio_write_32(Addr,val);                 /* Write value */
}

static void Kick_CR7(void) {
    uint32_t regval;

    mmio_write_32(LOC_CPG_CPGWPCR, 0xa5a50000);

    mmio_write_32(LOC_CPG_CPGWPR, 0xffbfffff);

    regval = (LOC_CR7_CODE_ADDR & 0xfffc0000);
    mmio_write_32(LOC_RST_CR7BAR, regval);
    regval |= 0x10;
    mmio_write_32(LOC_RST_CR7BAR, regval);

    mmio_write_32(LOC_SYSC_PWRONCR7, 0x1);

    do {
        regval = (mmio_read_32(LOC_APMU_CR7PSTR) & 0x3);
        regval |= (mmio_read_32(LOC_SYSC_PWRSR7) & 0x10);
    } while (regval != 0x10);

    locCPGReadModWriteRegSet(LOC_MSSR_SRCR2, 0x00400000);
/* FIXME: to be investigated. The commented code should (acc. to HW-Manual) be used
 * in the core startup, however it creates yet to be investigated problems:
 * 1. After this code sequence the linux kernel cannot start (data abort exception).
 * 2. It is also incompatible to R-Car Inspect, there this is commented as well */
#if 0
    regval = mmio_read_32(LOC_CR7_WBCTLR);
    regval |= 0x1;
    mmio_write_32(LOC_CR7_WBCTLR, regval);

    regval = mmio_read_32(LOC_CR7_WBPWRCTLR);
    regval |= 0x1;
    mmio_write_32(LOC_CR7_WBPWRCTLR, regval);
#endif
    locCPGReadModWriteRegSet(LOC_MSSR_SRSTCLR2, 0x00400000);
}

#if !BL2_AT_EL3
/*******************************************************************************
 * Setup function for BL2.
 ******************************************************************************/
void bl2_setup(u_register_t arg0, u_register_t arg1, u_register_t arg2,
	       u_register_t arg3)
{
	/* Perform early platform-specific setup */
	bl2_early_platform_setup2(arg0, arg1, arg2, arg3);

	/* Perform late platform-specific setup */
	bl2_plat_arch_setup();

#if CTX_INCLUDE_PAUTH_REGS
	/*
	 * Assert that the ARMv8.3-PAuth registers are present or an access
	 * fault will be triggered when they are being saved or restored.
	 */
	assert(is_armv8_3_pauth_present());
#endif /* CTX_INCLUDE_PAUTH_REGS */
}

#else /* if BL2_AT_EL3 */
/*******************************************************************************
 * Setup function for BL2 when BL2_AT_EL3=1.
 ******************************************************************************/
void bl2_el3_setup(u_register_t arg0, u_register_t arg1, u_register_t arg2,
		   u_register_t arg3)
{
	/* Perform early platform-specific setup */
	bl2_el3_early_platform_setup(arg0, arg1, arg2, arg3);

	/* Perform late platform-specific setup */
	bl2_el3_plat_arch_setup();

#if CTX_INCLUDE_PAUTH_REGS
	/*
	 * Assert that the ARMv8.3-PAuth registers are present or an access
	 * fault will be triggered when they are being saved or restored.
	 */
	assert(is_armv8_3_pauth_present());
#endif /* CTX_INCLUDE_PAUTH_REGS */
}
#endif /* BL2_AT_EL3 */

/*******************************************************************************
 * The only thing to do in BL2 is to load further images and pass control to
 * next BL. The memory occupied by BL2 will be reclaimed by BL3x stages. BL2
 * runs entirely in S-EL1.
 ******************************************************************************/
void bl2_main(void)
{
	entry_point_info_t *next_bl_ep_info;

	NOTICE("BL2: %s\n", version_string);
	NOTICE("BL2: %s\n", build_message);

	/* Perform remaining generic architectural setup in S-EL1 */
	bl2_arch_setup();

#if TRUSTED_BOARD_BOOT
	/* Initialize authentication module */
	auth_mod_init();
#endif /* TRUSTED_BOARD_BOOT */

	/* initialize boot source */
	bl2_plat_preload_setup();

	/* Load ROS image */
	rcar_dma_init();
	rcar_dma_exec(LOC_CR7_CODE_ADDR, FLASH_RTOS_MMAP_ADDR, FLASH_RTOS_IMAGESIZE);
	// execDMA(LOC_CR7_CODE_ADDR, FLASH_RTOS_MMAP_ADDR, FLASH_RTOS_IMAGESIZE);

	/* Load the subsequent bootloader images. */
	next_bl_ep_info = bl2_load_images();

	Kick_CR7();

#if !BL2_AT_EL3
#ifndef __aarch64__
	/*
	 * For AArch32 state BL1 and BL2 share the MMU setup.
	 * Given that BL2 does not map BL1 regions, MMU needs
	 * to be disabled in order to go back to BL1.
	 */
	disable_mmu_icache_secure();
#endif /* !__aarch64__ */

	console_flush();

#if ENABLE_PAUTH
	/*
	 * Disable pointer authentication before running next boot image
	 */
	pauth_disable_el1();
#endif /* ENABLE_PAUTH */

	/*
	 * Run next BL image via an SMC to BL1. Information on how to pass
	 * control to the BL32 (if present) and BL33 software images will
	 * be passed to next BL image as an argument.
	 */
	smc(BL1_SMC_RUN_IMAGE, (unsigned long)next_bl_ep_info, 0, 0, 0, 0, 0, 0);
#else /* if BL2_AT_EL3 */
	NOTICE("BL2: Booting " NEXT_IMAGE "\n");
	print_entry_point_info(next_bl_ep_info);
	console_flush();

#if ENABLE_PAUTH
	/*
	 * Disable pointer authentication before running next boot image
	 */
	pauth_disable_el3();
#endif /* ENABLE_PAUTH */

	bl2_run_next_image(next_bl_ep_info);
#endif /* BL2_AT_EL3 */
}
