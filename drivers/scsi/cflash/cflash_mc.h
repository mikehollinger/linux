/*
 * cflash_mc.h -- driver for IBM Power CAPI Flash Adapter
 *
 * Written By: Manoj Kumar <kumarmn@us.ibm.com>, IBM Corporation
 *
 * Copyright (C) IBM Corporation, 2015
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef _CFLASHMC_H
#define _CFLASHMC_H


typedef unsigned int    useconds_t;     /* time in microseconds */

/* Max pathlen - e.g. for AFU device path */
#define MC_PATHLEN       64

/* The write_nn or read_nn routines can be used to do byte reversed MMIO
   or byte reversed SCSI CDB/data.
*/
static inline void write_64(volatile __u64 *addr, __u64 val)
{
    __u64 zero = 0;
#ifndef _AIX
    asm volatile ( "stdbrx %0, %1, %2" : : "r"(val), "r"(zero), "r"(addr) );
#else
    *((volatile __u64 *)(addr)) = val;
#endif /* _AIX */
}

static inline void write_32(volatile __u32 *addr, __u32 val)
{
    __u32 zero = 0;
#ifndef _AIX
    asm volatile ( "stwbrx %0, %1, %2" : : "r"(val), "r"(zero), "r"(addr) );
#else
    *((volatile __u32 *)(addr)) = val;
#endif /* _AIX */
}

static inline void write_16(volatile __u16 *addr, __u16 val)
{
    __u16 zero = 0;
#ifndef _AIX
    asm volatile ( "sthbrx %0, %1, %2" : : "r"(val), "r"(zero), "r"(addr) );
#else
    *((volatile __u16 *)(addr)) = val;
#endif /* _AIX */
}

static inline __u64 read_64(volatile __u64 *addr)
{
    __u64 val;
    __u64 zero = 0;
#ifndef _AIX
    asm volatile ( "ldbrx %0, %1, %2" : "=r"(val) : "r"(zero), "r"(addr) );
#else
   val =  *((volatile __u64 *)(addr));
#endif /* _AIX */

    return val;
}

static inline __u32 read_32(volatile __u32 *addr)
{
    __u32 val;
    __u32 zero = 0;
#ifndef _AIX
    asm volatile ( "lwbrx %0, %1, %2" : "=r"(val) : "r"(zero), "r"(addr) );
#else
     val =  *((volatile __u32 *)(addr));
#endif /* _AIX */
    return val;
}

static inline __u16 read_16(volatile __u16 *addr)
{
    __u16 val;
    __u16 zero = 0;
#ifndef _AIX
    asm volatile ( "lhbrx %0, %1, %2" : "=r"(val) : "r"(zero), "r"(addr) );
#else
     val =  *((volatile __u16 *)(addr));
#endif /* _AIX */
    return val;
}


/* mc_stat is analogous to fstat in POSIX. It returns information on
 * a virtual disk.
 *
 * Inputs:
 *   mc_hndl         - client handle that specifies a (context + AFU)
 *   res_hndl        - resource handle identifying the virtual disk
 *                     to query
 *
 * Output:
 *   p_mc_stat       - pointer to location that will contain the
 *                     output data
 */
typedef struct mc_stat_s {
  __u32       blk_len;   /* length of 1 block in bytes as reported by device */
  __u8        nmask;     /* chunk_size = (1 << nmask) in device blocks */
  __u8        rsvd[3];
  __u64       size;      /* current size of the res_hndl in chunks */
  __u64       flags;     /* permission flags */
} mc_stat_t;


/* In the course of doing IOs, the user may be the first to notice certain
 * critical events on the AFU or the backend storage. mc_notify allows a
 * user to pass such information to the master. The master will verify the
 * events and can take appropriate action.
 *
 * Inputs:
 *   mc_hndl         - client handle that specifies a (context + AFU)
 *                     The event pertains to this AFU.
 *
 *   p_mc_notify     - pointer to location that contains the event
 *
 * Output:
 */
typedef struct mc_notify_s {
  __u8 event;  /* MC_NOTIF_xxx */
#define MC_NOTIFY_CMD_TIMEOUT    0x01 /* user command timeout */
#define MC_NOTIFY_SCSI_SENSE     0x02 /* interesting sense data */
#define MC_NOTIFY_AFU_EEH        0x03 /* user detected AFU is frozen */
#define MC_NOTIFY_AFU_RST        0x04 /* user detected AFU has been reset */
#define MC_NOTIFY_AFU_ERR        0x05 /* other AFU error, unexpected response */
  /*
   * Note: the event must be sent on a mc_hndl_t that pertains to the
   * affected AFU. This is important when the user interacts with multiple
   * AFUs.
   */

  union {
    struct {
      res_hndl_t       res_hndl;
    } cmd_timeout;

    struct {
      res_hndl_t       res_hndl;
      char data[20]; /* 20 bytes of sense data */
    } scsi_sense;

    struct {
    } afu_eeh;

    struct {
    } afu_rst;

    struct {
    } afu_err;
  };
} mc_notify_t;

#endif  /* ifndef _CFLASHMC_H */

