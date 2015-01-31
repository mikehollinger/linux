//  IBM_PROLOG_BEGIN_TAG
//  This is an automatically generated prolog.
//
//  $Source: drivers/scsi/cflash/cflash_ba.c $
//
//  IBM CONFIDENTIAL
//
//  COPYRIGHT International Business Machines Corp. 2015
//
//  p1
//
//  Object Code Only (OCO) source materials
//  Licensed Internal Code Source Materials
//  IBM Surelock Licensed Internal Code
//
//  The source code for this program is not published or other-
//  wise divested of its trade secrets, irrespective of what has
//  been deposited with the U.S. Copyright Office.
//
//  Origin: 30
//
//  IBM_PROLOG_END

#include <linux/module.h>
#include <linux/slab.h>

#include "cflash.h"
#include "cflash_ba.h"
#include "cflash_ba_internal.h"

/**************************************************************
 *                                                            *
 *            LUN BIT map table                               *
 *                                                            *
 *     0    1    2   3   4   5   6   ...    63                *
 *    64   65   66  67  68  69  70   ...   127                *
 *    ......                                                  *
 *                                                            *
 **************************************************************/


/**************************************************************
 *                                                            *
 *                      Defines                               *
 *                                                            *
 **************************************************************/

/* Bit operations */
#define SET_BIT(num, bit_pos)  num |= (uint64_t)0x01 << (63-bit_pos);
#define CLR_BIT(num, bit_pos)  num &= ~((uint64_t)0x01 << (63-bit_pos));
#define TEST_BIT(num, bit_pos)  (num & ((uint64_t)0x01 << (63-bit_pos)))


/**************************************************************
 *                                                            *
 *                Function Prototypes                         *
 *                                                            *
 **************************************************************/
static int find_free_bit(uint64_t lun_map_entry);


int ba_init(ba_lun_t *ba_lun)
{
	lun_info_t	*lun_info = NULL;
	int		 lun_size_au = 0, i = 0;
	int		 last_word_underflow = 0;

	/* Allocate lun_fino */
	lun_info = kzalloc(sizeof(lun_info_t), GFP_KERNEL);
	if (!lun_info) {
		cflash_err("block_alloc: Failed to allocate lun_info for lun_id %llX\n",
			ba_lun->lun_id);
		return -ENOMEM;
	}

	cflash_info("block_alloc: Initializing LUN: lun_id = %llX, ba_lun->lsize = %lX, ba_lun->au_size = %lX\n",
		ba_lun->lun_id, ba_lun->lsize, ba_lun->au_size);

	/* Calculate bit map size */
	lun_size_au = ba_lun->lsize / ba_lun->au_size;

	/* XXX - do we need this? Thinking no...how should we handle a 0 lun
	 * size, just return?
	 */
#ifdef _FILEMODE_
	if (lun_size_au == 0)
		lun_size_au = 1;
#endif /* _FILEMODE_ */

	lun_info->total_aus = lun_size_au;
	lun_info->lun_bmap_size = lun_size_au / 64;

	if (lun_size_au % 64)
		lun_info->lun_bmap_size++;

	/* Allocate bitmap space */
	lun_info->lun_alloc_map = kzalloc((lun_info->lun_bmap_size * sizeof(uint64_t)), GFP_KERNEL);
	if (!lun_info->lun_alloc_map) {
		cflash_err("block_alloc: Failed to allocate lun allocation map: lun_id = %llX\n",
			ba_lun->lun_id);
		kfree(lun_info);
		return -ENOMEM;
	}

	/* Initialize the bit map size and set all bits to '1' */
	lun_info->free_aun_cnt = lun_size_au;

	for (i = 0; i < lun_info->lun_bmap_size; i++)
		lun_info->lun_alloc_map[i] = (uint64_t)~0;

	/* If the last word is not fully utilized, mark the extra bits as allocated */
	last_word_underflow = (lun_info->lun_bmap_size * 64) - lun_info->free_aun_cnt;
	if (last_word_underflow > 0) {
		for (i = (63 - last_word_underflow + 1); i < 64 ; i++)
			CLR_BIT(lun_info->lun_alloc_map[lun_info->lun_bmap_size-1], i);
	}

	/* Initialize high elevator index, low/curr already at 0 from kzalloc */
	lun_info->free_high_idx = lun_info->lun_bmap_size;

	/* Allocate clone map */
	lun_info->aun_clone_map = kzalloc((lun_info->total_aus * sizeof(uint8_t)), GFP_KERNEL);
	if (!lun_info->aun_clone_map) {
		cflash_err("block_alloc: Failed to allocate clone map: lun_id = %llX\n",
			ba_lun->lun_id);
		kfree(lun_info->lun_alloc_map);
		kfree(lun_info);
		return -ENOMEM;
	}

	/* Pass the allocated lun info as a handle to the user */
	ba_lun->ba_lun_handle = (void *)lun_info;

	cflash_info("block_alloc: Successfully initialized the LUN: lun_id = %llX, bitmap size = %X, free_aun_cnt = %llX\n",
		ba_lun->lun_id, lun_info->lun_bmap_size, lun_info->free_aun_cnt);
	return 0;
}


static int find_free_bit(uint64_t lun_map_entry)
{
	int pos = -1;

	asm volatile ("cntlzd %0, %1": "=r"(pos) : "r"(lun_map_entry));
	return pos;
}


aun_t ba_alloc(ba_lun_t *ba_lun)
{
	aun_t		 bit_pos = -1;
	int		 i = 0;
	lun_info_t	*lun_info = NULL;

	lun_info = (lun_info_t *)ba_lun->ba_lun_handle;

	cflash_info("block_alloc: Received block allocation request: lun_id = %llX, free_aun_cnt = %llX\n",
		ba_lun->lun_id, lun_info->free_aun_cnt);

	if (lun_info->free_aun_cnt == 0) {
		cflash_err("block_alloc: No space left on LUN: lun_id = %llX\n",
			ba_lun->lun_id);
		return (aun_t)-1;
	}

	/* Search for free entry between free_curr_idx and free_high_idx */
	for (i = lun_info->free_curr_idx; i < lun_info->free_high_idx; i++) {
		if (lun_info->lun_alloc_map[i] != 0) {
			/* There are some free AUs .. find free entry */
			bit_pos = find_free_bit(lun_info->lun_alloc_map[i]);

			cflash_info("block_alloc: Found free bit %lX in lun map entry %llX at bitmap index = %X\n",
				bit_pos, lun_info->lun_alloc_map[i], i);

			lun_info->free_aun_cnt--;
			CLR_BIT(lun_info->lun_alloc_map[i], bit_pos);
			break;
		}
	}

	/* XXX - look at refactoring these searches (dup code) */
	if (bit_pos == -1) {
		/* Search for free entry between free_low_idx and free_curr_idx  */
		for (i = lun_info->free_low_idx; i < lun_info->free_curr_idx; i++) {
			if (lun_info->lun_alloc_map[i] != 0) {
				/* There are some free AUs .. find free entry */
				bit_pos = find_free_bit(lun_info->lun_alloc_map[i]);

				cflash_info("block_alloc: Found free bit %lX in lun map entry %llX at bitmap index = %X\n",
					bit_pos, lun_info->lun_alloc_map[i], i);

				lun_info->free_aun_cnt--;
				CLR_BIT(lun_info->lun_alloc_map[i], bit_pos);
				break;
			}
		}
	}

	if (bit_pos == -1) {
		cflash_err("block_alloc: Could not find an allocation unit on LUN: lun_id = %llX\n",
			ba_lun->lun_id);
		return (aun_t)-1;
	}

	/* Update the free_curr_idx */
	if (bit_pos == 63)
		lun_info->free_curr_idx = i + 1;
	else
		lun_info->free_curr_idx = i;

	cflash_info("block_alloc: Allocating AU number %lX, on lun_id %llX, free_aun_cnt = %llX\n",
		((i * 64) + bit_pos), ba_lun->lun_id, lun_info->free_aun_cnt);

	return (aun_t)((i * 64) + bit_pos);
}


static int validate_alloc(lun_info_t *lun_info, aun_t aun)
{
	int idx = 0, bit_pos = 0;

	idx     = aun / 64;
	bit_pos = aun % 64;

	if (TEST_BIT(lun_info->lun_alloc_map[idx], bit_pos))
		return -1;

	return 0;
}


int ba_free(ba_lun_t *ba_lun, aun_t to_free)
{
	int		 idx = 0, bit_pos = 0;
	lun_info_t	*lun_info = NULL;

	lun_info = (lun_info_t *)ba_lun->ba_lun_handle;

	if (validate_alloc(lun_info, to_free)) {
		cflash_err("block_alloc: The AUN %lX is not allocated on lun_id %llX\n",
			to_free, ba_lun->lun_id);
		return -1;
	}

	cflash_info("block_alloc: Received a request to free AU %lX on lun_id %llX, free_aun_cnt = %llX\n",
		to_free, ba_lun->lun_id, lun_info->free_aun_cnt);

	if (lun_info->aun_clone_map[to_free] > 0) {
		cflash_info("block_alloc: AU %lX on lun_id %llX has been cloned. Clone count = %X\n",
			to_free, ba_lun->lun_id, lun_info->aun_clone_map[to_free]);
		lun_info->aun_clone_map[to_free]--;
		return 0;
	}

	idx     = to_free / 64;
	bit_pos = to_free % 64;

	SET_BIT(lun_info->lun_alloc_map[idx], bit_pos);
	lun_info->free_aun_cnt++;

	if (idx < lun_info->free_low_idx)
		lun_info->free_low_idx = idx;
	else if (idx > lun_info->free_high_idx)
		lun_info->free_high_idx = idx;

	cflash_info("block_alloc: Successfully freed AU at bit_pos %X, bit map index %X on lun_id %llX, free_aun_cnt = %llX\n",
		bit_pos, idx, ba_lun->lun_id, lun_info->free_aun_cnt);
	return 0;
}


int ba_clone(ba_lun_t *ba_lun, aun_t to_clone)
{
	lun_info_t *lun_info = (lun_info_t *)ba_lun->ba_lun_handle;

	if (validate_alloc(lun_info, to_clone)) {
		cflash_err("block_alloc: AUN %lX is not allocated on lun_id %llX\n",
			to_clone, ba_lun->lun_id);
		return -1;
	}

	cflash_info("block_alloc: Received a request to clone AU %lX on lun_id %llX\n",
		to_clone, ba_lun->lun_id);

	if (lun_info->aun_clone_map[to_clone] == MAX_AUN_CLONE_CNT) {
		cflash_err("block_alloc: AUN %lX on lun_id %llX has hit max clones already\n",
			to_clone, ba_lun->lun_id);
		return -1;
	}

	lun_info->aun_clone_map[to_clone]++;

	return 0;
}


uint64_t ba_space(ba_lun_t *ba_lun)
{
	lun_info_t *lun_info = (lun_info_t *)ba_lun->ba_lun_handle;

	return lun_info->free_aun_cnt;
}


#ifdef BA_DEBUG
void dump_ba_map(ba_lun_t *ba_lun)
{
	lun_info_t	*lun_info = NULL;
	int		 i = 0, j = 0;

	lun_info = (lun_info_t *)ba_lun->ba_lun_handle;

	pr_debug("Dumping block allocation map: map size = %u\n",
		lun_info->lun_bmap_size);

	for (i = 0; i < lun_info->lun_bmap_size; i++) {
		pr_debug("%4d ", (i * 64));

		for (j = 0; j < 64; j++) {
			if (j % 4 == 0)
				pr_debug(" ");

			pr_debug("%1d",
				TEST_BIT(lun_info->lun_alloc_map[i], j) ? 1:0);
		}

		pr_debug("\n");
	}

	pr_debug("\n");
}


void dump_ba_clone_map(ba_lun_t *ba_lun)
{
	lun_info_t	*lun_info = NULL;
	int		 i = 0;

	lun_info = (lun_info_t *)ba_lun->ba_lun_handle;

	pr_debug("Dumping clone map: map size = %u\n",
		lun_info->total_aus);

	for (i = 0; i < lun_info->total_aus; i++) {
		if (i % 64 == 0)
			pr_debug("\n%3d", i);

		if (i % 4 == 0)
			pr_debug("   ");

		pr_debug("%2X", lun_info->aun_clone_map[i]);
	}

	pr_debug("\n");
}
#endif
