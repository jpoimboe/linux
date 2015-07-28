/*
 * dwarf.c - DWARF access library
 *
 * Copyright (C) 2015 Josh Poimboeuf <jpoimboe@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include "dwarf.h"
#include "warn.h"

#define DWARF_CFA_OPCODE(op) (op & 0xc0)
#define DWARF_CFA_OPERAND(op) (op & 0x3f)

#define DWARF_CODE_ALIGN		1
#define DWARF_DATA_ALIGN		-8
#define DWARF_ARCH_RET_ADDR_COLUMN	16 /* FIXME */

static u8 dwarf_read_u8(unsigned long *addr)
{
	u8 val = *(u8 *)(*addr);
	(*addr)++;
	return val;
}

static u16 dwarf_read_u16(unsigned long *addr)
{
	u16 val = *(u16 *)(*addr);
	*addr = *addr + 2;
	return val;
}

static u32 dwarf_read_u32(unsigned long *addr)
{
	u32 val = *(u32 *)(*addr);
	*addr = *addr + 4;
	return val;
}

static s32 dwarf_read_s32(unsigned long *addr)
{
	s32 val = *(s32 *)(*addr);
	*addr = *addr + 4;
	return val;
}

static unsigned long dwarf_read_uleb128(unsigned long *addr)
{
	u8 byte;
	unsigned long val = 0, shift = 0;

	do {
		byte = dwarf_read_u8(addr);
		val |= ((unsigned long)byte & 0x7f) << shift;
		shift += 7;
	} while (byte & 0x80);

	return val;
}

static long dwarf_read_leb128(unsigned long *addr)
{
	u8 byte;
	long val = 0;
	unsigned long shift = 0;

	do {
		byte = dwarf_read_u8(addr);
		val |= ((unsigned long)byte & 0x7f) << shift;
		shift += 7;
	} while (byte & 0x80);

	/* sign extend */
	if (shift < sizeof(long)*8 && (byte & 0x40) != 0)
		val |= ((long) -1) << shift;

	return val;
}

static struct cfi_insn *dwarf_read_cfi_insn(unsigned long *addr)
{
	unsigned char opcode;
	struct cfi_insn *cfi_insn;
	unsigned long end;

	cfi_insn = malloc(sizeof(*cfi_insn));
	if (!cfi_insn) {
		perror("malloc");
		return NULL;
	}
	memset(cfi_insn, 0, sizeof(*cfi_insn));

	opcode = dwarf_read_u8(addr);

	cfi_insn->opcode = DWARF_CFA_OPCODE(opcode);

	switch (cfi_insn->opcode) {

	case 0:
		break;

	case DW_CFA_advance_loc:
		cfi_insn->delta = DWARF_CFA_OPERAND(opcode) * DWARF_CODE_ALIGN;
		return cfi_insn;

	case DW_CFA_offset:
		cfi_insn->reg = DWARF_CFA_OPERAND(opcode);
		cfi_insn->offset = dwarf_read_uleb128(addr) * DWARF_DATA_ALIGN;
		return cfi_insn;

	case DW_CFA_restore:
		cfi_insn->reg = DWARF_CFA_OPERAND(opcode);
		return cfi_insn;

	default:
		return NULL;
	}

	cfi_insn->opcode = opcode;

	switch(opcode) {

	case DW_CFA_def_cfa_expression:
		end = dwarf_read_uleb128(addr);
		end += *addr;
		if (dwarf_read_u8(addr) != DW_OP_breg6) {
			printf("FIXME 2\n");
			return NULL;
		}
		cfi_insn->offset = dwarf_read_leb128(addr);
		*addr = end;
		return cfi_insn;

	case DW_CFA_expression:
		cfi_insn->reg = dwarf_read_uleb128(addr);
		if (dwarf_read_uleb128(addr) != 2 ||
		    dwarf_read_u8(addr) != DW_OP_breg6) {
			printf("FIXME\n");
			return NULL;
		}
		cfi_insn->offset = dwarf_read_u8(addr);
		return cfi_insn;

	case DW_CFA_advance_loc1:
		cfi_insn->delta = dwarf_read_u8(addr) * DWARF_CODE_ALIGN;
		return cfi_insn;

	case DW_CFA_advance_loc2:
		cfi_insn->delta = dwarf_read_u16(addr) * DWARF_CODE_ALIGN;
		return cfi_insn;

	case DW_CFA_def_cfa:
		cfi_insn->reg = dwarf_read_uleb128(addr);
		cfi_insn->offset = dwarf_read_uleb128(addr);
		return cfi_insn;

	case DW_CFA_def_cfa_register:
		cfi_insn->reg = dwarf_read_uleb128(addr);
		return cfi_insn;

	case DW_CFA_def_cfa_offset:
		cfi_insn->offset = dwarf_read_uleb128(addr);
		return cfi_insn;

	case DW_CFA_remember_state:
	case DW_CFA_restore_state:
	case DW_CFA_nop:
		return cfi_insn;

	default:
		return NULL;
	}
}

static struct dwarf_fde *dwarf_read_fde(struct section *sec,
					unsigned long offset,
					unsigned long pc_offset, //FIXME change this to be absolute
					unsigned long len)
{
	unsigned long addr;
	unsigned int augmentation_len;
	struct dwarf_fde *fde;
	struct rela *rela;

	fde = malloc(sizeof(*fde));
	if (!fde) {
		perror("malloc");
		return NULL;
	}

	addr = sec->data + offset + pc_offset;

	rela = find_rela_by_dest(sec, addr - sec->data);
	if (!rela) {
		WARN("can't find pc rela");
		return NULL;
	}
	if (rela->sym->type != STT_SECTION) {
		WARN("rela type != section");
		return NULL;
	}

	fde->ip_sec = rela->sym->sec;
	fde->ip_offset = rela->addend;

	addr += 4;

	fde->ip_len = dwarf_read_s32(&addr);

	augmentation_len = dwarf_read_uleb128(&addr);
	if (augmentation_len != 0) {
		WARN("unexpected augmentation length %d", augmentation_len);
		return NULL;
	}

	INIT_LIST_HEAD(&fde->cfi_insns);

	//FIXME this can be moved to helper function and reused for cie
	while (addr < sec->data + offset + len) {
		struct cfi_insn *cfi_insn = dwarf_read_cfi_insn(&addr);
		if (!cfi_insn) {
			WARN_PTR("bad CFI instruction", sec, addr);
			return NULL;
		}
		list_add_tail(&cfi_insn->list, &fde->cfi_insns);
	}

	//FIXME consider union for cie and fde structs
	//FIXME kfree

	return fde;
}

static struct dwarf_cie *dwarf_read_cie(struct section *sec,
					unsigned long offset,
					unsigned long version_offset,
					unsigned long len)
{
	//FIXME need more generic read_length read_augmentation_length etc instead of read_cie and read_fde
	unsigned long addr;
	u8 version;
	const char *augmentation_str;
	unsigned int code_align, augmentation_len;
	int data_align;
	unsigned char ret_addr_column, encoding;
	struct dwarf_cie *cie;

	cie = malloc(sizeof(*cie));
	if (!cie) {
		perror("malloc");
		return NULL;
	}

	cie->offset = offset;

	addr = sec->data + offset + version_offset;

	version = dwarf_read_u8(&addr);
	if (version != 1) {
		WARN("unexpected .eh_frame version %d", version);
		return NULL;
	}

	augmentation_str = (const char *)addr;
	if (strcmp(augmentation_str, "zR")) {
		WARN("unexpected augmentation string %s", augmentation_str);
		return NULL;
	}
	addr += strlen(augmentation_str) + 1;

	code_align = dwarf_read_uleb128(&addr);
	if (code_align != DWARF_CODE_ALIGN) {
		WARN("unexpected code alignment factor %u", code_align);
		return NULL;
	}

	data_align = dwarf_read_leb128(&addr);
	if (data_align != DWARF_DATA_ALIGN) {
		WARN("unexpected data alignment factor %d", data_align);
		return NULL;
	}

	ret_addr_column = dwarf_read_u8(&addr);
	if (ret_addr_column != DWARF_ARCH_RET_ADDR_COLUMN) {
		WARN("unexpected return address column %u", ret_addr_column);
		return NULL;
	}

	augmentation_len = dwarf_read_uleb128(&addr);
	if (augmentation_len != 1) {
		WARN("unexpected augmentation length %d", augmentation_len);
		return NULL;
	}

	encoding = dwarf_read_u8(&addr);
	if (encoding != 0x1b) { //FIXME
		WARN("unexpected encoding %u", encoding); //FIXME WARN_PTR here and elsewhere
		return NULL;
	}

	INIT_LIST_HEAD(&cie->cfi_insns);

	while (addr < sec->data + offset + len) {
		struct cfi_insn *cfi_insn = dwarf_read_cfi_insn(&addr);
		if (!cfi_insn) {
			WARN_PTR("bad CFI instruction", sec, addr);
			return NULL;
		}
		list_add_tail(&cfi_insn->list, &cie->cfi_insns);
	}

	return cie;
}

static int dwarf_read_cfi(struct dwarf *dwarf)
{
	struct section *sec;
	unsigned long addr, offset;
	u32 len, cie_offset;

	INIT_LIST_HEAD(&dwarf->cies);
	INIT_LIST_HEAD(&dwarf->fdes);

	sec = find_section_by_name(dwarf->elf, ".eh_frame");
	if (!sec) {
		WARN("missing .eh_frame section");
		return -1;
	}
	dwarf->sec = sec; //FIXME needed?

	for (offset = 0; offset < sec->len; offset += len) {
		addr = sec->data + offset;

		len = dwarf_read_u32(&addr);
		if (!len || len == 0xffffffff) {
			WARN("unexpected entry len %u", len);
			return -1;
		}

		len += 4;

		cie_offset = dwarf_read_u32(&addr);

		if (!cie_offset) {
			struct dwarf_cie *cie;

			cie = dwarf_read_cie(sec, offset,
					     addr - sec->data - offset, len);
			if (!cie)
				return -1;

			list_add_tail(&cie->list, &dwarf->cies);
		} else {
			struct dwarf_fde *fde;
			struct dwarf_cie *cie;

			cie_offset = addr - 4 - sec->data - cie_offset;

			fde = dwarf_read_fde(sec, offset,
					     addr - sec->data - offset, len);
			if (!fde)
				return -1;

			fde->cie = NULL;
			list_for_each_entry(cie, &dwarf->cies, list) {
				if (cie->offset == cie_offset) {
					fde->cie = cie;
					break;
				}
			}
			if (!fde->cie) {
				WARN("can't find cie"); //FIXME
				return -1;
			}

			list_add_tail(&fde->list, &dwarf->fdes);
		}
	}

	return 0;
}

void dwarf_close(struct dwarf *dwarf)
{
	//FIXME free lists etc
	free(dwarf);
}

struct dwarf *dwarf_open(struct elf *elf, bool write)
{
	struct dwarf *dwarf;

	dwarf = malloc(sizeof(*dwarf));
	if (!dwarf) {
		perror("malloc");
		return NULL;
	}

	dwarf->elf = elf;
	dwarf->write = write;

	if (!dwarf->write && dwarf_read_cfi(dwarf))
		goto err;

	return dwarf;

err:
	dwarf_close(dwarf);
	return NULL;
}
