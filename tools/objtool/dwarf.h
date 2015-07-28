/*
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

#ifndef _STACKVALIDATE_DWARF_H
#define _STACKVALIDATE_DWARF_H

#include <linux/list.h>
#include <dwarf.h>
#include "elf.h"

struct cfi_insn {
	struct list_head list;
	unsigned char opcode;
	u16 delta;
	unsigned char reg;
	unsigned long offset;
};

struct dwarf_cie {
	struct list_head list;
	unsigned long offset;
	struct list_head cfi_insns;
};

struct dwarf_fde {
	struct list_head list;
	struct dwarf_cie *cie;
	struct section *ip_sec;
	unsigned long ip_offset, ip_len;
	struct list_head cfi_insns;

};

struct dwarf {
	struct elf *elf;
	bool write;
	struct section *sec;
	struct list_head cies;
	struct list_head fdes;
};

struct dwarf *dwarf_open(struct elf *elf, bool write);
void dwarf_close(struct dwarf *dwarf);

#endif /* _STACKVALIDATE_DWARF_H */
