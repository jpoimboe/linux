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

#ifndef _CFI_H
#define _CFI_H

//FIXME arch-specific
enum dwarf_reg {
	CFI_EXPRESSION = -3,
	CFI_CFA = -2,
	CFI_UNDEFINED = -1,
	CFI_AX = 0,
	CFI_DX,
	CFI_CX,
	CFI_BX,
	CFI_SI,
	CFI_DI,
	CFI_BP,
	CFI_SP,
	CFI_R8,
	CFI_R9,
	CFI_R10,
	CFI_R11,
	CFI_R12,
	CFI_R13,
	CFI_R14,
	CFI_R15,
	CFI_RA,
};  //FIXME cfi_reg?  //FIXME lots of wasted space here....

enum frame_state {
	FRAME_NONE = 0,
	FRAME_SETUP_1,
	FRAME_SETUP_2,
	FRAME_CREATED,
};

enum stack_op_type {
	OP_ENABLE_FP,
	OP_DISABLE_FP,
	OP_ADD_SP,
	OP_SAVE_REG,
	OP_RESTORE_REG,
	OP_COPY_REG,
};

#define CFI_NUM_REGS	17

struct cfi_reg {
	enum dwarf_reg reg;
	int offset;
};

struct cfi_state {
	struct cfi_reg cfa;
	struct cfi_reg regs[CFI_NUM_REGS];  //FIXME make CFI_NUM_REGS arch-specific...?
};

struct insn_state {
	struct cfi_state cfi;

	struct cfi_reg cfa_store;
	enum dwarf_reg drap;
};

struct dwarf_state {
	struct cfi_state cfi;

	struct cfi_state remember;
	unsigned long offset;
};

#endif /* _CFI_H */
