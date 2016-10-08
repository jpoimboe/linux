/*
 * Copyright (C) 2016 Josh Poimboeuf <jpoimboe@redhat.com>
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
#include "elf.h"
#include "warn.h"

//FIXME
#undef ELF_ST_BIND
#undef ELF_ST_TYPE
#undef ELF_R_SYM
#undef ELF_R_TYPE

#if KERNEL_ELFCLASS == ELFCLASS32

#define Elf_Ehdr    Elf32_Ehdr
#define Elf_Shdr    Elf32_Shdr
#define Elf_Sym     Elf32_Sym
#define Elf_Addr    Elf32_Addr
#define Elf_Sword   Elf64_Sword
#define Elf_Section Elf32_Half
#define ELF_ST_BIND ELF32_ST_BIND
#define ELF_ST_TYPE ELF32_ST_TYPE

#define Elf_Rel     Elf32_Rel
#define Elf_Rela    Elf32_Rela
#define ELF_R_SYM   ELF32_R_SYM
#define ELF_R_TYPE  ELF32_R_TYPE
#else

#define Elf_Ehdr    Elf64_Ehdr
#define Elf_Shdr    Elf64_Shdr
#define Elf_Sym     Elf64_Sym
#define Elf_Addr    Elf64_Addr
#define Elf_Sword   Elf64_Sxword
#define Elf_Section Elf64_Half
#define ELF_ST_BIND ELF64_ST_BIND
#define ELF_ST_TYPE ELF64_ST_TYPE

#define Elf_Rel     Elf64_Rel
#define Elf_Rela    Elf64_Rela
#define ELF_R_SYM   ELF64_R_SYM
#define ELF_R_TYPE  ELF64_R_TYPE
#endif

#define MODULE_NAME_LEN (64 - sizeof(Elf_Addr))

#define SHN_LIVEPATCH		0xff20
#define SHF_RELA_LIVEPATCH	0x00100000


static const char usage_string[] =
	"klp-convert <input.ko> <output.ko>";

struct elf *elf;

//FIXME
struct klp_module_reloc {
	void *sym;
	unsigned int sympos;
} __attribute__((packed));

static struct section *find_or_create_klp_rela_section(char *objname,
						       struct section *oldsec)
{
	char secname[256]; //FIXME
	struct section *sec;

	//FIXME this function should be mostly moved to elf.c?
	sprintf(secname, ".klp.rela.%s.%s", objname, oldsec->base->name);

	sec = find_section_by_name(elf, secname);
	if (sec)
		return sec;

	sec = malloc(sizeof(*sec));
	if (!sec) {
		WARN("malloc failed");
		return NULL;
	}
	memset(sec, 0, sizeof(*sec));
	INIT_LIST_HEAD(&sec->relas);

	sec->base = oldsec->base;
	sec->name = strdup(secname);
	sec->sh.sh_name = -1; //FIXME helper functions for these?
	sec->sh.sh_type = SHT_RELA;
	sec->sh.sh_entsize = sizeof(GElf_Rela);
	sec->sh.sh_addralign = 8;
	sec->sh.sh_flags = SHF_RELA_LIVEPATCH | SHF_ALLOC;


	sec->elf_data = malloc(sizeof(*sec->elf_data));
	if (!sec->elf_data) {
		WARN("malloc failed");
		return NULL;
	}
	memset(sec->elf_data, 0, sizeof(*sec->elf_data));
	sec->elf_data->d_type = ELF_T_RELA;


	list_add_tail(&sec->list, &elf->sections);

	return sec;
}

static int rename_klp_symbols(struct section *sec, char *objname)
{
	struct section *relasec;
	struct rela *rela, *next;
	struct klp_module_reloc *reloc;
	int nr_entries, i;
	char name[256]; //FIXME

	relasec = sec->rela;
	if (!relasec) {
		WARN("section %s doesn't have a corresponding rela section",
		     sec->name);
		return -1;
	}

	if (list_empty(&relasec->relas)) {
		WARN("section %s is empty", relasec->name);
		return -1;
	}

	reloc = sec->data;
	nr_entries = sec->size / sizeof(*reloc);

	//FIXME improve loop?
	rela = list_first_entry(&relasec->relas, struct rela, list);
	for (i = 0; i < nr_entries; i++) {
		next = list_next_entry(rela, list);
		list_del(&rela->list);

		sprintf(name, ".klp.sym.%s.%s,%d", objname, rela->sym->name,
			reloc[i].sympos);
		rela->sym->name = strdup(name);
		rela->sym->sym.st_name = -1;
		rela->sym->sec = NULL;
		rela->sym->sym.st_shndx = SHN_LIVEPATCH;

		rela = next;
		if (&rela->list == &relasec->relas)
			break;
	}

	list_del(&relasec->list);
	list_del(&sec->list);
	list_del(&sec->sym->list);

	return 0;
}

static int migrate_klp_rela(struct section *oldsec, struct rela *rela)
{
	char objname[MODULE_NAME_LEN];
	struct section *newsec;

	if (sscanf(rela->sym->name, ".klp.sym.%55[^.]", objname) != 1) {
		WARN("bad format for klp rela %s", rela->sym->name);
		return -1;
	}

	newsec = find_or_create_klp_rela_section(objname, oldsec);
	if (!newsec)
		return -1;

	list_del(&rela->list);
	list_add_tail(&rela->list, &newsec->relas);

	return 0;
}

int main(int argc, const char **argv)
{
	const char *in_name, *out_name;
	struct section *sec, *tmpsec;
	char objname[MODULE_NAME_LEN];
	struct rela *rela, *tmprela;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s\n", usage_string);
		return 1;
	}

	in_name = argv[1];
	out_name = argv[2];

	elf = elf_open(in_name);
	if (!elf) {
		fprintf(stderr, "error reading elf file %s\b", in_name);
		return 1;
	}

	list_for_each_entry_safe(sec, tmpsec, &elf->sections, list) {
		if (sscanf(sec->name, ".klp.module_relocs.%55s", objname) != 1)
			continue;
		if (rename_klp_symbols(sec, objname))
			return 1;
	}

	list_for_each_entry(sec, &elf->sections, list) {
		if (!is_rela_section(sec))
			continue;
		if (!strncmp(sec->name, ".klp.rela.", 10))
			continue;
		list_for_each_entry_safe(rela, tmprela, &sec->relas, list) {
			if (strncmp(rela->sym->name, ".klp.sym.", 9))
				continue;
			if (migrate_klp_rela(sec, rela))
				return 1;
		}
	}

	if (elf_write(elf, out_name))
		return 1;

	return 0;
}
