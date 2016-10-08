#ifndef _KLP_WARN_H
#define _KLP_WARN_H

#define WARN(format, ...)						\
	fprintf(stderr, "%s: " format "\n", elf->name, ##__VA_ARGS__)

#endif /* _KLP_WARN_H */
