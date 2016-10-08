hostprogs-y		:= klp-convert
always			:= $(hostprogs-y)

klp-convert-objs	:= klp-convert.o elf.o

HOSTCFLAGS		:= -g -I$(srctree)/include -Wall
HOSTLDFLAGS		:= -lelf
