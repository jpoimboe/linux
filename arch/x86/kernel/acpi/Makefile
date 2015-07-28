obj-$(CONFIG_ACPI)		+= boot.o
obj-$(CONFIG_ACPI_SLEEP)	+= sleep.o wakeup_$(BITS).o
obj-$(CONFIG_ACPI_APEI)		+= apei.o

ifneq ($(CONFIG_ACPI_PROCESSOR),)
obj-y				+= cstate.o
endif

OBJECT_FILES_NON_STANDARD_wakeup_$(BITS).o := y
