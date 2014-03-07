capi-y				+= main.o file.o irq.o fault.o capi-native.o capi-hv.o
obj-$(CONFIG_CAPI)		+= capi.o

capi-pci-$(CONFIG_PPC_POWERNV)	+= pci.o
obj-$(CONFIG_PPC_POWERNV)	+= capi-pci.o

capi-of-y			+= of.o
obj-y				+= capi-of.o

$(obj)/trace_stat_descriptor.c: $(src)/trace_stat_descriptor.c_shipped
$(obj)/file.o: $(obj)/trace_stat_descriptor.c
