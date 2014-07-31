capi-y				+= main.o file.o irq.o fault.o capi-native.o capi-hv.o context.o
obj-$(CONFIG_CAPI)		+= capi.o
obj-$(CONFIG_CAPI_PCI)		+= pci.o
obj-$(CONFIG_CAPI_OF)		+= of.o

$(obj)/trace_stat_descriptor.c: $(src)/trace_stat_descriptor.c_shipped
$(obj)/file.o: $(obj)/trace_stat_descriptor.c
