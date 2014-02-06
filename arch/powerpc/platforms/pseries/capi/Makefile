capi-y				+= main.o file.o irq.o fault.o capi-native.o capi-hv.o
obj-$(CONFIG_CAPI)		+= capi.o

$(obj)/trace_stat_descriptor.c: $(src)/trace_stat_descriptor.c_shipped
$(obj)/file.o: $(obj)/trace_stat_descriptor.c
