ccflags-y := -Werror -Wno-unused-const-variable

cxl-y				+= main.o file.o irq.o fault.o
cxl-y				+= context.o sysfs.o debugfs.o trace.o
cxl-y				+= api.o vphb.o 
obj-$(CONFIG_CXL)		+= cxl.o
obj-$(CONFIG_CXL_BASE)		+= base.o
cxl-pci-y			+= native.o pci.o
obj-$(CONFIG_CXL_PCI)		+= cxl-pci.o
cxl-of-y			+= flash.o guest.o of.o hcalls.o
obj-$(CONFIG_CXL_OF)		+= cxl-of.o

# For tracepoints to include our trace.h from tracepoint infrastructure:
CFLAGS_trace.o := -I$(src)
ccflags-y += -DDEBUG
