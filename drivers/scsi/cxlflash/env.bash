###########################
#Linux module dev env stuff
###########################
export CONFIG_CXLFLASH=m
export MY_KERNEL_SRC=/home/surebot/workspace/cxl-kernel/linux

alias makemod='make -C $MY_KERNEL_SRC M=$(pwd)'
