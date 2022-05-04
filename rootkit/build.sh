#!/bin/bash

if [ -z "$1" ]
  then
    echo "Provide module name as argument"
    exit
fi

echo "obj-m = $1.o" > Makefile
echo "all:" >> Makefile
echo "	make -C /lib/modules/$(uname -r)/build M=$(pwd) modules" >> Makefile

make
rm $1.mod* $1.o modules.order Module.symvers
