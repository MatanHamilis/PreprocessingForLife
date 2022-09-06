#!/usr/bin/env bash
set -e
if [ ! -d softspoken-implementation/ ]; then
	git clone https://github.com/ldr709/softspoken-implementation.git --recursive
fi
cd softspoken-implementation/
if [ ! -d build ]; then
	mkdir build
fi
cd build
cmake .. -D ENABLE_ALL_OT=ON -D ENABLE_SODIUM=ON -D SODIUM_MONTGOMERY=OFF
make -j 4
for i in $(seq 10); do
	echo $i
	./frontend/frontend_libOTe -sshonest -n 10000000 -f $i
done
