#!/usr/bin/env bash
REPO_ADDR=git@github.com:ladnir/libOTe.git
COMMIT_ID=e907375f352a8a0691381c7ebde9f04381275c68
DEST_FOLDER=$(pwd)/silver
ITER_COUNT=1
set -e
if [ ! -d "$DEST_FOLDER" ]; then
	git clone --branch coproto "$REPO_ADDR" --recursive "$DEST_FOLDER"
	cd "$DEST_FOLDER"
	git checkout "$COMMIT_ID"
	git submodule update
	mv frontend/benchmark.h frontend/Benchmark.h
else
	cd "$DEST_FOLDER"
fi
# if [ ! -d build ]; then
# 	mkdir build
# fi
# cd build
# cmake .. -D ENABLE_ALL_OT=ON -D ENABLE_SODIUM=ON -D SODIUM_MONTGOMERY=OFF
# make -j 4
if [ ! -d out ]; then
	python build.py --all
fi
for i in $(seq "$ITER_COUNT"); do
./out/build/*/frontend/frontend_libOTe -encode -Silent -m 10000000 
done
