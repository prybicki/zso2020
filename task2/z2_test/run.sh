#!/bin/bash

cd $(dirname $0)
make

run() {
	tst_exec=$1
	result=$2
	ok=1

	echo === Test $tst_exec ===
	echo DEADBEEF > tst
	if ! ./$tst_exec ; then
		echo "Exec failed"
		ok=0
	fi

	if ! cmp --silent tst $result ; then
		echo Invalid file content
		ok=0
	fi

	[ "$ok" == "1" ] && echo OK
}

for x in nosync_* ftrunc lseek fstat multi_fd; do
	run $x nosync.out
done

for x in partial_*; do
	run $x partial.out
done

for x in sync_* default_* multi_fd_sync; do
	run $x sync.out
done


