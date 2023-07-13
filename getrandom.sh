#! /bin/bash

if [ $# -lt 1 ]
then
	echo "need file" >&2
	exit 3
fi

file=$1;
shift

cat $file | grep -e 'random number' | awk '{print $3}' | xargs -I {} echo -n " {}"
echo -ne "\n"