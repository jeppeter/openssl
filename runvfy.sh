#! /bin/sh

mustcompile=0
while [ $# -gt 0 ]
do
	curfile=$1
	shift
	cp /mnt/zdisk/openssl/$curfile /home/bt/source/openssl/$curfile
	mustcompile=1	
done

if [ $mustcompile -ne 0 ]
then
	pushd $PWD && cd /home/bt/source/openssl/ && make  && popd
fi

export LD_LIBRARY_PATH=/home/bt/source/openssl/:/mnt/zdisk/clibs/dynamiclib

outfile=/mnt/zdisk/log.txt
simpleout=/mnt/zdisk/log_simple.txt	
signfile=/mnt/zdisk/sign.bin
ectype=secp112r1
ecpub=/mnt/zdisk/ecpub.bin
#ectype=secp224r1
privnum=0x13c5873c53d1046528aeed5cbe4b
hashnumber=0x99bcf1bc2a70d552e85a3b7efe51
hashsize=14
randfile=/mnt/zdisk/rand.bin

if [ ! -x /mnt/zdisk/clibs/test/ssltst/ssltst ]
then
	pushd $PWD && cd /mnt/zdisk/clibs/test/ssltst && make && popd
fi

export OPENSSL_RANDFILE=$randfile
/mnt/zdisk/clibs/test/ssltst/ssltst ecvfybase $ectype $ecpub $hashnumber $signfile $hashsize 2>$outfile
if [ $? -eq 0 ]
then
	python /mnt/zdisk/pylib/utils.py filterlog -i $outfile -o $simpleout python
else
	python /mnt/zdisk/pylib/utils.py filterlog -i $outfile -o $simpleout python
	#rm -f $simpleout
fi
