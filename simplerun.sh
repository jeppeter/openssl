#! /bin/bash

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
signlog=/mnt/zdisk/sign.log
ecfile=/mnt/zdisk/ecpriv.bin
ecpub=/mnt/zdisk/ecpub.bin
signfile=/mnt/zdisk/sign.bin
ectype=secp112r1
privnum=1152
hashnumber=7201
if [ ! -x /mnt/zdisk/clibs/test/ssltst/ssltst ]
then
	pushd $PWD && cd /mnt/zdisk/clibs/test/ssltst && make && popd
fi
/mnt/zdisk/clibs/test/ssltst/ssltst ecgen --ecpriv $ecfile --ecpub $ecpub $ectype $privnum 2>$outfile
#/mnt/zdisk/clibs/test/ssltst/ssltst ecsignbase -o $signfile $ecfile $hashnumber 2>$signlog
#/mnt/zdisk/clibs/test/ssltst/ssltst ecvfybase $ectype $ecpub $hashnumber $signfile 2>$outfile

python /mnt/zdisk/pylib/utils.py filterlog -i $outfile -o $simpleout python
numbers=`cat $simpleout | grep -e 'random number' | awk '{print $3}' | xargs -I {} echo -n " {}"`
echo "number [$numbers]"
python /mnt/zdisk/pylib/utils.py randwr -o /mnt/zdisk/rand2.bin $numbers
dd if=/dev/urandom of=/mnt/zdisk/rand.bin bs=1M count=2
dd if=/mnt/zdisk/rand2.bin of=/mnt/zdisk/rand.bin conv=notrunc