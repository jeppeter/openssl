#! /bin/bash

export LD_LIBRARY_PATH=/home/bt/source/openssl/:/mnt/zdisk/clibs/dynamiclib
scriptfile=`readlink -f $0`
scriptdir=`dirname $scriptfile`
outdir=/mnt/zdisk/eckeys

if [ ! -d $outdir ]
then
	mkdir -p $outdir
fi

$scriptdir/apps/openssl ecparam -genkey -name sect163r1 -noout -out $outdir/sect163r1.ecpriv.named.pem -conv_form hybrid 
$scriptdir/apps/openssl ecparam -genkey -name sect163r1 -noout -out $outdir/sect163r1.ecpriv.pem -conv_form compressed -param_enc explicit
$scriptdir/apps/openssl ec -in $outdir/sect163r1.ecpriv.named.pem -pubout -out $outdir/sect163r1.ecpub.named.pem -conv_form hybrid
$scriptdir/apps/openssl ec -in $outdir/sect163r1.ecpriv.pem -pubout -out $outdir/sect163r1.ecpub.pem -conv_form compressed -param_enc explicit

$scriptdir/apps/openssl ecparam -genkey -name secp224r1 -noout -out $outdir/secp224r1.ecpriv.named.pem -conv_form hybrid 
$scriptdir/apps/openssl ecparam -genkey -name secp224r1 -noout -out $outdir/secp224r1.ecpriv.pem -conv_form compressed -param_enc explicit
$scriptdir/apps/openssl ec -in $outdir/secp224r1.ecpriv.named.pem -pubout -out $outdir/secp224r1.ecpub.named.pem -conv_form hybrid
$scriptdir/apps/openssl ec -in $outdir/secp224r1.ecpriv.pem -pubout -out $outdir/secp224r1.ecpub.pem -conv_form compressed -param_enc explicit