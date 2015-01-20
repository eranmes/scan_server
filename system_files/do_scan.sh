#!/bin/bash
if [[ $1 == "" ]]
then
  echo "No filename specified."
  exit
fi

if [[ $2 == "" ]]
then
  echo "No directory given."
  exit
fi

cd $2
export FN=$1

scanimage --mode=Color --format=pnm --resolution 300 > ${FN}.pnm
pnmtojpeg --quality=95 ${FN}.pnm > ${FN}.jpg
rm ${FN}.pnm
