#!/bin/bash
#
# Basic script to mv all of the txt files out of subdirectories and into the current
# directory for the AU enumeration run. Cannot do in one go as there are too many
# and receive an error

for i in `seq -f "%03g" 0 149`; do mv thread$i/4*.txt .; done
for i in `seq -f "%03g" 0 149`; do mv thread$i/6*.txt .; done
for i in `seq -f "%03g" 0 149`; do mv thread$i/7*.txt .; done
for i in `seq -f "%03g" 0 149`; do mv thread$i/8*.txt .; done
for i in `seq -f "%03g" 0 149`; do mv thread$i/9*.txt .; done
for i in `seq -f "%03g" 0 149`; do mv thread$i/1[1-9].*.txt .; done
for i in `seq -f "%03g" 0 149`; do mv thread$i/10[1-9].*.txt .; done
for i in `seq -f "%03g" 0 149`; do mv thread$i/1[1-4][1-9].*.txt .; done
for i in `seq -f "%03g" 0 149`; do mv thread$i/1[5-9][1-9].*.txt .; done
for i in `seq -f "%03g" 0 149`; do mv thread$i/1*.txt .; done
for i in `seq -f "%03g" 0 149`; do mv thread$i/2[0-9][0-9].*.txt .; done
for i in `seq -f "%03g" 0 149`; do mv thread$i/2*.txt .; done
for i in `seq -f "%03g" 0 149`; do mv thread$i/52.*.txt .; done
for i in `seq -f "%03g" 0 149`; do mv thread$i/54.*.txt .; done
for i in `seq -f "%03g" 0 149`; do mv thread$i/5*.txt .; done
for i in `seq -f "%03g" 0 149`; do mv thread$i/3[0-9].*.txt .; done
for i in `seq -f "%03g" 0 149`; do mv thread$i/3*.txt .; done
for i in `ls -d thread???`; do mv $i/*.txt .; done
