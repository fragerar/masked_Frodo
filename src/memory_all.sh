#!/bin/bash

if [[ $1 == "-h" || $1 == "--help" ]]; then
    echo -e "usage: ./memory_all.sh [clean] <640|976|1344> <order>"
    exit 0
elif [[ $1 == "clean" ]]; then
    cd FrodoKEM && make clean >> /dev/null
    echo -e "Temporary files cleaned."
    exit 0
elif [ -n "$1" ]; then
    declare -a frodo_levels=($1)
else
    declare -a frodo_levels=("640" "976" "1344")
fi

if [ -n "$2" ]; then
    declare -a orders=("$2")
else
    declare -a orders=("1" "2" "3" "4" "5" "6" "7")
fi

cd FrodoKEM

echo -e "#############################"
echo -e "# Measuring for x64"
echo -e "#############################\n"

for order in "${orders[@]}"; do
    echo -e "Measuring at order $order  "
    echo -e "====================="
    make clean >> /dev/null 2>&1
    make simple_tests OPT_LEVEL=FAST_GENERIC MASKING_ORDER=$order USE_OPENSSL=FALSE DO_VALGRIND_CHECK=TRUE >> /dev/null 2>&1

    for level in "${frodo_levels[@]}"; do
        valgrind --tool=massif --stacks=yes  --time-unit=B --massif-out-file=massif.out masked_frodo$level/simple_tests >> /dev/null 2>&1
        max_stack=$(cat massif.out | grep mem_stacks_B | cut -f2 -d '=' | awk '$1 > m || NR == 1 { m = $1 } END { print m }')
        echo -e "[FrodoKEM $level]\t"$max_stack
    done
    echo -e "=====================\n"
done
