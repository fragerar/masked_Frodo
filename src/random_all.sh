#!/bin/bash

if [[ $1 == "-h" || $1 == "--help" ]]; then
    echo -e "usage: ./random_all.sh [clean] <640|976|1344> <order>"
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
    make simple_tests OPT_LEVEL=FAST_GENERIC MASKING_ORDER=$order PROF=TRUE >> /dev/null 2>&1

    for level in "${frodo_levels[@]}"; do
        ./masked_frodo$level/simple_tests >> /dev/null 2>&1
        rand_decaps=$(gprof -prand_u16 -b ./masked_frodo$level/simple_tests gmon.out | grep rand_u16 | awk -F ' ' '{print $4}')
        # we don't want to count the randomness used to mask the secret key
        rand_key=$(gprof ./masked_frodo$level/simple_tests gmon.out | grep arith_mask_value_u16_array | grep $rand_decaps | awk -F ' ' '{print $3}' | awk -F '/' '{print $1}')
        echo -e "[FrodoKEM $level]\t"$(($rand_decaps - $rand_key))""
    done
    echo -e "=====================\n"
done
