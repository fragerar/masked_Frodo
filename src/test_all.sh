#!/bin/bash

if [[ $1 == "-h" || $1 == "--help" ]]; then
    echo -e "usage: ./test_all.sh [clean] <SHAKE|AES> <640|976|1344> <order>"
    exit 0
elif [[ $1 == "clean" ]]; then
    cd FrodoKEM && make clean >> /dev/null
    echo -e "Temporary files cleaned."
    exit 0
elif [[ $1 == "SHAKE" ]]; then
    genA="SHAKE128"
else
    genA="AES128"
fi

if [ -n "$2" ]; then
    declare -a frodo_levels=($2)
else
    declare -a frodo_levels=("640" "976" "1344")
fi

if [ -n "$3" ]; then
    declare -a orders=("$3")
else
    declare -a orders=("1" "2" "3")
fi

cd FrodoKEM

echo -e "#############################"
echo -e "# Testing for x64"
echo -e "#############################\n"

for order in "${orders[@]}"; do
    echo -e "Testing at order $order - $genA "
    echo -e "============================="
    make clean >> /dev/null 2>&1
    make simple_tests OPT_LEVEL=FAST_GENERIC MASKING_ORDER=$order GENERATION_A=$genA >> /dev/null 2>&1

    for level in "${frodo_levels[@]}"; do
        out=$(./masked_frodo$level/simple_tests)
        if [[ $out == *"Tests PASSED"* && $out == *"KAT success"* ]]; then
            echo -e "[FrodoKEM $level]\tOK"
        else
            echo -e "[FrodoKEM $level]\tKO"
        fi
    done
    echo -e "=============================\n"
done

echo -e ""

echo -e "#############################"
echo -e "# Testing for Cortex M4"
echo -e "#############################\n"

for order in "${orders[@]}"; do
    echo -e "Testing at order $order - $genA "
    echo -e "============================="
    make clean >> /dev/null 2>&1
    make simple_tests ARCH=mps2 MASKING_ORDER=$order GENERATION_A=$genA >> /dev/null 2>&1 

    for level in "${frodo_levels[@]}"; do
        out=$(qemu-system-arm -M mps2-an386 -nographic -semihosting -kernel masked_frodo$level/simple_tests)
        if [[ $out == *"Tests PASSED"* && $out == *"KAT success"* ]]; then
            echo -e "[FrodoKEM $level]\tOK"
        else
            echo -e "[FrodoKEM $level]\tKO"
        fi
    done
    echo -e "=============================\n"
done
