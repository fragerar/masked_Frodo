# Masked FrodoKEM

## Repository organisation

The masked FrodoKEM implementation is located in the `src` folder.  
The code of the non-masked implementation is taken from the official FrodoKEM [repository](https://github.com/microsoft/PQCrypto-LWEKE/).  

This repository uses pqm4 as a submodule to enable compilation for qemu.  
After cloning this repository, run the following command:  

```
git submodule update --init --recursive --progress
```

## Compilation of masked gadgets

To compile only the masked gadgets, move into `src/Masking` directory: 

```
make basics ARCH=mps2
qemu-system-arm -M mps2-an386 -nographic -semihosting -kernel main
```

## Compilation of masked FrodoKEM

To test all the FrodoKEM versions at different masking orders and for all supported platforms, move into `src` and run:  

```
./test_all.sh
```

### For x64   

Move into `src/FrodoKEM` directory.

```
make simple_tests OPT_LEVEL=FAST_GENERIC
./masked_frodo640/simple_tests
./masked_frodo976/simple_tests
./masked_frodo1344/simple_tests
```

This will compile the masking library inside `src/Masking` before producing the test executables.  

The x64 version of the masked implementation can be tested against KATs:  

```
make KATS OPT_LEVEL=FAST_GENERIC
./masked_frodo640/PQCtestKAT_kem
./masked_frodo976/PQCtestKAT_kem
./masked_frodo1344/PQCtestKAT_kem
```

### For Cortex-M4

Move into `src/FrodoKEM` directory.  
The masked implementation can be compiled for Cortex-M4 target and executed with `qemu`:  

```
make simple_tests ARCH=mps2
qemu-system-arm -M mps2-an386 -nographic -semihosting -kernel masked_frodo640/simple_tests
qemu-system-arm -M mps2-an386 -nographic -semihosting -kernel masked_frodo976/simple_tests
qemu-system-arm -M mps2-an386 -nographic -semihosting -kernel masked_frodo1344/simple_tests
```

### Profiling of the gadgets

Two profiling tools have been integrated in the compilation toolchain: `gprof` and `massif`.  

```
make simple_tests OPT_LEVEL=FAST_GENERIC PROF=TRUE
./masked_frodo640/simple_tests
gprof ./masked_frodo640/simple_tests gmon.out > analysis.txt
```

```
make simple_tests OPT_LEVEL=FAST_GENERIC USE_OPENSSL=FALSE DO_VALGRIND_CHECK=TRUE
valgrind --tool=massif --stacks=yes --time-unit=B --massif-out-file=massif.out -v masked_frodo640/simple_tests
ms_print massif.out
```

To measure the performance of the masked implementation in terms of both randomness and memory usage, run:

```
./random_all.sh
./memory_all.sh
```

### Compilation options

- `MASKING_ORDER=?`: default value is 1, number of shares is equal to `MASKING_ORDER` + 1
- `KEM_TEST_ITERATIONS=?` default value is 10  
- `GENERATION_A=<AES128|SHAKE128>`: default value is `AES128`.
- `MUL_ADD_NAIVE=TRUE`: if set to TRUE, will expand A for each share of S in AS+E operation.
- `PROF=TRUE`: if set to TRUE, compile with gprof flags.  

## Evaluation on ChipWhisperer

The folder `chipwhisperer` contains the files necessary to analyze the provided code by performing TVLA on traces generated with the ChipWhipserer-Lite platform. The ChipWhisperer must have been previously installed and configured.  

To generate the traces and perform the TVLA, use the jupyter notebook `gadgets_tvla.ipynb`.  

The folder `results` contains the TVLA results described in the paper.  