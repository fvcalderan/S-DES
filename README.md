# S-DES
Simplified Data Encryption Standard (S-DES)

This is a very straightforward implementation of the S-DES algorithm in C.

## How to build the program
```
gcc sdes.c -o sdes
```

## How to use the program
```
Encrypt: ./sdes -e path/to/input path/to/output
Decrypt: ./sdes -d path/to/input path/to/output
```

## Memcheck results
```
==2829== HEAP SUMMARY:
==2829==     in use at exit: 0 bytes in 0 blocks
==2829==   total heap usage: 103,214 allocs, 103,214 frees, 2,370,224 bytes allocated
==2829==
==2829== All heap blocks were freed -- no leaks are possible
==2829==
==2829== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```

## License
```
BSD 3-Clause License
Copyright (c) 2021, fvcalderan
All rights reserved.
See the full license text inside the LICENSE file.
```