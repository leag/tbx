10 OPTION BASE 1
20 INPUT N
30 DIM A(4)
40 DIM C(3,2)
50 DIM B(N)
60 A(1) = 2
70 A(N) = A(2) + 1
80 C(1,2) = A(N)
90 C(N,1) = 4
100 B(1) = C(1,1)
110 PRINT A(N); C(N,2); B(N)
120 END
