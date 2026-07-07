10 OPTION BASE 1
20 INPUT N
30 DIM A(0:4)
40 DIM C(2:3,0:2)
50 DIM B(N)
60 A(0) = 2
70 A(N) = A(2) + 1
80 C(2,0) = A(N)
90 C(N,2) = 4
100 B(1) = C(3,1)
110 PRINT A(N); C(N,2); B(N)
120 END
