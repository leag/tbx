10 PRINT FNB$("hello", 2)
20 END
30 DEF FNB$(X$, N%)
40 MID$(X$, N%, 1) = " "
50 FNB$ = X$
60 END DEF
