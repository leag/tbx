10 DIM A$(10)
20 I% = 3
30 A$(I%) = "HELLO"
40 B$ = "XY"
50 MID$(A$(I%), 2, 2) = B$
60 PRINT A$(I%)
