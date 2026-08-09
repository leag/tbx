10 DIM V0$(10)
20 A% = 3
30 V0$(A%) = "HELLO"
40 B$ = "XY"
50 MID$(V0$(A%), 2, 2) = B$
60 PRINT V0$(A%)
