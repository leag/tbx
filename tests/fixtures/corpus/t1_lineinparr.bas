10 DIM recarr$(50)
20 sourcename$ = "LMENUTB.TXT"
30 OPEN sourcename$ FOR INPUT AS #1
40 rec = 0
50 DO
60 INCR rec
70 LINE INPUT #1,recarr$(rec)
80 LOOP UNTIL EOF(1)
90 CLOSE #1
100 PRINT rec
110 END
