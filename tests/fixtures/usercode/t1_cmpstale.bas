10 A$ = "#"
20 B$ = "X"
30 IF A$ = "#" AND B$ <> "" THEN PRINT "Y"
40 B$ = A$ + B$
50 IF LEN(B$) <= 4 THEN 70
60 B$ = RIGHT$(B$,4)
70 PRINT B$
80 END
