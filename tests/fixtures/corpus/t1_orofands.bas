10 SUB F(A%, S1$, B%, S2$)
20 IF (A% = 0 AND S1$ = "X") OR (B% = 1 AND S2$ = "Y") THEN PRINT "YES"
30 END SUB
40 X% = 0
50 CALL F(X%, "X", X%, "Y")
60 END
