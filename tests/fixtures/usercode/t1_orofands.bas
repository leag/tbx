10 SUB SUB1(A%, B$, C%, D$)
  IF (A% = 0 AND B$ = "X") OR (C% = 1 AND D$ = "Y") THEN PRINT "YES"
END SUB
20 E% = 0
30 CALL SUB1(E%,"X",E%,"Y")
40 END
