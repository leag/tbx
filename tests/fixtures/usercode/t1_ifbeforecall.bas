10 SUB SUB1(A$(1), B%)
  PRINT A$(B%)
END SUB
20 SUB SUB2(C$(1), D%, B%)
  C$(1) = "z"
  IF D% >= 1 THEN 24
  D% = 1
24 CALL SUB1(C$(),B%)
END SUB
30 DIM V0$(10)
40 V0$(2) = "hi"
50 E% = 0
60 F% = 2
70 CALL SUB2(V0$(),E%,F%)
80 END
