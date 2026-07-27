10 SUB SUB1(A%, B%, C%)
  LOCAL D
  FOR D = 1 TO A%
  PRINT D
  NEXT D
  IF C% > 1 + (A% + (-B%)) THEN B% = D - 1
END SUB
20 E% = 3
30 F% = 1
40 G% = 9
50 CALL SUB1(E%,F%,G%)
60 PRINT F%
70 END
