10 SUB SUB1(A%)
  LOCAL B%, C%, D%
  C% = 0
  D% = A%
  FOR B% = 1 TO 10 STEP D%
  C% = C% + B%
  NEXT B%
  PRINT C%
END SUB
20 CALL SUB1(2)
30 END
