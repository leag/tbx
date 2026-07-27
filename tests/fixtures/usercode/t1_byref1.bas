10 SUB SUB1(A%)
  LOCAL B%, C%, D%
  B% = A%
  C% = A% AND 5
  D% = A% + 1
  A% = 9
  A% = B%
  PRINT B%, C%, D%, A%
END SUB
20 E% = 7
30 CALL SUB1(E%)
40 PRINT E%
50 END
