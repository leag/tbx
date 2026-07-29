SUB SUB1(N%)
  LOCAL I%, S%, T%
  S% = 0
  T% = N%
  FOR I% = 1 TO 10 STEP T%
    S% = S% + I%
  NEXT I%
  PRINT S%
END SUB
10 CALL SUB1(2)
20 END
