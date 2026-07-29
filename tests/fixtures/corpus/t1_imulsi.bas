DIM A%(10)
DIM B%(5,5)
FOR K% = 1 TO 10
  A%(K%) = K%
NEXT K%
FOR I% = 1 TO 5
  FOR J% = 1 TO 5
    B%(I%,J%) = I% + J%
  NEXT J%
NEXT I%
S% = 0
FOR K% = 1 TO 5
  S% = S% + A%(K%) * B%(K%,K%)
NEXT K%
PRINT S%
END
