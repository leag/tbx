$DYNAMIC
DIM A$(10)
A$(2) = "hello"
CALL SUB1(2)
PRINT A$(2)
END
SUB SUB1(I%)
  SHARED A$()
  MID$(A$(I%), 1, 1) = "X"
END SUB
