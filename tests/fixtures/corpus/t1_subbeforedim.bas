$DYNAMIC
SUB SUB1(I%)
  SHARED A%()
  A%(0) = A%(0) + 7
  A%(I%) = A%(I%) + 1
END SUB
DIM A%(10)
A%(0) = 1
A%(2) = 3
CALL SUB1(2)
PRINT A%(0)
PRINT A%(2)
END
