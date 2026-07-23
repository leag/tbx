10 DEF FNFN1(A)
  LOCAL V0$(), B, C$
  DIM V0$(2)
  V0$(1) = "X"
  B = 1
  C$ = "Z"
  C$ = UCASE$(C$)
  FOR D = 0 TO 2 STEP B
  V0$(D) = "Y"
  NEXT D
  ERASE V0$
  FNFN1 = B + A
END DEF
20 PRINT FNFN1(3)
30 END
