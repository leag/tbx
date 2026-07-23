10 DEF FNFN1(A)
  LOCAL V0$(), B, C$, D%
  D% = 2
  DIM V0$(D%)
  V0$(1) = "X"
  B = 1
  C$ = "Z"
  C$ = UCASE$(C$)
  FOR E = 0 TO 2 STEP B
  V0$(E) = "Y"
  NEXT E
  ERASE V0$
  FNFN1 = B + A
END DEF
20 PRINT FNFN1(3)
30 END
