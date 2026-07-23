10 DEF FNFN1(A)
  LOCAL V0$(), B, C$, D%, E, F
  D% = 2
  DIM V0$(D%)
  V0$(1) = "X"
  B = 1
  C$ = "Z"
  C$ = UCASE$(C$)
  FOR G = 0 TO 2 STEP B
  V0$(G) = "Y"
  NEXT G
  ERASE V0$
  F = 1
  FOR E = 1 TO D% STEP F
  B = B + E
  NEXT E
  FNFN1 = B + A
END DEF
20 PRINT FNFN1(3)
30 END
