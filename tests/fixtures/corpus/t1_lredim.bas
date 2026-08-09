DEF FNA%(N%)
  LOCAL A$()
  DIM A$(N%)
  ERASE A$
  DIM A$(N% + 1)
  A$(1) = "x"
  FNA% = LEN(A$(1))
END DEF
PRINT FNA%(3)
