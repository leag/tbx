10 PRINT FNFN1$("hello",2)
20 END
30 DEF FNFN1$(A$, B%)
  MID$(A$, B%, 1) = " "
  FNFN1$ = A$
END DEF
