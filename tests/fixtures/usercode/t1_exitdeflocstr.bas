10 DEF FNFN1$(A$, B%)
  LOCAL C$
  C$ = "x"
  IF B% > 3 THEN
    FNFN1$ = C$
    EXIT DEF
  END IF
  FNFN1$ = C$ + A$
END DEF
20 PRINT FNFN1$("y",5)
30 END
