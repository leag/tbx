10 SUB SUB1(A$, B%, C%)
  MID$(A$, B%) = CHR$(64 + C%)
END SUB
20 D$ = ""
30 CALL SUB1(D$,2,3)
40 END
