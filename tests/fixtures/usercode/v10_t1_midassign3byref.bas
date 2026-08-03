10 SUB SUB1(A$, B%)
  MID$(A$, B%, 1) = "X"
END SUB
20 C$ = ""
30 CALL SUB1(C$,2)
40 END
