10 SUB SUB1(A, B)
  SHARED C
  LOCAL D, E, F$, G$
  D = 0
  C = -1
  F$ = "a"
  G$ = "b"
  FOR E = 1 TO A
  B = E
  NEXT E
  PRINT F$; G$; D
END SUB
20 SUB SUB2(A, B)
  SHARED H, I, C
  LOCAL D, E, F$, G$
  D = 0
  H = -1
  I = C
  F$ = "c"
  G$ = "d"
  FOR E = 1 TO A
  B = E
  NEXT E
  PRINT F$; G$; D
END SUB
30 C = 0
40 H = 0
50 I = 0
60 J = 2
70 K = 0
80 L = 0
90 CALL SUB1(J,K)
100 CALL SUB2(J,L)
110 PRINT K; L; C; H; I
120 END
