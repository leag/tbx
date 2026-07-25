10 SUB SUB1(A, B$, C, D, E, F)
  IF A AND ((B$ = CHR$(75)) OR (B$ = CHR$(77))) THEN
    SELECT CASE B$
    CASE CHR$(75)
      C = -1
    CASE CHR$(77)
      C = 1
    END SELECT
    D = -1
    E = F
    F = 0
  END IF
END SUB
20 G = -1
30 H$ = CHR$(75)
40 I = 0
50 J = 0
60 K = 0
70 L = 3
80 CALL SUB1(G,H$,I,J,K,L)
90 PRINT I; J; K; L
100 END
