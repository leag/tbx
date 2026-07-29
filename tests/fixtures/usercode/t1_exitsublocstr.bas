10 SUB SUB1(A%, B%)
  LOCAL C$
  C$ = "x"
  IF A% > B% THEN
    A% = 0
    EXIT SUB
  END IF
  PRINT C$; A%
END SUB
20 D% = 5
30 E% = 2
40 CALL SUB1(D%,E%)
50 END
