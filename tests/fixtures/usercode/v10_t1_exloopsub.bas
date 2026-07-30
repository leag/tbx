10 CALL SUB1("Q")
20 END
30 SUB SUB1(A$)
  B$ = "A"
  C% = 65
  D% = 3
  DO
  IF B$ = A$ THEN
    LOCATE 11,D%
    PRINT CHR$(24)
    EXIT LOOP
  END IF
  D% = D% + 2
  C% = C% + 1
  B$ = CHR$(C%)
  LOOP
  LOCATE 15,1
END SUB
