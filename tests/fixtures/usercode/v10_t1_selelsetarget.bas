10 SUB SUB1(A%, B$, C%)
  IF B$ = "a" OR B$ = "b" THEN
    SELECT CASE A%
    CASE 3
      PRINT "three"
    CASE ELSE
      PRINT "other"
      IF C% > 2 THEN PRINT "flon"
    END SELECT
    SELECT CASE B$
    CASE "a"
      PRINT "AA"
    CASE ELSE
      PRINT "BB"
    END SELECT
  END IF
END SUB
20 D% = 3
30 E$ = "a"
40 F% = 1
50 CALL SUB1(D%,E$,F%)
60 END
