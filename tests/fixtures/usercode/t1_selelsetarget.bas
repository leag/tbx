10 SUB SUB1(A%, B$, C%)
  IF B$ = "a" OR B$ = "b" THEN
    SELECT CASE A%
    CASE 3
      PRINT "three"
    CASE ELSE
      PRINT "other"
      IF C% <= 2 THEN 20
      PRINT "flon"
    END SELECT
20 SELECT CASE B$
    CASE "a"
      PRINT "AA"
    CASE ELSE
      PRINT "BB"
    END SELECT
  END IF
END SUB
21 D% = 3
31 E$ = "a"
41 F% = 1
51 CALL SUB1(D%,E$,F%)
61 END
