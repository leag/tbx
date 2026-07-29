10 SUB SUB1(A%, B%, C%, D$)
  SELECT CASE D$
  CASE "a"
    IF A% < B% THEN
      INCR C%
      IF C% > 2 THEN
        DECR C%
        IF A% <= B% THEN
          PRINT "u"
        ELSE
          A% = B%
        END IF
      END IF
    END IF
  CASE ELSE
    PRINT "z"
  END SELECT
END SUB
20 E% = 1
30 F% = 5
40 G% = 3
50 H$ = "a"
60 CALL SUB1(E%,F%,G%,H$)
70 END
