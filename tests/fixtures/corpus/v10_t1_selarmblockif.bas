SUB Barmove(A%, B%, C%, D$)
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
E% = 1
F% = 5
G% = 3
H$ = "a"
CALL Barmove(E%, F%, G%, H$)
END
