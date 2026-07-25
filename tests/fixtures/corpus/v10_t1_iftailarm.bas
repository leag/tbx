SUB Pickone(A%, B%, C$)
SELECT CASE C$
CASE "a"
IF A% <> B% THEN PRINT "x"
CASE ELSE
PRINT "z"
END SELECT
END SUB
D% = 1
E% = 2
F$ = "a"
CALL Pickone(D%, E%, F$)
END
