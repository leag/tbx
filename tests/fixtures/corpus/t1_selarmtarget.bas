SUB Wrap(A$, B%, C%)
SELECT CASE A$
CASE "a"
DECR B%
IF B% < 1 THEN B% = C%
WHILE MID$(A$, B%, 1) = "0"
DECR B%
WEND
CASE ELSE
B% = 0
END SELECT
END SUB
D$ = "a"
E% = 2
F% = 3
CALL Wrap(D$, E%, F%)
END
