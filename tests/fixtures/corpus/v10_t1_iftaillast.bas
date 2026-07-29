SUB Listrows(A%, B%, C%)
LOCAL J
FOR J = 1 TO A%
PRINT J
NEXT
IF A% - B% + 1 < C% THEN B% = J - 1
END SUB
D% = 3
E% = 1
F% = 9
CALL Listrows(D%, E%, F%)
PRINT E%
END
