SUB Wrap(A%, B%)
LOCAL C$
C$ = "x"
IF A% > B% THEN
A% = 0
EXIT SUB
END IF
PRINT C$; A%
END SUB
D% = 5
E% = 2
CALL Wrap(D%, E%)
END
