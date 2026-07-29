SUB Blit INLINE
$INLINE &H55, &H8B, &HEC, &HC4, &H7E, &H06, &H5D, &HCB
END SUB
SUB Wrap(A$, B%, C%)
CALL Blit(A$)
IF B% = 0 THEN IF C% = 0 THEN B% = 1 ELSE B% = C%
WHILE MID$(A$, B%, 1) <> "1"
INCR B%
WEND
PRINT B%
END SUB
D$ = "001"
E% = 0
F% = 2
CALL Wrap(D$, E%, F%)
END
