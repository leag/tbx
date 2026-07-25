SUB Prtlist(A$(1), B%)
PRINT A$(B%)
END SUB
SUB Showlist(A$(1), B%, C%)
A$(1) = "z"
IF B% < 1 THEN B% = 1
CALL Prtlist(A$(), C%)
END SUB
DIM P$(10)
P$(2) = "hi"
Q% = 0
R% = 2
CALL Showlist(P$(), Q%, R%)
END
