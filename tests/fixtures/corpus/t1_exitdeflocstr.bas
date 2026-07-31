DEF FNWrap$(A$, B%)
LOCAL C$
C$ = "x"
IF B% > 3 THEN
FNWrap$ = C$
EXIT DEF
END IF
FNWrap$ = C$ + A$
END DEF
PRINT FNWrap$("y", 5)
END
