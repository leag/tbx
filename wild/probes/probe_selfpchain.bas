DEF FNCurvideo
 REG 1,&H0F00
 CALL INTERRUPT(&H10)
 FNCurvideo = REG(1) AND &H0F
END DEF
SELECT CASE disp
CASE 0 : msg$ = "MONO"
CASE 1 : msg$ = "CGA"
CASE 2 : msg$ = "EGA"
CASE 3 : msg$ = "MCGA"
CASE 4 : msg$ = "VGA"
END SELECT
msg1$ = STR$(FNCurvideo)
msg$ = msg$ + " monitor in video mode "+msg1$
PRINT msg$
END
