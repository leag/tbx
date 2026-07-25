DEF FNCurvideo
 REG 1,&H0F00
 CALL INTERRUPT(&H10)
 FNCurvideo = REG(1) AND &H0F
END DEF
IF disp% = 0 THEN msg$ = "MONO"
msg1$ = STR$(FNCurvideo)
msg$ = msg$ + " monitor in video mode "+msg1$
PRINT msg$
END
