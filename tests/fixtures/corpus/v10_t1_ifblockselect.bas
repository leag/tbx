SUB Barpick(hmenuopen, ans1$, movbar, done, startpos, curntpos)
  IF hmenuopen AND (ans1$ = CHR$(75) OR ans1$ = CHR$(77)) THEN
    SELECT CASE ans1$
    CASE CHR$(75) : movbar = -1
    CASE CHR$(77) : movbar = 1
    END SELECT
    done = -1
    startpos = curntpos
    curntpos = 0
  END IF
END SUB
a = -1
b$ = CHR$(75)
c = 0
d = 0
e = 0
f = 3
CALL Barpick(a, b$, c, d, e, f)
PRINT c; d; e; f
END
