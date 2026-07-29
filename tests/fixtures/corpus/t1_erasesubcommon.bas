10 DIM wrow(30), wcol(30)
20 COMMON wrow(1), wcol(1), idx
30 idx = 1
40 CALL Showfile
50 END
60 SUB Showfile
70 SHARED idx
80 DIM recarr$(50)
90 recarr$(1) = "HI"
100 rec = 1
110 CALL Uselist(recarr$(),rec)
120 PRINT recarr$(rec); idx
130 ERASE recarr$
140 END SUB
150 SUB Uselist(p$(1),n)
160 PRINT p$(n); n
170 END SUB
