10 DIM a$(10), b$(10)
20 a$(1) = "X"
30 b$(1) = "Y"
40 CALL Showfile
50 PRINT a$(1); b$(1)
60 END
70 SUB Showfile
80 DIM recarr$(50)
90 recarr$(1) = "HI"
100 PRINT recarr$(1)
110 END SUB
