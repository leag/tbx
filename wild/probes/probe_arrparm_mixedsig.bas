10 DIM A$(3)
20 A$(1) = "HI"
30 CALL One(A$(), 1)
40 END
50 SUB One(X$(1), N%)
60 CALL Two(LEN(X$(N%)), X$(N%))
70 END SUB
80 SUB Two(L%, T$)
90 PRINT L%; T$
100 END SUB
