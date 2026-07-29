10 DIM A$(3)
20 A$(1) = "HI"
30 CALL One(A$(), 1, 2, 3)
40 END
50 SUB One(X$(1), A%, B%, C%)
60 PRINT X$(A%); B%; C%
70 END SUB
