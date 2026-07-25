10 SUB SUB1(A$, B%, C%)
  SELECT CASE A$
  CASE "a"
    DECR B%
    IF B% >= 1 THEN 16
    B% = C%
16 DO WHILE MID$(A$,B%,1) = "0"
    DECR B%
    LOOP
  CASE ELSE
    B% = 0
  END SELECT
END SUB
20 D$ = "a"
30 E% = 2
40 F% = 3
50 CALL SUB1(D$,E%,F%)
60 END
