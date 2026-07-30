10 A% = 1
20 B% = 1
30 SUB SUB1
  IF C% = 1 THEN 35
  IF C% = 2 THEN 45
  EXIT SUB
  DO
35 IF D% = 1 THEN
    D% = 5
    GOTO 45
  ELSE
    D% = D% - 1
    EXIT LOOP
  END IF
  LOOP
  DO
  DO
45 IF D% = 5 THEN
    D% = 1
    GOTO 53
  ELSE
    D% = D% + 1
    GOTO 53
  END IF
  LOOP
53 LOOP
END SUB
54 CALL SUB1
64 END
