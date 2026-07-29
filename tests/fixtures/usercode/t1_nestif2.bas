10 A$ = "X"
20 B$ = "Y"
30 IF A$ <> "Q" THEN
  IF B$ <> "R" THEN
    PRINT "A"
33 PRINT "B"
  END IF
END IF
40 IF A$ = "X" THEN 60
50 END
60 A$ = "Q"
70 GOTO 33
