10 ON KEY(1) GOSUB TrapHandler
20 KEY(1) ON
30 GOSUB PlainRoutine
40 PRINT "done"
50 END
60 TrapHandler:
70 PRINT "trapped"
80 RETURN
90 PlainRoutine:
100 PRINT "plain"
110 RETURN
