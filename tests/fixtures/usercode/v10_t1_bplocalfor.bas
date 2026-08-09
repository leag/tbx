10 SUB SUB1
  LOCAL A%, B%, C#, D#, E#, F#, G#, H#, I#, J#, K#, L#, M#, N#, O#, P#, Q#, R#, S#, T%, U%
  PRINT C#; D#; E#; F#; G#; H#; I#; J#; K#; L#; M#; N#; O#; P#; Q#; R#; S#
  B% = 60
  U% = 60
  FOR A% = 1 TO 152 STEP 8
  PRINT A%
  NEXT A%
  FOR A% = 1 TO B%
  PRINT A%
  NEXT A%
  FOR T% = 1 TO 60
  PRINT T%
  NEXT T%
  FOR T% = 1 TO 152 STEP 8
  PRINT T%
  NEXT T%
  FOR T% = 1 TO U%
  PRINT T%
  NEXT T%
END SUB
20 CALL SUB1
30 END
