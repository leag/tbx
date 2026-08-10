INPUT A$
SELECT CASE A$
  CASE "a"
    INPUT B$
    SELECT CASE B$
      CASE "x"
        PRINT 1
      CASE "y"
        PRINT 2
    END SELECT
  CASE "b"
    PRINT 3
END SELECT
END
