SUB Makevmenu(itemcount, curntpos)
  SHARED vmenuopen, hmenuopen, movbar
  LOCAL done, mloop, ans$, ans1$
  done = 0
  vmenuopen = -1
  ans$ = "a"
  ans1$ = "b"
  FOR mloop = 1 TO itemcount
    curntpos = mloop
  NEXT
  PRINT ans$; ans1$; done
END SUB
SUB Makehmenu(itemcount, curntpos)
  SHARED vmenuopen, hmenuopen, movbar
  LOCAL done, mloop, ans$, ans1$
  done = 0
  hmenuopen = -1
  movbar = vmenuopen
  ans$ = "c"
  ans1$ = "d"
  FOR mloop = 1 TO itemcount
    curntpos = mloop
  NEXT
  PRINT ans$; ans1$; done
END SUB
vmenuopen = 0
hmenuopen = 0
movbar = 0
n = 2
g = 0
h = 0
CALL Makevmenu(n, g)
CALL Makehmenu(n, h)
PRINT g; h; vmenuopen; hmenuopen; movbar
END
