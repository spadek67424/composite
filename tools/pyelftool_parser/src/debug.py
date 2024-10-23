DEBUG = False
DEBUGinst = True
DEBUGcall = False
DEBUGerror = False
DEBUGstack = True
DEBUGresult = True
DEBUGrust = True
DEBUGterminator = True
def log(*argv):
    if DEBUG:
        print(argv)
def loginst(*argv):
    if DEBUGinst:
        print(argv)
def logresult(*argv):
    if DEBUGresult:
        print(argv)
def logcall(*argv):
    if DEBUGcall:
        print(argv)
def logerror(*argv):
    if DEBUGerror:
        print(argv)
def logstack(*argv):
    if DEBUGstack:
        print(argv)
def logrust(argv):
    if DEBUGrust:
        print(argv)
def logterminator(argv):
    if DEBUGterminator:
        print(argv)

