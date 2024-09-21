DEBUG = False
DEBUGinst = True
DEBUGresult = True
DEBUGcall = True
DEBUGerror = False
DEBUGstack = True
DEBUGrust = True
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
        print("hey call")
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

