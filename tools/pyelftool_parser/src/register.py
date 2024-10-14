from debug import log, logstack
class register:
    def __init__(self, stacksizeinit):
        self.reg = dict()
        self.stacksizeinit = stacksizeinit
        self.reg["pc"] = 0
        self.reg["rbp"] = 0
        self.reg["rspbegin"] = stacksizeinit
        self.reg["rsp"] = stacksizeinit
        self.reg["enter"] = 0
        self.reg["stack"] = 0
        self.reg["max"] = 0
        self.reg["rip"] = 0
        self.reg["call_or_jmp"] = 0 ## spectial reg for fucntion pointer.
    def clean(self):
        self.reg["rbp"] = 0
        self.reg["enter"] = 0
    def cleanstack(self):
        self.reg["stack"] = 0
    def alignrsp(self):
        self.reg["rspbegin"] = self.stacksizeinit
        self.reg["rsp"] = self.stacksizeinit
    def updaterip(self, key):
        if key != -1:
            self.reg["rip"] = key
    def updatesmaxstackreg(self):
        self.reg["stack"] =  min(self.reg["stack"], self.reg["rsp"] - self.reg["rspbegin"])  ## catch the maximum stack, but I use min because stack is negative.
        if self.reg["max"] > self.reg["stack"]:
            self.reg["max"] = self.reg["stack"]
        logstack("The stack frame = " + str(self.reg["rspbegin"]))
        logstack("The rsp now is = "+ str(self.reg["rsp"]))
        logstack(self.reg["stack"])