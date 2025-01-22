class JmpContext:
    def __init__(self, returnPCIndex, index, stack, rspbegin, rsp) -> None:
        self.returnPCIndex = returnPCIndex
        self.index = index
        self.stack = stack
        self.rspbegin = rspbegin
        self.rsp = rsp
    def GetReturnPC(self):
        return self.returnPCIndex
    def GetAddress(self):
        return self.index