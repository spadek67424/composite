class JmpContext:
    def __init__(self, returnPCIndex, index) -> None:
        self.returnPCIndex = returnPCIndex
        self.index = index
    def GetReturnPC(self):
        return self.returnPCIndex
    def GetAddress(self):
        return self.index