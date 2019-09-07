def PrintSuccess(Msg):
	print('\033[1;32m[+]\033[1;m ' + Msg)

def PrintStatus(Msg):
	print('\033[1;34m[*]\033[1;m ' + Msg)

def PrintFailure(Msg):
	print('\033[1;31m[-]\033[1;m ' + Msg)

def PrintError(Msg):
	print('\033[1;31m[!]\033[1;m ' + Msg)

def PrintHighSeverity(Msg):
	print('\033[1;33m[!]\033[1;m ' + Msg)
