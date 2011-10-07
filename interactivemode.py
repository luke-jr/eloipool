def _RunCLI():
	import code, sys, threading
	try:
		raise None
	except:
		namespace = sys.exc_info()[2].tb_frame.f_back.f_back.f_globals

	def CLI():
		code.interact(banner=None, local=namespace)
	threading.Timer(0, CLI).start()

_RunCLI()
