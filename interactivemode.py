def _RunCLI():
	import code, sys, threading
	try:
		raise None
	except:
		namespace = sys.exc_info()[2].tb_frame.f_back.f_back.f_globals
	
	namespace['sys'] = sys
	c = code.InteractiveConsole(locals=namespace)
	
	def CLI():
		while True:
			c.interact()
			print("Not exiting implicitly. Use sys.exit() if you really want to.")
			dt = ndt = 0
			for thread in threading.enumerate():
				if thread.daemon:
					dt += 1
				else:
					ndt += 1
			print("(%d threads: %d primary, %d daemon)" % (dt + ndt, ndt, dt))
	threading.Timer(0, CLI).start()

_RunCLI()
