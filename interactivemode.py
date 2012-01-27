def exit():
	import os, signal
	os.kill(os.getpid(), signal.SIGTERM)

def _RunCLI():
	import code, sys, threading
	try:
		raise None
	except:
		namespace = sys.exc_info()[2].tb_frame.f_back.f_back.f_globals
	
	namespace['exit'] = exit
	
	def CLI():
		while True:
			code.interact(local=namespace, banner='')
			print("Not exiting implicitly. Use exit() if you really want to.")
			dt = ndt = 0
			for thread in threading.enumerate():
				if thread.daemon:
					dt += 1
				else:
					ndt += 1
			print("(%d threads: %d primary, %d daemon)" % (dt + ndt, ndt, dt))
	threading.Timer(0, CLI).start()

_RunCLI()
