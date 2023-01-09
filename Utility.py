from string import ascii_letters
from random import choice, randint
import datetime

class Utility:

	@staticmethod
	def random_string(length=10):
		return ''.join([choice(ascii_letters) for _ in range(length)])

	@staticmethod
	def random_email(h1_email, length=4):
		return h1_email.split("@")[0] + "+" + Utility.random_string(length) + "@" + h1_email.split("@")[1]

	@staticmethod
	def random_username(username, length=4):
		return username + Utility.random_string(length) 

	@staticmethod
	def is_tool(name):
		"""Check whether `name` is on PATH and marked as executable."""

		# from whichcraft import which
		from shutil import which

		return which(name) is not None




class LogProcess:
	
	@staticmethod
	def logProc(message, fileName="Log/logProc.log"):
		if fileName:
			try:
				with open(fileName, "a") as f:
					f.write(message)
					f.write("\n")
				return
			except:
				pass
		print(f"{message}")

	@staticmethod
	def logNucleiFormat(serverity, appId, target, method="SendBird", typeError="APK", isPrint=True):
		nucleiFormat = "[{detected_date}] [{typeError}] [{method}] [{serverity}] {target} {options}".format(
				detected_date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), typeError=typeError, target=target, method=method, serverity=serverity, options=appId
			)
		with open("Log/resultNuclei.log", "a") as f:
			f.write(nucleiFormat)
			f.write("\n")	
		if isPrint:
			print(nucleiFormat)
		return nucleiFormat