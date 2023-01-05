# AWSCognitoKiller
AWS Cognito Misconiguration Automation Check

## Requirements:
- Install AWS CLI

## Currently Supported:
### Automated Check Pre-Authen Misconfigurations:
- Sign Up Via Client Id - Authentication bypass due to
enabled Signup API action
- Generate AWS credentials from Identity ID - Unauthorized access to AWS
services due to Liberal AWS Credentials
- Enumerate IAM from Generated AWS credentials
- Sign Up Via Client Id + Client Secret When Application Allows SignUp but Need Proper Secret Hash

#### TODO:
##### Post-Authen Misconfigurations:
- Privilege escalation
through writable user attributes
- Updating email attribute
before verification


#### References:
- https://www.yassineaboukir.com/talks/NahamConEU2022.pdf
