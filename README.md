# AWSCognitoKiller
AWS Cognito Misconiguration Automation Check

## Currently Supported:
### Automated Check Unauthenticated Misconfigurations:
- Sign Up Permission Via Client Id - Authentication bypass due to
enabled Signup API action
- Generate AWS credentials from Identity ID - Unauthorized access to AWS
services due to Liberal AWS Credentials
- Enumerate IAM from Generated AWS credentials

#### TODO:
##### Post-Authen Misconfigurations:
- Privilege escalation
through writable user attributes
- Updating email attribute
before verification

#### References:
- https://www.yassineaboukir.com/talks/NahamConEU2022.pdf
