## Building

This is a set of build containers for various packages, brought up to date for Trusty.

`make 32`

`make 64`

Reindex packages

`make index`

Push to S3 debian repository (you will need AWS credentials configured first)

`pip install -r requirements.txt`

`aws configure` - Si, Paul, Uzzell, Dan, Ed, Carlos can all grant cred's

`make sync`
