# awsfund - AWS Fun Daemon

AWS fun daemon - some micro service that you can request to spawn EC2 instances
with a custom username/password.

### Security Notice

Bare in mind, this tool is purely educational. Do not run in production, and
do only run in trusted environments (as it doesn't support authentication).

### HTTP API

```
GET  /ping                    Can be used for basic health checking.
GET  /version                 Responds with the micro service version.
GET  /v1/instances            Lists all EC2 instance in its AWS region
POST /v1/instances/create    Spawns a new EC2 instances with non-empty 
                             query arguments for username and password.
```

### Download and Installation

The easiest way to get it if you've already a working Go development environment:

```
go get github.com/christianparpart/awsfund
awsfund -h
```

Otherwise, I'll provide you with the binary ;-)
Please check the Github releases page.

### Example
Please make sure to use real credentials and security values.

The AMI image chosen is Ubuntu 14.04 LTS and the Region is Germany/Frankfurt.

```!sh
./awsfund \
  --aws-access-key-id="AKIAXXXXXXXXXXXXXXXX" \
  --aws-secret-access-key="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" \
  --aws-key-name="YOUR_KEY_ID" \
  --aws-sg-name="YOUR_SECURITY_GROUP" \
  --aws-image-id="ami-26c43149" \
  --aws-region="eu-central-1"
```

### Licence

```
The MIT License (MIT)
Copyright (c) 2016 Christian Parpart <trapni@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
