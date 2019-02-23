# WobbleBoxen Cloud Domain Instructions

## Pre-Requisites
* Download and Install Terraform
This is a single executable so there's no "install", just uncompress the file and put it in your path.  Download from: https://learn.hashicorp.com/terraform/getting-started/install.html

* Create an AWS account
All of these images can run under the free tier.  If you're past the year into period, each image will cost you 1.6 cents an hour (so less than a dime per hour for the whole environment).

## Clone this repo
Clone this repo into some place that will be convenient to work from the command line from.

## AWS Prep
* Create an AWS User (sub-user)
  * Aws Console -> IAM->Users->Add User
  * Enter User Name, Programatic Access, Next: Permissions
  * Create Group, Group Name=wbcdomain, Add policies, Create Group "AmazonEC2FullAccess" and "Network Administrator"
    * If you start typing part of those names in the "Filter policies" field, it will only show policies that match.
    * You can check the policy, type a different fiter, and the original policy will stay checked even though it's not being displayed any more.
  * The new group will automatically be checked, click Next: Tags
  * Tags aren't used in the setup, Next: Review
  * Create user
  * Download or copy the access keys into the repo directory (the gitignore is set up to help ensure you don't accidentally commit them).  Name them WBCDomain\\AWSCreds  The file format is:
      [default]
      aws_access_key_id=BLAH
      aws_secret_access_key=BLAH
* Create a Key Pair:
  * Console->EC2->Key Pairs
  * Switch to the Oregon region using the menu in the top right of the console.
  * Create Key Pair
  * Name it wbcloud
  * Download the wbcloud.pem file into the repo directory (again, the gitignore is set up not to commit this file)
  * Don't forget to change the permissions to user read/write only (
    * UNIX hosts: `chmod 600 wbcloud.pem`
    * Windows hosts: Properties->Security->Advanced.  Change the owner to you, disable inheritance and delete all permissions. Then grant yourself "Full control" and save the permissions.

## OpenVPN
If you want to run tools directly from your PC (rather than from the Kali box in the environment), you'll need to install OpenVPN.  If you only want to attack from the included Kali box, you don't need this.
  * Download openvpn (or install via package manager) https://openvpn.net/community-downloads/
  * After environment boots, replace the "REMOTE" line in client.ovpn with the IP address of the KALI box

## Prep the Terraform file
There is a firewall rule to restrict access to the environment to a specific IP.  Find the line "Allow inbound traffic from your IP here" and enter your IP (type "what is my ip" in Google if you are unsure) in the line below.  If desired, you can copy the "ingress" block multiple times to authorize multiple IPs.  Save the file.

## Build your environment
* From the project directory run
```
  terraform init
  terraform apply
```
* Wait ~15 minutes.  The Kali box will be up sooner, but the windows machines really take this long to set up and reboot a couple times.

## Environment Contents
Currently the environment consists of the following machines.  Use the public IPs as needed to observe results and modify configurations (and connect for attacks in the case of the Kali image).  Windows machines have RDP open, Kali has ssh.  The Local Administrator password is displayed as output from the terraform apply command.  Kali uses the private key (ssh -i wbcloud.pem [kali ip].  Use internal IPs for all simulated attacks.
  * Primary Domain Controller - Windows 2012r2 from 2019 - 10.1.0.10
  * Domain Member 1 - Windows 2008r2 from 2014 - 10.1.0.15
  * Domain Member 2 - Windows 2008r2 from 2019 - 10.1.0.16
  * Attack Platform - Kali 2018.3 - 10.1.0.200

## Domain Credentials
Obviously the goal is to reveal these passwords using various techniques, but you may need to seed them in various fashions so that the tools can find them.
  * Domain Administrator  
    * DomAdmin:DAPassword1!
  * Theoretical Service User (naturally also a domain admin)   
    * HealthCheck:Health4TW!
  * Unprivileged Users (with Remote Desktop Privileges)
    * User 1  User1:Password1!
    * User 2  User2:Password2!
    * User 3  User3:Password3!

## Practice!
  * This environment is not a puzzle to be solved (future versions might be).  Spoiler, Member 1 is vulnerable to EternalBlue.  Start there and then practice your lateral movement.  You will probably have to fake events like an admin logging in to the system or running a service under a domain account.
  * Try running mimikatz on the systems to see when credentials will be cached.
    * After logging in via Remote Desktop?
    * After remotely executing commands?
    * After running a service with domain credentials?
  * Try your favorite domain exploitation tools (Powershell Empire, CrackMapExec, etc.)
  * Practice setting up port forwards to tunnel traffic in for various tools.

## Destroy your environment
When you are done with your environment, destroy the resources so you don't get charged.
```
    terraform destroy
```

## Common Errors
### Unable to locate valid AWS credential file
* Most often this is a problem with case.  Make sure your AWSCreds file is capitalized this way and that it is in the same directory as the domain.tf file.
* If the file is named correctly, check the case inside the file.  Everything should be lowercase except the values of the keys themselves.

### Unable to create resources in zone
Sometimes a particular availability zone rejects new ec2 instances.  If this is happening, either wait 10 minutes, or modify the line like the one below in the domain.tf file from the "aws_subnet" resource.  Change 2c to 2a, 2b, or 2d.
```
availability_zone = "us-west-2c"
```

### Error in null_resource
Make sure that you've got the correct command for your host OS uncommented in the "null_resource" declaration within the domain.tf file.  Try running the command from a prompt to make sure it works on your system.  If not, change it to anything that will take 420 or so seconds to complete.
