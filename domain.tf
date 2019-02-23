provider "aws" {
  shared_credentials_file = "AWScreds"
  region     = "us-west-2"
}

### Network Resources
# A VPC to allow the domain members to communicate amongst themselves.
resource "aws_vpc" "wbc_vpc" {
  cidr_block = "10.1.0.0/24"
}
# Subnet required for VPC
resource "aws_subnet" "wbc_subnet" {
  vpc_id = "${aws_vpc.wbc_vpc.id}"
  cidr_block = "10.1.0.0/24"
}
# Internet Gateway required to allow members of the VPC to get to the Internet
resource "aws_internet_gateway" "wbc_gw" {
  vpc_id = "${aws_vpc.wbc_vpc.id}"
}
# Route to send VPC member's Internet traffic through the gateway
resource "aws_route" "wbc_inet_route" {
  route_table_id = "${aws_vpc.wbc_vpc.main_route_table_id}"
  destination_cidr_block = "0.0.0.0/0"
  gateway_id = "${aws_internet_gateway.wbc_gw.id}"
}
# Security Group to allow Internet traffic ONLY from our IP
resource "aws_security_group" "wbc_sg"{
  name = "allow_all_from_me"
  description = "allow all traffic from a single IP"
  vpc_id = "${aws_vpc.wbc_vpc.id}"
  ingress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    # Allow inbound traffic from your IP here
    cidr_blocks = ["71.237.118.185/32"]
  }
  # Ingress from anywhere on the internal subnet
  ingress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["10.1.0.0/24"]
  }
  # Egress anywhere!
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Couldn't figure out how to get the AWS generated Admin pass in time for domain script
# since self references were forbidden.  So we'll create some new ones.
# Don't follow this pattern for production servers.  It leaves password unencrypted in the state file.
resource "random_string" "pdc_admin_pass" {
  length = 10
}

resource "random_string" "mem1_admin_pass" {
  length = 10
}

resource "random_string" "mem2_admin_pass" {
  length = 10
}

#### Servers
# Define the Primary Domain Controller
resource "aws_instance" "pdc" {
  # Base Win2012R2 Image as of Jan 2019
  ami           = "ami-004d6bbd25fdba500"
  instance_type = "t2.micro"
  subnet_id= "${aws_subnet.wbc_subnet.id}"
  private_ip = "10.1.0.10"
  associate_public_ip_address = true
  vpc_security_group_ids = ["${aws_security_group.wbc_sg.id}"]
  key_name="wbcloud"
  #get_password_data = true
  # This script will be executed once the instance is available
  # In this case, configure the system as a domain controller
  # Since this can't be done without a reboot in the middle
  # Set up a scheduled task to complete the configuration
  user_data = <<-EOF
    <powershell>
    #echo "User Data Started" | Out-File -filepath C:\Users\Administrator\log.txt
    # Install Active Directory Powershell Tools
    Add-windowsfeature AD-Domain-Services -IncludeManagementTools
    # Create User Creation Script (Step 2)
echo @'
  New-ADUser -SamAccountName DomAdmin -Name "Domain Admin 2" -UserPrincipalName domadmin@wb.local -AccountPassword (ConvertTo-SecureString -asplaintext "DAPassword1!" -force) -Enabled $true -PasswordNeverExpires $true -Path "CN=Users,DC=wb,DC=local"
  New-ADUser -SamAccountName HealthCheck -Name "Automated Health Check" -UserPrincipalName healthy@wb.local -AccountPassword (ConvertTo-SecureString -asplaintext "Health4TW!" -force) -Enabled $true -PasswordNeverExpires $true -Path "CN=Users,DC=wb,DC=local"
  Add-ADGroupMember -Identity "Domain Admins" -Members DomAdmin,HealthCheck
  New-ADUser -SamAccountName User1 -Name "User One" -UserPrincipalName user1@wb.local -AccountPassword (ConvertTo-SecureString -asplaintext "Password1!" -force) -Enabled $true -Path "CN=Users,DC=wb,DC=local"
  New-ADUser -SamAccountName User2 -Name "User Two" -UserPrincipalName user2@wb.local -AccountPassword (ConvertTo-SecureString -asplaintext "Password2!" -force) -Enabled $true -Path "CN=Users,DC=wb,DC=local"
  New-ADUser -SamAccountName User3 -Name "User Three" -UserPrincipalName user3@wb.local -AccountPassword (ConvertTo-SecureString -asplaintext "Password3!" -force) -Enabled $true -Path "CN=Users,DC=wb,DC=local"
  Add-ADGroupMember -Identity "Remote Desktop Users" -Members DomAdmin, User1, User2, User3
  Rename-Computer -NewName "PDC"
  # Delete the scheduled task and undo auto-login
  Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon" -Name AutoAdminLogon -Force | Out-Null
  Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon" -Name DefaultUserName -Force | Out-Null
  Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon"  -Name DefaultPassword -Force | Out-Null
  SCHTASKS.EXE /DELETE /F /TN "Step2"
  del C:\Users\Administrator\addusers.ps1
  echo "Calling Reboot 2" | Out-File -filepath C:\Users\Administrator\log.txt -append
  Restart-Computer -Force
'@ | Out-File -filepath C:\Users\Administrator\addusers.ps1

    # Set the admin pass to our random string
    $user = [adsi]"WinNT://localhost/Administrator,user"
    $user.SetPassword("${random_string.pdc_admin_pass.result}")
    $user.SetInfo()

    # Set the system to automatically log in and create a schedule task for step 2
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon" -Name AutoAdminLogon -PropertyType DWORD -Value 1 -Force | Out-Null
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon" -Name DefaultUserName -PropertyType String -Value Administrator -Force | Out-Null
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon"  -Name DefaultPassword -PropertyType String -Value "${random_string.pdc_admin_pass.result}" -Force | Out-Null
    SCHTASKS.EXE /CREATE /F /SC ONLOGON /DELAY 0001:00 /TN "Step2" /RL HIGHEST /TR "Powershell.exe -ExecutionPolicy Bypass -File C:\Users\Administrator\addusers.ps1"

    # Actually do the domain promotion.  This will cause a reboot automatically
    install-addsforest -domainname wb.local -DomainNetBIOSName "WB" -Force -safemodeadministratorpassword (convertto-securestring "SafePass1!" -asplaintext -force)
    </powershell>
    EOF
}

# A dummy resource that gives the PDC time to get set up
# Add a dependency on this resource to Windows domain members
resource "null_resource" "pdc_reboot_time" {
  provisioner "local-exec" {
    # For UNIX based hosts
    #command = "sleep 60"
    # For Windows based hosts
    # Don't know why this complains about output redirection
    #command = "timeout 60"
    command = "echo 'Waiting seven minutes for PDC to initialize'"
    command = "ping -n 420 127.0.0.1 > nul"
  }
  # Start counting after PDC thinks it's available
  depends_on = ["aws_instance.pdc"]
}

# Define Domain Member 1 (Win2008 Server)
resource "aws_instance" "member1" {
  #Don't start this till the PDC has had time to come up after reboot
  depends_on = ["null_resource.pdc_reboot_time"]
  # Old Win2008R2
  ami           = "ami-fde6cccd"
  instance_type = "t2.micro"
  subnet_id= "${aws_subnet.wbc_subnet.id}"
  private_ip = "10.1.0.15"
  associate_public_ip_address = true
  vpc_security_group_ids = ["${aws_security_group.wbc_sg.id}"]
  key_name="wbcloud"
  #get_password_data = true
  user_data = <<-EOF
    <powershell>
    # Create Join Domain Script (Step 2)
echo @'
  # Delete the scheduled task and undo auto-login
  Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon" -Name AutoAdminLogon -Force | Out-Null
  Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon" -Name DefaultUserName -Force | Out-Null
  Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon"  -Name DefaultPassword -Force | Out-Null
  SCHTASKS.EXE /DELETE /F /TN "Step2"
  del C:\Step2.ps1
  netdom JOIN $env:computername /Domain:wb.local /UserD:WB\domadmin /PasswordD:DAPassword1! /reboot > C:\result.txt
'@ | Out-File -filepath C:\Step2.ps1
    # Simplify the file path above because 2003 doesn't have a Users directory

    # Set the admin pass to our random string
    $user = [adsi]"WinNT://localhost/Administrator,user"
    $user.SetPassword("${random_string.mem1_admin_pass.result}")
    $user.SetInfo()

    # Set the system to automatically log in and create a schedule task for step 2
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon" -Name AutoAdminLogon -PropertyType DWORD -Value 1 -Force | Out-Null
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon" -Name DefaultUserName -PropertyType String -Value Administrator -Force | Out-Null
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon"  -Name DefaultPassword -PropertyType String -Value "${random_string.mem1_admin_pass.result}" -Force | Out-Null
    # Set up a scheduled task to complete the configuration
    SCHTASKS.EXE /CREATE /F /SC ONLOGON /DELAY 0001:00 /TN "Step2" /RL HIGHEST /TR "Powershell.exe -ExecutionPolicy Bypass -File C:\Step2.ps1"

    # Point the DNS to the PDC or domain join won't work
    # Powershell 3 version
    #Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("10.1.0.10")
    # Win2008 version
    netsh interface ip set dns "Local Area Connection" static 10.1.0.10
    # Rename the computer
    Rename-Computer -NewName Server1
    # Reboot to take effect
    Restart-Computer -Force
    </powershell>
    EOF
}

# Define Domain Member 2 (Win2008 Server)
resource "aws_instance" "member2" {
  #Don't start this till the PDC has had time to come up after reboot
  depends_on = ["null_resource.pdc_reboot_time"]
  #ami           = "ami-fde6cccd"    #Vulnerable to eternal blue
  ami           = "ami-004d6bbd25fdba500"  #Not vulnerable to eternal blue
  instance_type = "t2.micro"
  subnet_id= "${aws_subnet.wbc_subnet.id}"
  private_ip = "10.1.0.16"
  associate_public_ip_address = true
  vpc_security_group_ids = ["${aws_security_group.wbc_sg.id}"]
  key_name= "wbcloud"
  user_data = <<-EOF
    <powershell>
    # Create Join Domain Script (Step 2)
echo @'
  # Delete the scheduled task and undo auto-login
  Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon" -Name AutoAdminLogon -Force | Out-Null
  Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon" -Name DefaultUserName -Force | Out-Null
  Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon"  -Name DefaultPassword -Force | Out-Null
  SCHTASKS.EXE /DELETE /F /TN "Step2"
  del C:\Step2.ps1
  netdom JOIN $env:computername /Domain:wb.local /UserD:WB\domadmin /PasswordD:DAPassword1! /reboot > C:\result.txt
'@ | Out-File -filepath C:\Step2.ps1

    # Set the admin pass to our random string
    $user = [adsi]"WinNT://localhost/Administrator,user"
    $user.SetPassword("${random_string.mem2_admin_pass.result}")
    $user.SetInfo()

    # Set the system to automatically log in and create a schedule task for step 2
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon" -Name AutoAdminLogon -PropertyType DWORD -Value 1 -Force | Out-Null
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon" -Name DefaultUserName -PropertyType String -Value Administrator -Force | Out-Null
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon"  -Name DefaultPassword -PropertyType String -Value "${random_string.mem2_admin_pass.result}" -Force | Out-Null
    # Set up a scheduled task to complete the configuration
    SCHTASKS.EXE /CREATE /F /SC ONLOGON /DELAY 0001:00 /TN "Step2" /RL HIGHEST /TR "Powershell.exe -ExecutionPolicy Bypass -File C:\Step2.ps1"

    # Point the DNS to the PDC or domain join won't work
    # Powershell 3 version
    #Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("10.1.0.10")
    # Win2008 version
    netsh interface ip set dns "Local Area Connection" static 10.1.0.10
    # Rename the computer
    Rename-Computer -NewName Server2
    # Reboot to take effect
    Restart-Computer -Force
    </powershell>
    EOF
}

# Define an attack box
resource "aws_instance" "kali" {
  ami           = "ami-0f95cde6ebe3f5ec3"
  instance_type = "t2.micro"
  subnet_id= "${aws_subnet.wbc_subnet.id}"
  private_ip = "10.1.0.200"
  associate_public_ip_address = true
  vpc_security_group_ids = ["${aws_security_group.wbc_sg.id}"]
  key_name="wbcloud"

  # Tell terraform how to connect for the provisioning
  connection {
      type     = "ssh"
      user     = "ec2-user"
      private_key = "${file("wbcloud.pem")}"
  }

  # The masquerade script allows external connections to be passed
  # to the internal network
  provisioner "file" {
      source      = "OpenVPN/masq.sh"
      destination = "/home/ec2-user/masq.sh"
  }

  provisioner "file" {
    source      = "OpenVPN/server.conf"
    destination = "/home/ec2-user/server.conf"
  }

  # Modify the openvpn config file to start our config on boot
  # And then restart the service to start the VPN now
  provisioner "remote-exec" {
    inline = [
      "sudo sed -i 's/#AUTOSTART=\"all\"/AUTOSTART=\"all\"/' /etc/default/openvpn",
      "sudo mv /home/ec2-user/server.conf /etc/openvpn/server.conf",
      "sudo mv /home/ec2-user/masq.sh /etc/openvpn/masq.sh",
      "sudo chmod 760 /etc/openvpn/masq.sh",
      "sudo sed -i 's/ExecStart=\\/bin\\/true/ExecStart=\\/etc\\/openvpn\\/masq.sh/' /lib/systemd/system/openvpn.service",
      "sudo systemctl daemon-reload",
      "sudo systemctl start openvpn"
    ]
  }
}

## Output results
output "PDC Info" {
  value = "\n${aws_instance.pdc.public_ip}\n${random_string.pdc_admin_pass.result}\n"
}

output "Member 1 Info" {
  value = "\n${aws_instance.member1.public_ip}\n${random_string.mem1_admin_pass.result}\n"
}

output "Member 2 Info" {
  value = "\n${aws_instance.member2.public_ip}\n${random_string.mem2_admin_pass.result}\n"
}

output "Kali Info" {
  value = "\n${aws_instance.kali.public_ip}\n"
}
