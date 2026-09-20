terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "my_ip" {
  description = "Your public IP in CIDR form, e.g. 203.0.113.4/32. Nothing else can reach these hosts."
  type        = string
}

variable "key_name" {
  description = "Existing EC2 key pair for SSH to RHEL. ED25519 is fine here."
  type        = string
}

# Windows AMIs reject ED25519 key pairs outright, and the admin password is
# RSA-encrypted, so this host needs its own RSA pair rather than sharing one.
variable "windows_key_name" {
  description = "Existing RSA EC2 key pair, used to decrypt the Windows admin password."
  type        = string
}

variable "instance_type" {
  type    = string
  default = "t3.medium"
}

# looked up dynamically, hardcoded AMI IDs go stale
data "aws_ami" "windows_2022" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }
}

data "aws_ami" "rhel9" {
  most_recent = true
  owners      = ["309956199498"] # Red Hat

  filter {
    name   = "name"
    values = ["RHEL-9.*_HVM-*-x86_64-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

resource "aws_security_group" "lab" {
  name        = "hardening-lab"
  description = "Hardening lab access, restricted to a single operator IP"

  ingress {
    description = "RDP from operator only"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  ingress {
    description = "SSH from operator only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  ingress {
    description = "WinRM over HTTPS from operator only"
    from_port   = 5986
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  # 5985 (WinRM cleartext) is deliberately absent

  egress {
    description = "outbound for patching and package installs"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "hardening-lab" }
}

resource "aws_instance" "windows" {
  ami                    = data.aws_ami.windows_2022.id
  instance_type          = var.instance_type
  key_name               = var.windows_key_name
  vpc_security_group_ids = [aws_security_group.lab.id]

  # Brings up the encrypted WinRM listener at first boot so the host can be
  # bootstrapped remotely instead of through an interactive RDP session. It
  # configures transport only, the least-privilege service account is still
  # created by scripts/bootstrap_windows.ps1, run afterwards over this channel.
  user_data = <<-EOF
    <powershell>
    $ErrorActionPreference = "Stop"
    $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
    New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * `
        -CertificateThumbPrint $cert.Thumbprint -Force
    # cleartext management traffic is never enabled, not even briefly
    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false
    New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound `
        -LocalPort 5986 -Protocol TCP -Action Allow
    cmd.exe /c 'winrm delete winrm/config/Listener?Address=*+Transport=HTTP' 2>$null
    </powershell>
  EOF

  metadata_options {
    http_tokens = "required" # IMDSv2 only
  }

  root_block_device {
    encrypted = true
  }

  tags = { Name = "hardening-lab-windows" }
}

resource "aws_instance" "linux" {
  ami                    = data.aws_ami.rhel9.id
  instance_type          = var.instance_type
  key_name               = var.key_name
  vpc_security_group_ids = [aws_security_group.lab.id]

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = { Name = "hardening-lab-rhel9" }
}

output "windows_public_ip" {
  value = aws_instance.windows.public_ip
}

output "linux_public_ip" {
  value = aws_instance.linux.public_ip
}
