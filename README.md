# SSH PuTTY login bruteforcer

This repository contains a wrapper script **ssh-putty-brute.ps1**. This script uses PuTTY clients (either putty.exe or plink.exe) to perform SSH login bruteforce attacks.

See the main article here: https://www.infosecmatter.com/ssh-login-bruteforcer-using-putty-plink/

## Usage and examples

The tool requires either **putty.exe** or **plink.exe** executables in the PATH or in the current working directory.

```
import .\ssh-putty-brute.ps1

# Usage:
ssh-putty-brute [-h ip|ips.txt] [-p port] [-u user|users.txt] [-pw pass|pwdlist.txt]

# Examples:
ssh-putty-brute -h 10.10.5.11 -p 22 -u root -pw P@ssw0rd
ssh-putty-brute -h 10.10.5.11 -p 22 -u root -pw (Get-Content .\pwdlist.txt)
```

## Screenshots

SSH login attack against a single target:

![ssh-putty-bruteforce-login-attack-0](https://user-images.githubusercontent.com/60963123/80275175-93e8c500-86f0-11ea-9838-346e68f404b5.png)

SSH password spraying accross the network:

![ssh-putty-bruteforce-login-attack-password-spraying](https://user-images.githubusercontent.com/60963123/80275055-e8d80b80-86ef-11ea-9ada-1fc84ce58f71.png)

Hunting for default SSH credentials:

![ssh-putty-bruteforce-login-attack-full](https://user-images.githubusercontent.com/60963123/80275192-af53d000-86f0-11ea-80bb-e52cdd490753.png)

For more information, visit: https://www.infosecmatter.com/ssh-login-bruteforcer-using-putty-plink/
