## Powershell For Penetration Testers Exam Task 3 - Enumerate directories inside "C:\Windows\System32" which are writable by non-admin users

function Scan-Directory-Permissions
{ 
<#
.SYNOPSIS
A cmdlet to quickly audit the security permissions of the windows\system32 folder or any other folder.

.DESCRIPTION
This script checks if the user who launches the script can write in the folder passed as an argument, if the script is launched with no argument it will check the windows system32 folder.

.PARAMETER Dir
The directory to check, default is "Windows\System32".

.PARAMETER OnlyWritable
Use this switch to show only the folder where the user can write.

.EXAMPLE
PS C:\> . .\Scan-Dir-Permissions.ps1
PS C:\> Scan-Dir-Permissions -Dir "C:\ProgramData"
PS C:\> Scan-Dir-Permissions
PS C:\> Scan-Dir-Permissions -OnlyWritable

.LINK
https://github.com/ankh2054/windows-pentest/blob/master/Powershell/folderperms.ps1

.NOTES
This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3190
#>  


[CmdletBinding()] Param( 

        [Parameter(Mandatory = $false, ValueFromPipeline=$true)]
		[Alias("d", "directory")]
		[String]
		$dir = 'C:\Windows\System32\',
        
        [Parameter(Mandatory = $false)]
        [Switch]
        $OnlyWritable
		

)



$filetocopy  = "test.txt"
New-Item $filetocopy -type file | Out-Null
Write-Host "Copying and removing test file to path folders where access is granted"
$folders = Get-ChildItem $dir -Directory

foreach ($folder in $folders) {

    Copy-Item $filetocopy -Destination $folder.fullname -errorAction SilentlyContinue -errorVariable errors
    if ($errors.count -le 0)
    {
        Write-Host -foregroundColor Green "Access granted:" $folder
        $filetoremove = $folder.fullname + "\" + $filetocopy
        Remove-Item $filetoremove
    }
    else
    {
        if (-Not $OnlyWritable){
            Write-Host -foregroundColor Red "Access denied :" $folder
        }
    }
 }

Remove-Item $filetocopy 
}