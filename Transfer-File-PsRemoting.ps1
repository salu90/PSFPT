## Powershell For Penetration Testers Exam Task 6 - Transfer files over PowerShell Remoting
function Transfer-File-PsRemoting
{

<#

.SYNOPSIS
PowerShell cmdlet to trasfer a file with PowerShell Remoting

.DESCRIPTION
PowerShell cmdlet to trasfer a file with PowerShell Remoting

.PARAMETER LocalFile
The localfile to transfer. -l for short

.PARAMETER Target
The remote computer to send the file. -t for short

.PARAMETER remoteFile
The filepath where to copy the file on the remote machine. -r for short

.PARAMETER User
The user for the PowerShell Remote authentication. -u for short

.EXAMPLE
PS C:\> . .\Transfer-File-PsRemoting.ps1
PS C:\> Transfer-File-PsRemoting  -l C:\test.txt -t WIN-PEUQLRSAE1C -r C:\testRemote.txt -u win-peuqlrsae1c\administrator

.LINK
https://stackoverflow.com/questions/10635238/send-files-over-pssession
https://blogs.msdn.microsoft.com/luisdem/2016/08/31/powershell-how-to-copy-a-local-file-to-remote-machines/

.NOTES
This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3190


#>


[CmdletBinding()] Param( 

		[Parameter(Mandatory = $true)]
		[Alias("l")]
		[String]
		$LocalFile,
		
		[Parameter(Mandatory = $true)]
		[Alias("t")]
		[String]
		$Target,
		
		[Parameter(Mandatory = $true)]
		[Alias("r")]
		[String]
		$RemoteFile,
		
		[Parameter(Mandatory = $true)]
		[Alias("u")]
		[String]
		$User
)


$Server01 = New-PSSession -ComputerName WIN-PEUQLRSAE1C -Credential win-peuqlrsae1c\administrator
$remote= $remoteFile
$content=Get-Content $LocalFile

invoke-command -session $Server01 -script {param($RemoteFile,$contents) `
     set-content -path $RemoteFile -value $contents} -argumentlist $remote,$content
}