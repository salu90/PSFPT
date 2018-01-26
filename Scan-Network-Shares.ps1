## Powershell For Penetration Testers Exam Task 2 - Enumerate all open shares on a network
function Scan-Network-Shares
{

<#
.SYNOPSIS
PowerShell cmdlet to scan for open network shares with read, write and fullControl access

.DESCRIPTION
The script, given an IP address, connects to all available network shares and determine if there is anonymous read and write access. By default it will run against localhost.

.PARAMETER IPsList
A file which contains IPs to scan

.PARAMETER Target
Use this parameter to scan a single host

.EXAMPLE
PS C:\> . .\Scan-Network-Shares.ps1
PS C:\> Scan-Network-Shares
PS C:\> Scan-Network-Shares -Target 192.168.0.1
PS C:\> Scan-Network-Shares -IPsList IPs.txt

.LINK
https://gallery.technet.microsoft.com/scriptcenter/List-Share-Permissions-83f8c419
https://superuser.com/questions/769679/powershell-get-list-of-folders-shared
https://trwagner1.wordpress.com/2012/04/17/powershell-and-listing-shares-on-your-network/
https://gallery.technet.microsoft.com/scriptcenter/Powershell-script-to-get-39c73c74

.NOTES
This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3190
#>

	[CmdletBinding()] Param(
		
		#Defaults to local machine
		[Parameter(Mandatory = $false)]
		[String]
		$Target = '127.0.0.1',
				
		[Parameter(Mandatory = $false)]
        [Alias('IPs')]
		[String]
		$IPsList = $null
	)



    function Get-Shares($Target){
	    try{
			# Gets the shares list
			$shares = gwmi -Class win32_share -ComputerName $Target | select -ExpandProperty Name  
            $ACLmodify = @{}
            $ACLfullcontrol = @{}
            $ACLread = @{}
            $ACL = @{}
		}
		catch
		{
			Write-Host "Unable to connect to any shares on $Target"  -ForegroundColor Red  
			return
		}
    
        # the foreach loop has been ispired by --> https://gallery.technet.microsoft.com/scriptcenter/List-Share-Permissions-83f8c419    
        foreach ($share in $shares) { 
        $acl = $null 
        $objShareSec = Get-WMIObject -Class Win32_LogicalShareSecuritySetting -Filter "name='$Share'"  -ComputerName $target
        try { 
            $SD = $objShareSec.GetSecurityDescriptor().Descriptor   
            foreach($ace in $SD.DACL){  
                $UserName = $ace.Trustee.Name     
                If ($ace.Trustee.Domain -ne $Null) {$UserName = "$($ace.Trustee.Domain)\$UserName"}   
                If ($ace.Trustee.Name -eq $Null) {$UserName = $ace.Trustee.SIDString }   
                If ($ace.AccessMask -eq "1245631"){
                    $ACLmodify.Add($share, (New-Object Security.AccessControl.FileSystemAccessRule($UserName, $ace.AccessMask, $ace.AceType) )) 
                }

                elseif ($ace.AccessMask -eq "2032127"){
                    $ACLfullcontrol.Add($share, (New-Object Security.AccessControl.FileSystemAccessRule($UserName, $ace.AccessMask, $ace.AceType))) 
                }

                elseif ($ace.AccessMask -eq "1179817"){
                    $ACLread.Add($share, (New-Object Security.AccessControl.FileSystemAccessRule($UserName, $ace.AccessMask, $ace.AceType) ))
                }

                else{
                    $ACL.Add($share, (New-Object Security.AccessControl.FileSystemAccessRule($UserName, $ace.AccessMask, $ace.AceType) ))     
                }
            }            
        }
        catch {Write-Host "Unable to obtain permissions for $share" -ForegroundColor Red}
        }
        if ($ACLread.count -gt 0){
            Write-Host $('=' * 90)
            Write-Host "Listing network shares with read/execute permissions"
            foreach ($share in $ACLread.GetEnumerator()) {
                Write-Host $share.Name -ForegroundColor Green
                Write-Host $('-' * 20) -ForegroundColor Green
                $share.Value
            }
            Write-Host $('=' * 90)
        }

        if ($ACLmodify.count -gt 0){
            Write-Host "Listing network shares with modify permissions"
            foreach ($share in $ACLmodify.GetEnumerator()) {
                    Write-Host $share.Name -ForegroundColor Green
                    Write-Host $('-' * 20) -ForegroundColor Green
                    $share.Value
            }
            Write-Host $('=' * 90)
        }
        
        if ($ACLfullControl.count -gt 0){
            Write-Host "Listing network shares with full control permissions"
            foreach ($share in $ACLfullcontrol.GetEnumerator()) {
                Write-Host $share.Name -ForegroundColor Green
                Write-Host $('-' * 20) -ForegroundColor Green
                $share.Value
            }
            Write-Host $('=' * 90)
        }
            
        if ($ACL.count -gt 0){
            Write-Host "Listing network shares with other permissions"
            foreach ($share in $ACL.GetEnumerator()) {
                Write-Host $share.Name -ForegroundColor Green
                Write-Host $('-' * 20) -ForegroundColor Green
                $share.Value
            }
        }
    }

    if ($IPsList)
	{
		$IPs = Get-Content $IPsList
		foreach ($IP in $IPs)
		{
			Write-Host "Analyzing $IP shares" -ForegroundColor Green  
			Get-Shares($IP)
		}
	}
	else
	{
		Write-Host "Analyzing $Target" -ForegroundColor Green
		Get-Shares($Target)
	}
}