## Powershell For Penetration Testers Exam Task 7 - Write a simple web server in PowerShell which could be used to list, delete, download and upload files over HTTP
function Start-Simple-WebServer
{ 
<#
.SYNOPSIS
A simple PowerShell Web Server that could be used to list, delete, download and upload files over HTTP

.DESCRIPTION
A simple PowerShell Web Server that could be used to list, delete, download and upload files over HTTP

.PARAMETER WebRoot
The webroot of the server. Defaults to the current working directory

.PARAMETER url
The url to run the webserver on. Defaults to http://127.0.0.1:80/

.EXAMPLE
PS C:\> . .\Simple-Server.ps1
PS C:\> Start-Simple-WebServer -WebRoot C:\Users\tony\Desktop\Powershell\

.LINK
https://gallery.technet.microsoft.com/scriptcenter/Powershell-Webserver-74dcf466
https://gist.github.com/pmolchanov/0120a26a6ca8d88220a8

.NOTES
This script has been created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/
Student ID: PSP-3190
#>           
    [CmdletBinding()] Param( 

       [Parameter(Mandatory = $false)]
       [String]
       $WebRoot = "",
       
       [Parameter(Mandatory = $false)]
       [String]
       $url = 'http://127.0.0.1:80/'

    )

    if ($WebRoot -eq ""){$WebRoot=pwd}
    


#Webserver code inspired by: https://gist.github.com/pmolchanov/0120a26a6ca8d88220a8

$HttpListener = New-Object System.Net.HttpListener
$HttpListener.Prefixes.Add($url)
$HttpListener.Start()

$Upload = @"
<html><body>
	<form method="POST" enctype="multipart/form-data" action="/upload">
	<p><b>File to upload:</b><input type="file" name="filedata"></p>	<input type="submit" name="button" value="Upload">
	</form>
</body></html>
"@

While ($HttpListener.IsListening) {
    $HttpContext = $HttpListener.GetContext()
    $HttpRequest = $HttpContext.Request
    $RequestUrl = $HttpRequest.Url.OriginalString
    $requestFunction = '{0} {1}' -f $HttpRequest.httpMethod, $HttpRequest.Url.LocalPath
    
    Write-Host $requestFunction
  
    $HttpResponse = $HttpContext.Response
    $ResponseBuffer = ''

    switch ($requestFunction) 
    { 
        "GET /list" {
            $resp = Get-ChildItem $WebRoot
            $HttpResponse.Headers.Add("Content-Type","text/plain")
            $ResponseBuffer = [System.Text.Encoding]::UTF8.GetBytes($resp)
        }

        "GET /delete" {
            $HttpResponse.Headers.Add("Content-Type","text/plain")
            $toDelete = "$webRoot\" + $HttpContext.Request.QueryString[0]
            $check =  Get-ChildItem $toDelete

            if (!$check){
                $resp =  "Error: the requested file doesn't exist"
                $ResponseBuffer = [System.Text.Encoding]::UTF8.GetBytes($resp)
                break
            }

            Remove-Item ($toDelete)
            $resp =  "File deleted"
            $ResponseBuffer = [System.Text.Encoding]::UTF8.GetBytes($resp)
            break
        }
       
        "GET /download" { 
            $downPath = "$webRoot\" + $HttpContext.Request.QueryString[0]

		    $ResponseBuffer = [System.IO.File]::ReadAllBytes($downPath)
		    $HttpResponse.SendChunked = $FALSE
		    $HttpResponse.ContentType = "application/octet-stream"
		    $Filename = $HttpContext.Request.QueryString[0]
		    $HttpResponse.AddHeader("Content-Disposition", "attachment; filename=$Filename")
        }
      

        "GET /upload" {$ResponseBuffer = [System.Text.Encoding]::UTF8.GetBytes($upload)}        "GET /stop" {$HttpResponse.Close()        $HttpListener.Stop()        return}        
           #Upload functionality inspired by: https://gallery.technet.microsoft.com/scriptcenter/Powershell-Webserver-74dcf466
        	"POST /upload"
			{ # upload file
				# only if there is body data in the request				if ($HttpRequest.HasEntityBody)				{					# set default message to error message (since we just stop processing on error)					$ResponseBuffer = "Received corrupt or incomplete form data"					# check content type
					if ($HttpRequest.ContentType)					{						# retrieve boundary marker for header separation						$BOUNDARY = $NULL						if ($HttpRequest.ContentType -match "boundary=(.*);")						{	$BOUNDARY = "--" + $MATCHES[1] }						else						{ # marker might be at the end of the line							if ($HttpRequest.ContentType -match "boundary=(.*)$")							{ $BOUNDARY = "--" + $MATCHES[1] }						}						if ($BOUNDARY)						{ # only if header separator was found							# read complete header (inkl. file data) into string							$READER = New-Object System.IO.StreamReader($HttpRequest.InputStream, $HttpRequest.ContentEncoding)							$DATA = $READER.ReadToEnd()							$READER.Close()							$HttpRequest.InputStream.Close()							# variables for filenames							$FILENAME = ""							$SOURCENAME = ""							# separate headers by boundary string							$DATA -replace "$BOUNDARY--\r\n", "$BOUNDARY`r`n--" -split "$BOUNDARY\r\n" | % {
								# omit leading empty header and end marker header								if (($_ -ne "") -and ($_ -ne "--"))								{									# only if well defined header (seperation between meta data and data)									if ($_.IndexOf("`r`n`r`n") -gt 0)									{										# header data before two CRs is meta data										# first look for the file in header "filedata"										if ($_.Substring(0, $_.IndexOf("`r`n`r`n")) -match "Content-Disposition: form-data; name=(.*);")										{											$HEADERNAME = $MATCHES[1] -replace '\"'											# headername "filedata"?											if ($HEADERNAME -eq "filedata")											{ # yes, look for source filename												if ($_.Substring(0, $_.IndexOf("`r`n`r`n")) -match "filename=(.*)")												{ # source filename found													$SOURCENAME = $MATCHES[1] -replace "`r`n$" -replace "`r$" -replace '\"'													# store content of file in variable													$FILEDATA = $_.Substring($_.IndexOf("`r`n`r`n") + 4) -replace "`r`n$"												}											}										}										else										{ # look for other headers (we need "filepath" to know where to store the file)
											if ($_.Substring(0, $_.IndexOf("`r`n`r`n")) -match "Content-Disposition: form-data; name=(.*)")											{ # header found												$HEADERNAME = $MATCHES[1] -replace '\"'												# headername "filepath"?												if ($HEADERNAME -eq "filepath")												{ # yes, look for target filename													$FILENAME = $_.Substring($_.IndexOf("`r`n`r`n") + 4) -replace "`r`n$" -replace "`r$" -replace '\"'												}											}										}									}								}							}								if ($SOURCENAME -ne "")								{ # only upload if source file exists									# check or construct a valid filename to store									$TARGETNAME = ""                       									try {										# ... save file with the same encoding as received
                          
                                        $TARGETNAME = "$webRoot\" + $SOURCENAME										[IO.File]::WriteAllText($TARGETNAME, $FILEDATA, $HttpRequest.ContentEncoding)
                                    }
									catch	{}
									if ($Error.Count -gt 0)
									{ # retrieve error message on error
										$ResponseBuffer += "`nError saving '$TARGETNAME'`n`n"
										$ResponseBuffer += $Error[0]
										$Error.Clear()
									}
									else
									{ # success
										$ResponseBuffer = "File $SOURCENAME successfully uploaded as $TARGETNAME"
									}
								}
								else
								{
									$ResponseBuffer = "No file data received"
								}
						}
					}
				}
				else
				{
					$ResponseBuffer = "No client data received"
				}                $ResponseBuffer = [System.Text.Encoding]::UTF8.GetBytes($ResponseBuffer)
				break
			}

  default {$HttpResponse.Close()           break}
    }
 
            $HttpResponse.StatusCode = 200
            $HttpResponse.ContentLength64 = $ResponseBuffer.Length
            $HttpResponse.OutputStream.Write($ResponseBuffer,0,$ResponseBuffer.Length)
            $HttpResponse.Close()
}
}