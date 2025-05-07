#requires -Version 5.0
<#
.SYNOPSIS
    Analyzes network traffic captures for Kaolin RAT C2 communication patterns.

.DESCRIPTION
    This PowerShell script analyzes PCAP files for network traffic patterns associated with
    the Kaolin RAT malware. It identifies HTTP requests with dictionary-based URL parameters,
    steganography image downloads, and encrypted POST requests characteristic of the malware.

.PARAMETER PcapFile
    Path to the PCAP file to analyze.

.PARAMETER OutputFolder
    Path to the folder where extracted files and analysis results will be saved.

.PARAMETER ExtractFiles
    Switch to enable extraction of files from the PCAP.

.EXAMPLE
    .\analyze_c2_traffic.ps1 -PcapFile "capture.pcap" -OutputFolder "analysis" -ExtractFiles

.NOTES
    Author: Security Researcher
    Date: May 2024
    Requires: PowerShell 5.0 or later, tshark.exe (part of Wireshark)
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$PcapFile,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputFolder = ".\kaolin_analysis",
    
    [Parameter(Mandatory = $false)]
    [switch]$ExtractFiles
)

# Check if tshark is available
function Test-TsharkAvailable {
    try {
        $tsharkVersion = & tshark --version 2>&1
        if ($tsharkVersion -match "TShark") {
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}

# Extract HTTP requests from PCAP
function Get-HttpRequests {
    param (
        [string]$PcapFile
    )
    
    $tsharkOutput = & tshark -r $PcapFile -Y "http.request" -T fields -e frame.number -e ip.src -e ip.dst -e http.host -e http.request.uri -e http.request.method -e http.user_agent -E separator="|"
    
    $requests = @()
    foreach ($line in $tsharkOutput) {
        $fields = $line -split "\|"
        if ($fields.Count -ge 7) {
            $request = [PSCustomObject]@{
                FrameNumber = $fields[0]
                SourceIP = $fields[1]
                DestinationIP = $fields[2]
                Host = $fields[3]
                URI = $fields[4]
                Method = $fields[5]
                UserAgent = $fields[6]
            }
            $requests += $request
        }
    }
    
    return $requests
}

# Extract HTTP responses from PCAP
function Get-HttpResponses {
    param (
        [string]$PcapFile
    )
    
    $tsharkOutput = & tshark -r $PcapFile -Y "http.response" -T fields -e frame.number -e ip.src -e ip.dst -e http.response.code -e http.content_type -E separator="|"
    
    $responses = @()
    foreach ($line in $tsharkOutput) {
        $fields = $line -split "\|"
        if ($fields.Count -ge 5) {
            $response = [PSCustomObject]@{
                FrameNumber = $fields[0]
                SourceIP = $fields[1]
                DestinationIP = $fields[2]
                ResponseCode = $fields[3]
                ContentType = $fields[4]
            }
            $responses += $response
        }
    }
    
    return $responses
}

# Extract files from PCAP
function Extract-FilesFromPcap {
    param (
        [string]$PcapFile,
        [string]$OutputFolder
    )
    
    # Create output folder if it doesn't exist
    if (-not (Test-Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder | Out-Null
    }
    
    # Extract HTTP objects
    Write-Host "Extracting HTTP objects from PCAP..."
    & tshark -r $PcapFile --export-objects "http,$OutputFolder\http" | Out-Null
    
    # Extract image files
    Write-Host "Extracting image files from PCAP..."
    $imageFolder = Join-Path $OutputFolder "images"
    if (-not (Test-Path $imageFolder)) {
        New-Item -ItemType Directory -Path $imageFolder | Out-Null
    }
    
    & tshark -r $PcapFile -Y "http.response.code == 200 and (http.content_type contains \"image/jpeg\" or http.content_type contains \"image/png\")" -T fields -e frame.number -e http.request.uri -e http.content_type -E separator="|" | ForEach-Object {
        $fields = $_ -split "\|"
        if ($fields.Count -ge 3) {
            $frameNumber = $fields[0]
            $uri = $fields[1]
            $contentType = $fields[2]
            
            $extension = if ($contentType -match "jpeg") { "jpg" } else { "png" }
            $fileName = "image_frame${frameNumber}_$([System.IO.Path]::GetFileName($uri)).$extension"
            $outputFile = Join-Path $imageFolder $fileName
            
            & tshark -r $PcapFile -Y "frame.number == $frameNumber" --export-objects "http,$imageFolder" | Out-Null
            
            # Rename the extracted file if it exists
            $extractedFiles = Get-ChildItem $imageFolder -File | Where-Object { $_.CreationTime -gt (Get-Date).AddSeconds(-5) }
            if ($extractedFiles.Count -gt 0) {
                $extractedFile = $extractedFiles[0]
                Move-Item $extractedFile.FullName $outputFile -Force
                Write-Host "  Extracted image: $fileName"
            }
        }
    }
}

# Analyze HTTP requests for Kaolin RAT patterns
function Find-KaolinRatPatterns {
    param (
        [array]$HttpRequests,
        [array]$HttpResponses
    )
    
    $suspiciousRequests = @()
    $dictionaryWords = @("user", "type", "id", "session", "token", "auth", "data", "content", "action", "status", "result", "value", "param", "atype")
    
    foreach ($request in $HttpRequests) {
        $suspiciousScore = 0
        $reasons = @()
        
        # Check for dictionary-based URL parameters
        $urlParams = $request.URI -split "\?" | Select-Object -Last 1
        if ($urlParams -ne $request.URI) {
            $params = $urlParams -split "&"
            foreach ($param in $params) {
                $paramName = $param -split "=" | Select-Object -First 1
                if ($dictionaryWords -contains $paramName) {
                    $suspiciousScore += 1
                    $reasons += "Dictionary-based URL parameter: $paramName"
                }
                
                # Check for short random values (2 chars)
                $paramValue = $param -split "=" | Select-Object -Last 1
                if ($paramValue.Length -eq 2 -and $paramValue -match "[a-zA-Z0-9]{2}") {
                    $suspiciousScore += 1
                    $reasons += "Short random parameter value: $paramValue"
                }
            }
        }
        
        # Check for POST requests with form data
        if ($request.Method -eq "POST" -and $request.URI -match "\?[a-zA-Z]+=") {
            $suspiciousScore += 2
            $reasons += "POST request with URL parameters"
        }
        
        # Check for image requests that might be used for steganography
        if ($request.URI -match "\.(jpg|jpeg|png|gif)") {
            $suspiciousScore += 1
            $reasons += "Image request (potential steganography)"
        }
        
        # Check for suspicious domains
        if ($request.Host -match "henraux\.com") {
            $suspiciousScore += 3
            $reasons += "Known Kaolin RAT C2 domain"
        }
        
        # Check for specific URL patterns
        if ($request.URI -match "/sitemaps/about/about\.asp") {
            $suspiciousScore += 3
            $reasons += "Known Kaolin RAT C2 URL path"
        }
        
        # Add to suspicious requests if score is high enough
        if ($suspiciousScore -ge 2) {
            $suspiciousRequest = [PSCustomObject]@{
                FrameNumber = $request.FrameNumber
                SourceIP = $request.SourceIP
                DestinationIP = $request.DestinationIP
                Host = $request.Host
                URI = $request.URI
                Method = $request.Method
                UserAgent = $request.UserAgent
                SuspiciousScore = $suspiciousScore
                Reasons = $reasons -join ", "
            }
            $suspiciousRequests += $suspiciousRequest
        }
    }
    
    return $suspiciousRequests
}

# Analyze extracted images for steganography
function Analyze-ImagesForSteganography {
    param (
        [string]$ImageFolder
    )
    
    $results = @()
    
    # Get all image files
    $imageFiles = Get-ChildItem $ImageFolder -File -Include "*.jpg", "*.jpeg", "*.png", "*.gif"
    
    foreach ($imageFile in $imageFiles) {
        Write-Host "Analyzing image: $($imageFile.Name)"
        
        # Basic analysis - check file size and entropy
        $fileSize = $imageFile.Length
        $fileBytes = [System.IO.File]::ReadAllBytes($imageFile.FullName)
        
        # Calculate entropy (Shannon entropy)
        $byteFrequency = @{}
        foreach ($byte in $fileBytes) {
            if ($byteFrequency.ContainsKey($byte)) {
                $byteFrequency[$byte]++
            } else {
                $byteFrequency[$byte] = 1
            }
        }
        
        $entropy = 0
        foreach ($frequency in $byteFrequency.Values) {
            $probability = $frequency / $fileSize
            $entropy -= $probability * [Math]::Log($probability, 2)
        }
        
        # Check for anomalies
        $anomalies = @()
        
        # High entropy might indicate encrypted or compressed data
        if ($entropy -gt 7.5) {
            $anomalies += "High entropy ($([Math]::Round($entropy, 2)))"
        }
        
        # Check for data after EOF marker in JPEG
        if ($imageFile.Extension -match "\.jpe?g$") {
            $eofMarker = [byte[]]@(0xFF, 0xD9)
            $eofPosition = -1
            
            for ($i = 0; $i -lt $fileBytes.Length - 1; $i++) {
                if ($fileBytes[$i] -eq $eofMarker[0] -and $fileBytes[$i + 1] -eq $eofMarker[1]) {
                    $eofPosition = $i + 1
                    break
                }
            }
            
            if ($eofPosition -ne -1 -and $eofPosition -lt $fileBytes.Length - 1) {
                $dataAfterEof = $fileBytes.Length - $eofPosition - 1
                $anomalies += "Data after EOF marker ($dataAfterEof bytes)"
            }
        }
        
        # Add result
        $result = [PSCustomObject]@{
            FileName = $imageFile.Name
            FileSize = $fileSize
            Entropy = [Math]::Round($entropy, 2)
            Anomalies = $anomalies -join ", "
            SuspiciousScore = if ($anomalies.Count -gt 0) { $anomalies.Count } else { 0 }
        }
        
        $results += $result
    }
    
    return $results
}

# Main function
function Main {
    # Check if tshark is available
    if (-not (Test-TsharkAvailable)) {
        Write-Error "tshark.exe is not available. Please install Wireshark and ensure tshark is in your PATH."
        exit 1
    }
    
    # Check if PCAP file exists
    if (-not (Test-Path $PcapFile)) {
        Write-Error "PCAP file not found: $PcapFile"
        exit 1
    }
    
    # Create output folder if it doesn't exist
    if (-not (Test-Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder | Out-Null
    }
    
    Write-Host "Analyzing PCAP file: $PcapFile"
    Write-Host "Output folder: $OutputFolder"
    
    # Extract files if requested
    if ($ExtractFiles) {
        Write-Host "`nExtracting files from PCAP..."
        Extract-FilesFromPcap -PcapFile $PcapFile -OutputFolder $OutputFolder
    }
    
    # Analyze HTTP traffic
    Write-Host "`nAnalyzing HTTP requests..."
    $httpRequests = Get-HttpRequests -PcapFile $PcapFile
    $httpResponses = Get-HttpResponses -PcapFile $PcapFile
    
    Write-Host "  Found $($httpRequests.Count) HTTP requests"
    Write-Host "  Found $($httpResponses.Count) HTTP responses"
    
    # Find Kaolin RAT patterns
    Write-Host "`nSearching for Kaolin RAT C2 patterns..."
    $suspiciousRequests = Find-KaolinRatPatterns -HttpRequests $httpRequests -HttpResponses $httpResponses
    
    Write-Host "  Found $($suspiciousRequests.Count) suspicious requests"
    
    # Save suspicious requests to CSV
    $suspiciousRequestsFile = Join-Path $OutputFolder "suspicious_requests.csv"
    $suspiciousRequests | Export-Csv -Path $suspiciousRequestsFile -NoTypeInformation
    Write-Host "  Saved suspicious requests to: $suspiciousRequestsFile"
    
    # Analyze extracted images for steganography
    $imageFolder = Join-Path $OutputFolder "images"
    if (Test-Path $imageFolder) {
        Write-Host "`nAnalyzing extracted images for steganography..."
        $imageAnalysisResults = Analyze-ImagesForSteganography -ImageFolder $imageFolder
        
        $suspiciousImages = $imageAnalysisResults | Where-Object { $_.SuspiciousScore -gt 0 }
        Write-Host "  Found $($suspiciousImages.Count) suspicious images"
        
        # Save image analysis results to CSV
        $imageAnalysisFile = Join-Path $OutputFolder "image_analysis.csv"
        $imageAnalysisResults | Export-Csv -Path $imageAnalysisFile -NoTypeInformation
        Write-Host "  Saved image analysis results to: $imageAnalysisFile"
    }
    
    # Generate summary report
    Write-Host "`nGenerating summary report..."
    $reportFile = Join-Path $OutputFolder "analysis_report.txt"
    
    $report = @"
Kaolin RAT C2 Traffic Analysis Report
====================================
PCAP File: $PcapFile
Analysis Date: $(Get-Date)

Summary
-------
Total HTTP Requests: $($httpRequests.Count)
Total HTTP Responses: $($httpResponses.Count)
Suspicious Requests: $($suspiciousRequests.Count)
"@
    
    if (Test-Path $imageFolder) {
        $report += @"

Extracted Images: $($imageAnalysisResults.Count)
Suspicious Images: $($suspiciousImages.Count)
"@
    }
    
    $report += @"

Top Suspicious Requests
----------------------
"@
    
    $topSuspicious = $suspiciousRequests | Sort-Object -Property SuspiciousScore -Descending | Select-Object -First 5
    foreach ($request in $topSuspicious) {
        $report += @"

Frame: $($request.FrameNumber)
Host: $($request.Host)
URI: $($request.URI)
Method: $($request.Method)
Suspicious Score: $($request.SuspiciousScore)
Reasons: $($request.Reasons)
"@
    }
    
    if ($suspiciousImages.Count -gt 0) {
        $report += @"

Suspicious Images
----------------
"@
        
        foreach ($image in $suspiciousImages) {
            $report += @"

File: $($image.FileName)
Size: $($image.FileSize) bytes
Entropy: $($image.Entropy)
Anomalies: $($image.Anomalies)
"@
        }
    }
    
    $report | Out-File -FilePath $reportFile -Encoding utf8
    Write-Host "  Saved analysis report to: $reportFile"
    
    Write-Host "`nAnalysis complete!"
}

# Run the main function
Main
