# Configuration
$esURL = "https://<redacted>.es.ece-test-bm.<redacted>.net:<redacted>"

# Log indices
$logsWindowsIndex = "ste-logs-randbank-windows"
$logsMainframeIndex = "ste-logs-randbank-mainframe"
$logsApplicationIndex = "ste-logs-randbank-application"
$logsPowershellIndex = "ste-logs-randbank-powershell"
# Performance metrics indices
$perfAppTransIndex = "ste-metrics-randbank-application-transactions"
$perfWindowsIndex = "ste-metrics-randbank-windows"
$perfMainframeIndex = "ste-metrics-randbank-mainframe"
$SleepInterval = 10
$PerfSampleInterval = 60
$LogsSampleInterval = 60
# Credentials (Basic Auth)
$username = "<redacted>"
$password = "<redacted>"
$base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($username):$($password)"))
# Function to send data to Elasticsearch (Bulk API)
function Send-To-Elasticsearch {
    param (
        [string]$index,
        [object]$data
    )
    $bulkBody = @()
    foreach ($item in $data) {
        $bulkBody += '{ "index" : { "_index" : "' + $index + '" } }'
        $bulkBody += ($item | ConvertTo-Json -Compress)
    }
    $combinedUrl = $esURL + "/_bulk"
    try {
        $bulkBody += ""  # Empty line to ensure proper termination
        Invoke-RestMethod -Uri $combinedUrl -Method Post -Body ($bulkBody -join "`n") -Headers @{
            "Authorization" = "Basic $base64Auth"
            "Content-Type"  = "application/x-ndjson"
        } -Timeout 300
    }
    catch {
        Write-Error "Failed to send data to Elasticsearch: $_"
    }
}
# Function to generate random application transaction metrics
function New-RandomAppTransactionMetric {
    $random = Get-Random
    $baseTime = (Get-Date).AddMinutes(-$random % 120)
    $samples = @()
    $sampleCount = 5 + ($random % 6)
    # $timeSpan = New-TimeSpan -Seconds $PerfSampleInterval
    for ($i = 0; $i -lt $sampleCount; $i++) {
        $offset = [math]::Round(($random % 60) * 1000, 0)
        $sampleTime = $baseTime.AddMilliseconds($offset)
        $transactionRate = [math]::Round(($random % 500) + 50, 2)  # 50-550 transactions/sec
        $serverNames = @("RANDBANK-SRV01", "RANDBANK-SRV02", "RANDBANK-SRV03", "RANDBANK-WEB01", "RANDBANK-WEB02")
        $server = $serverNames[$random % $serverNames.Count]
        $samples += @{
            "@timestamp"   = $sampleTime.ToString("o")
            "ObjectName"   = "RandBank Transaction Processor"
            "CounterName"  = "Transaction/Sec"
            "InstanceName" = $server
            "Value"        = $transactionRate
            "host"         = @{
                "name" = $server
                "os"   = @{
                    "platform" = "Windows Server 2019"
                    "version"  = "10.0.17763"
                }
            }
            "metric"       = @{
                "name" = "Transaction/Sec"
                "type" = "gauge"
            }
        }
    }
    return $samples
}
# Function to generate random Windows metrics
function New-RandomWindowsMetrics {
    $random = Get-Random
    $baseTime = (Get-Date).AddMinutes(-$random % 120)
    $samples = @()
    $sampleCount = 5 + ($random % 6)
    $serverNames = @("WEB01", "APP01", "DB01", "FILE01")

    for ($i = 0; $i -lt $sampleCount; $i++) {
        $offset = [math]::Round(($random % 60) * 1000, 0)
        $sampleTime = $baseTime.AddMilliseconds($offset)
        $server = $serverNames[$random % $serverNames.Count]

        # CPU Usage (0-100%)
        $cpuUsage = [math]::Round(($random % 100), 2)

        # Memory Usage (0-100%)
        $memoryUsage = [math]::Round(($random % 100), 2)

        # Network Bytes Sent (0-1000000)
        $networkSent = [math]::Round(($random % 1000000), 0)

        # Network Bytes Received (0-1000000)
        $networkRecv = [math]::Round(($random % 1000000), 0)

        # Disk Read (0-10000)
        $diskRead = [math]::Round(($random % 10000), 0)

        # Disk Write (0-10000)
        $diskWrite = [math]::Round(($random % 10000), 0)

        $samples += @{
            "@timestamp"   = $sampleTime.ToString("o")
            "ObjectName"   = "Windows System"
            "CounterName"  = "CPU Usage"
            "InstanceName" = $server
            "Value"        = $cpuUsage
            "host"         = @{
                "name" = $server
                "os"   = @{
                    "platform" = "Windows Server 2019"
                    "version"  = "10.0.17763"
                }
            }
            "metric"       = @{
                "name" = "CPU Usage"
                "type" = "gauge"
            }
        }

        $samples += @{
            "@timestamp"   = $sampleTime.ToString("o")
            "ObjectName"   = "Windows System"
            "CounterName"  = "Memory Usage"
            "InstanceName" = $server
            "Value"        = $memoryUsage
            "host"         = @{
                "name" = $server
                "os"   = @{
                    "platform" = "Windows Server 2019"
                    "version"  = "10.0.17763"
                }
            }
            "metric"       = @{
                "name" = "Memory Usage"
                "type" = "gauge"
            }
        }

        $samples += @{
            "@timestamp"   = $sampleTime.ToString("o")
            "ObjectName"   = "Windows Network"
            "CounterName"  = "Bytes Sent/sec"
            "InstanceName" = $server
            "Value"        = $networkSent
            "host"         = @{
                "name" = $server
                "os"   = @{
                    "platform" = "Windows Server 2019"
                    "version"  = "10.0.17763"
                }
            }
            "metric"       = @{
                "name" = "Network Bytes Sent"
                "type" = "counter"
            }
        }

        $samples += @{
            "@timestamp"   = $sampleTime.ToString("o")
            "ObjectName"   = "Windows Network"
            "CounterName"  = "Bytes Received/sec"
            "InstanceName" = $server
            "Value"        = $networkRecv
            "host"         = @{
                "name" = $server
                "os"   = @{
                    "platform" = "Windows Server 2019"
                    "version"  = "10.0.17763"
                }
            }
            "metric"       = @{
                "name" = "Network Bytes Received"
                "type" = "counter"
            }
        }

        $samples += @{
            "@timestamp"   = $sampleTime.ToString("o")
            "ObjectName"   = "Windows Disk"
            "CounterName"  = "Disk Read Bytes/sec"
            "InstanceName" = $server
            "Value"        = $diskRead
            "host"         = @{
                "name" = $server
                "os"   = @{
                    "platform" = "Windows Server 2019"
                    "version"  = "10.0.17763"
                }
            }
            "metric"       = @{
                "name" = "Disk Read Bytes"
                "type" = "counter"
            }
        }

        $samples += @{
            "@timestamp"   = $sampleTime.ToString("o")
            "ObjectName"   = "Windows Disk"
            "CounterName"  = "Disk Write Bytes/sec"
            "InstanceName" = $server
            "Value"        = $diskWrite
            "host"         = @{
                "name" = $server
                "os"   = @{
                    "platform" = "Windows Server 2019"
                    "version"  = "10.0.17763"
                }
            }
            "metric"       = @{
                "name" = "Disk Write Bytes"
                "type" = "counter"
            }
        }
    }
    return $samples
}
# Function to generate random Mainframe metrics
function New-RandomMainframeMetrics {
    $random = Get-Random
    $baseTime = (Get-Date).AddMinutes(-$random % 120)
    $samples = @()
    $sampleCount = 5 + ($random % 6)
    $mainframeNames = @("RANDBANK-MF01", "RANDBANK-MF02", "RANDBANK-MF03")

    for ($i = 0; $i -lt $sampleCount; $i++) {
        $offset = [math]::Round(($random % 60) * 1000, 0)
        $sampleTime = $baseTime.AddMilliseconds($offset)
        $mainframe = $mainframeNames[$random % $mainframeNames.Count]

        # Queue Length (0-1000)
        $queueLength = [math]::Round(($random % 1000), 0)

        # Input Rate (0-1000)
        $inputRate = [math]::Round(($random % 1000), 0)

        # Output Rate (0-1000)
        $outputRate = [math]::Round(($random % 1000), 0)

        # Response Time (0-10000 ms)
        $responseTime = [math]::Round(($random % 10000), 0)

        # CPU Usage (0-100%)
        $cpuUsage = [math]::Round(($random % 100), 2)

        # I/O Wait Time (0-1000 ms)
        $ioWaitTime = [math]::Round(($random % 1000), 0)

        $samples += @{
            "@timestamp"   = $sampleTime.ToString("o")
            "ObjectName"   = "Mainframe System"
            "CounterName"  = "Queue Length"
            "InstanceName" = $mainframe
            "Value"        = $queueLength
            "host"         = @{
                "name" = $mainframe
                "os"   = @{
                    "platform" = "z/OS"
                    "version"  = "2.4"
                }
            }
            "metric"       = @{
                "name" = "Queue Length"
                "type" = "gauge"
            }
        }

        $samples += @{
            "@timestamp"   = $sampleTime.ToString("o")
            "ObjectName"   = "Mainframe System"
            "CounterName"  = "Input Rate"
            "InstanceName" = $mainframe
            "Value"        = $inputRate
            "host"         = @{
                "name" = $mainframe
                "os"   = @{
                    "platform" = "z/OS"
                    "version"  = "2.4"
                }
            }
            "metric"       = @{
                "name" = "Input Rate"
                "type" = "counter"
            }
        }

        $samples += @{
            "@timestamp"   = $sampleTime.ToString("o")
            "ObjectName"   = "Mainframe System"
            "CounterName"  = "Output Rate"
            "InstanceName" = $mainframe
            "Value"        = $outputRate
            "host"         = @{
                "name" = $mainframe
                "os"   = @{
                    "platform" = "z/OS"
                    "version"  = "2.4"
                }
            }
            "metric"       = @{
                "name" = "Output Rate"
                "type" = "counter"
            }
        }

        $samples += @{
            "@timestamp"   = $sampleTime.ToString("o")
            "ObjectName"   = "Mainframe System"
            "CounterName"  = "Response Time"
            "InstanceName" = $mainframe
            "Value"        = $responseTime
            "host"         = @{
                "name" = $mainframe
                "os"   = @{
                    "platform" = "z/OS"
                    "version"  = "2.4"
                }
            }
            "metric"       = @{
                "name" = "Response Time"
                "type" = "gauge"
            }
        }

        $samples += @{
            "@timestamp"   = $sampleTime.ToString("o")
            "ObjectName"   = "Mainframe System"
            "CounterName"  = "CPU Usage"
            "InstanceName" = $mainframe
            "Value"        = $cpuUsage
            "host"         = @{
                "name" = $mainframe
                "os"   = @{
                    "platform" = "z/OS"
                    "version"  = "2.4"
                }
            }
            "metric"       = @{
                "name" = "CPU Usage"
                "type" = "gauge"
            }
        }

        $samples += @{
            "@timestamp"   = $sampleTime.ToString("o")
            "ObjectName"   = "Mainframe System"
            "CounterName"  = "I/O Wait Time"
            "InstanceName" = $mainframe
            "Value"        = $ioWaitTime
            "host"         = @{
                "name" = $mainframe
                "os"   = @{
                    "platform" = "z/OS"
                    "version"  = "2.4"
                }
            }
            "metric"       = @{
                "name" = "I/O Wait Time"
                "type" = "gauge"
            }
        }
    }
    return $samples
}

# Function to generate random Windows logs
function New-RandomWindowsLogs {
    $random = Get-Random
    $baseTime = (Get-Date).AddMinutes(-$random % 120)
    $logs = @()
    $sampleCount = 5 + ($random % 6)
    $servers = @("WEB01", "APP01", "DB01", "FILE01")
    $logLevels = @("INFO", "WARNING", "ERROR", "CRITICAL")
    $eventSources = @("Application", "System", "Security", "Setup", "Service Control Manager")

    for ($i = 0; $i -lt $sampleCount; $i++) {
        $offset = [math]::Round(($random % 60) * 1000, 0)
        $sampleTime = $baseTime.AddMilliseconds($offset)
        $server = $servers[$random % $servers.Count]
        $logLevel = $logLevels[$random % $logLevels.Count]
        $eventSource = $eventSources[$random % $eventSources.Count]

        $logMessages = @(
            "Service $eventSource started successfully",
            "User logged in from IP $($random % 256).$($random % 256).$($random % 256).$($random % 256)",
            "Disk space low on drive C: (${$random % 100}% free)",
            "Failed to connect to database server",
            "Application pool $($random % 10) recycled",
            "Security audit: User attempted to access restricted resource",
            "Windows Update installed successfully",
            "Network interface $($random % 10) disconnected",
            "Memory pressure detected (${$random % 100}% usage)",
            "Scheduled task completed with errors"
        )

        $logMessage = $logMessages[$random % $logMessages.Count]

        $logs += @{
            "@timestamp" = $sampleTime.ToString("o")
            "host"       = @{
                "name" = $server
                "os"   = @{
                    "platform" = "Windows Server 2019"
                    "version"  = "10.0.17763"
                }
            }
            "log"        = @{
                "level"    = $logLevel
                "source"   = $eventSource
                "message"  = $logMessage
                "event_id" = $random % 1000
            }
        }
    }
    return $logs
}

# Function to generate random Mainframe logs
function New-RandomMainframeLogs {
    $random = Get-Random
    $baseTime = (Get-Date).AddMinutes(-$random % 120)
    $logs = @()
    $sampleCount = 5 + ($random % 6)
    $mainframeNames = @("RANDBANK-MF01", "RANDBANK-MF02", "RANDBANK-MF03")
    $logLevels = @("INFO", "WARNING", "ERROR", "SEVERE")
    $jobTypes = @("BATCH", "ONLINE", "REPORT", "UTILITY")

    for ($i = 0; $i -lt $sampleCount; $i++) {
        $offset = [math]::Round(($random % 60) * 1000, 0)
        $sampleTime = $baseTime.AddMilliseconds($offset)
        $mainframe = $mainframeNames[$random % $mainframeNames.Count]
        $logLevel = $logLevels[$random % $logLevels.Count]
        $jobType = $jobTypes[$random % $jobTypes.Count]

        $logMessages = @(
            "Job $($random % 10000) started on $mainframe",
            "ABEND occurred in program $($random % 1000) - RC $($random % 4095)",
            "Dataset $($random % 1000) opened successfully",
            "Tape mount request for volume $($random % 1000) completed",
            "Security violation detected - unauthorized access attempt",
            "Job $($random % 10000) completed with return code $($random % 4095)",
            "System checkpoint completed successfully",
            "IMS transaction processed in $($random % 1000) ms",
            "CICS transaction completed with response time $($random % 1000) ms",
            "DB2 SQL error occurred - SQLCODE $($random % 4095)",
            "JCL error in step $($random % 10) - RC $($random % 4095)"
        )

        $logMessage = $logMessages[$random % $logMessages.Count]

        $logs += @{
            "@timestamp" = $sampleTime.ToString("o")
            "host"       = @{
                "name" = $mainframe
                "os"   = @{
                    "platform" = "z/OS"
                    "version"  = "2.4"
                }
            }
            "log"        = @{
                "level"    = $logLevel
                "source"   = "Mainframe System"
                "message"  = $logMessage
                "job_type" = $jobType
                "job_id"   = $random % 10000
            }
        }
    }
    return $logs
}

# Function to generate random application logs
function New-RandomApplicationLogs {
    $random = Get-Random
    $baseTime = (Get-Date).AddMinutes(-$random % 120)
    $samples = @()
    $sampleCount = 5 + ($random % 6)
    $servers = @("WEB01", "APP01", "DB01", "FILE01")
    $apps = @("WebApp", "APIService", "Database", "FileProcessor", "BackgroundWorker")
    $logLevels = @("INFO", "WARN", "ERROR", "DEBUG", "TRACE")
    $commonErrors = @(
        "Connection timeout to database",
        "Failed to process request",
        "Invalid input parameters",
        "Resource not found",
        "Authentication failed",
        "Memory allocation error",
        "Thread pool exhausted",
        "Disk space low",
        "Network unreachable",
        "Service dependency failed"
    )

    for ($i = 0; $i -lt $sampleCount; $i++) {
        $offset = [math]::Round(($random % 60) * 1000, 0)
        $sampleTime = $baseTime.AddMilliseconds($offset)
        $server = $servers[$random % $servers.Count]
        $app = $apps[$random % $apps.Count]
        $level = $logLevels[$random % $logLevels.Count]
        $message = if ($level -eq "ERROR") {
            $commonErrors[$random % $commonErrors.Count]
        } else {
            $commonMessages = @(
                "Application started successfully",
                "Request processed in {0}ms" -f ($random % 1000),
                "Health check passed",
                "New connection established",
                "Data synchronized with external system",
                "Cache warmed up",
                "Background job completed",
                "Configuration reloaded",
                "User logged in",
                "Session expired"
            )
            $commonMessages[$random % $commonMessages.Count]
        }

        $samples += @{
            "@timestamp" = $sampleTime.ToString("o")
            "log" = @{
                "level" = $level
                "message" = $message
                "application" = $app
                "server" = $server
            }
            "host" = @{
                "name" = $server
                "os" = @{
                    "platform" = "Windows Server 2019"
                    "version" = "10.0.17763"
                }
            }
            "metric" = @{
                "name" = "Application Log"
                "type" = "log"
            }
        }
    }
    return $samples
}

# Function to generate random PowerShell logs
function New-RandomPowerShellLogs {
    $random = Get-Random
    $baseTime = (Get-Date).AddMinutes(-$random % 120)
    $samples = @()
    $sampleCount = 5 + ($random % 6)
    $servers = @("WEB01", "APP01", "DB01", "FILE01")
    $cmdlets = @(
        "Get-Process",
        "Invoke-WebRequest",
        "Start-Service",
        "Stop-Service",
        "Restart-Computer",
        "Export-Csv",
        "Import-Csv",
        "Test-Connection",
        "Get-EventLog",
        "Write-Output",
        "Set-ItemProperty",
        "Get-ChildItem",
        "Copy-Item",
        "Remove-Item",
        "New-Item"
    )
    $commonErrors = @(
        "Cannot find path",
        "Access denied",
        "Parameter not found",
        "Invalid operation",
        "Pipeline not supported",
        "Method not found",
        "Property not found",
        "Type not found",
        "Format not supported",
        "Execution policy violation"
    )

    for ($i = 0; $i -lt $sampleCount; $i++) {
        $offset = [math]::Round(($random % 60) * 1000, 0)
        $sampleTime = $baseTime.AddMilliseconds($offset)
        $server = $servers[$random % $servers.Count]
        $cmdlet = $cmdlets[$random % $cmdlets.Count]
        $isError = $random % 5 -eq 0  # 20% chance of error

        if ($isError) {
            $message = "Error: {0} - {1}" -f $cmdlet, $commonErrors[$random % $commonErrors.Count]
            $level = "ERROR"
        } else {
            $successMessages = @(
                "Successfully executed {0}" -f $cmdlet,
                "Command completed in {0}ms" -f ($random % 500),
                "Output written to console",
                "Pipeline processed {0} objects" -f ($random % 1000),
                "Configuration applied successfully",
                "Service state verified",
                "File operations completed",
                "Data retrieved successfully",
                "Script executed without errors",
                "All tests passed"
            )
            $message = $successMessages[$random % $successMessages.Count]
            $level = if ($random % 3 -eq 0) { "INFO" } else { "DEBUG" }
        }

        $samples += @{
            "@timestamp" = $sampleTime.ToString("o")
            "log" = @{
                "level" = $level
                "message" = $message
                "cmdlet" = $cmdlet
                "server" = $server
                "script" = if ($random % 2 -eq 0) { "Automation.ps1" } else { "Maintenance.ps1" }
            }
            "host" = @{
                "name" = $server
                "os" = @{
                    "platform" = "Windows Server 2019"
                    "version" = "10.0.17763"
                }
            }
            "metric" = @{
                "name" = "PowerShell Log"
                "type" = "log"
            }
        }
    }
    return $samples
}

# Main script
try {
    Write-Host "Application transaction metrics: $esURL/$perfAppTransIndex/_doc"
    Write-Host "Windows metrics: $esURL/$perfWindowsIndex/_doc"
    Write-Host "Mainframe metrics: $esURL/$perfMainframeIndex/_doc"
    Write-Host "Windows logs: $esURL/$logsWindowsIndex/_doc"
    Write-Host "Mainframe logs: $esURL/$logsMainframeIndex/_doc"
    Write-Host "Application logs: $esURL/$logsApplicationIndex/_doc"
    Write-Host "PowerShell logs: $esURL/$logsPowershellIndex/_doc"

    $lastPerfSample = (Get-Date).AddMinutes(-1)
    $lastLogsSample = (Get-Date).AddMinutes(-1)
    while ($true) {
        $appTransMetricsToSend = @()
        $windowsMetricsToSend = @()
        $mainframeMetricsToSend = @()
        $windowsLogsToSend = @()
        $mainframeLogsToSend = @()
        $applicationLogsToSend = @()
        $powershellLogsToSend = @()
        # Generate performance metrics every $PerfSampleInterval seconds
        if ((Get-Date) - $lastPerfSample -ge (New-TimeSpan -Seconds $PerfSampleInterval)) {
            $appTransMetricsToSend = New-RandomAppTransactionMetric
            $windowsMetricsToSend = New-RandomWindowsMetrics
            $mainframeMetricsToSend = New-RandomMainframeMetrics
            $lastPerfSample = Get-Date
            Write-Host "Generated $($appTransMetricsToSend.Count) application transaction metric samples"
            Write-Host "Generated $($windowsMetricsToSend.Count) Windows metric samples"
            Write-Host "Generated $($mainframeMetricsToSend.Count) Mainframe metric samples"
        }
        # Generate logs every $LogsSampleInterval seconds
        if ((Get-Date) - $lastLogsSample -ge (New-TimeSpan -Seconds $LogsSampleInterval)) {
            $windowsLogsToSend = New-RandomWindowsLogs
            $mainframeLogsToSend = New-RandomMainframeLogs
            $applicationLogsToSend = New-RandomApplicationLogs
            $powershellLogsToSend = New-RandomPowerShellLogs
            $lastLogsSample = Get-Date
            Write-Host "Generated $($windowsLogsToSend.Count) Windows log samples"
            Write-Host "Generated $($mainframeLogsToSend.Count) Mainframe log samples"
            Write-Host "Generated $($applicationLogsToSend.Count) Application log samples"
            Write-Host "Generated $($powershellLogsToSend.Count) PowerShell log samples"
        }
        if ($appTransMetricsToSend.Count -gt 0) {
            Write-Host "Sending batch of $($appTransMetricsToSend.Count) application transaction metrics..."
            try {
                Send-To-Elasticsearch -index $perfAppTransIndex -data $appTransMetricsToSend
            }
            catch {
                Write-Host "Error sending application transaction metrics: $_"
            }
        }
        if ($windowsMetricsToSend.Count -gt 0) {
            Write-Host "Sending batch of $($windowsMetricsToSend.Count) Windows metrics..."
            try {
                Send-To-Elasticsearch -index $perfWindowsIndex -data $windowsMetricsToSend
            }
            catch {
                Write-Host "Error sending Windows metrics: $_"
            }
        }
        if ($mainframeMetricsToSend.Count -gt 0) {
            Write-Host "Sending batch of $($mainframeMetricsToSend.Count) Mainframe metrics..."
            try {
                Send-To-Elasticsearch -index $perfMainframeIndex -data $mainframeMetricsToSend
            }
            catch {
                Write-Host "Error sending Mainframe metrics: $_"
            }
        }
        if($windowsLogsToSend.Count -gt 0) {
            Write-Host "Sending batch of $($windowsLogsToSend.Count) Windows logs..."
            try {
                Send-To-Elasticsearch -index $logsWindowsIndex -data $windowsLogsToSend
            }
            catch {
                Write-Host "Error sending Windows logs: $_"
            }
        }
        if($mainframeLogsToSend.Count -gt 0) {
            Write-Host "Sending batch of $($mainframeLogsToSend.Count) Mainframe logs..."
            try {
                Send-To-Elasticsearch -index $logsMainframeIndex -data $mainframeLogsToSend
            }
            catch {
                Write-Host "Error sending Mainframe logs: $_"
            }
        }
        if($applicationLogsToSend.Count -gt 0) {
            Write-Host "Sending batch of $($applicationLogsToSend.Count) Application logs..."
            try {
                Send-To-Elasticsearch -index $logsApplicationIndex -data $applicationLogsToSend
            }
            catch {
                Write-Host "Error sending Application logs: $_"
            }
        }
        if($powershellLogsToSend.Count -gt 0) {
            Write-Host "Sending batch of $($powershellLogsToSend.Count) PowerShell logs..."
            try {
                Send-To-Elasticsearch -index $logsPowershellIndex -data $powershellLogsToSend
            }
            catch {
                Write-Host "Error sending PowerShell logs: $_"
            }
        }
        # Wait before next batch
        Start-Sleep -Seconds $SleepInterval
    }
}
catch {
    Write-Host "An error occurred: $_"
    exit 1
}