"""Guest-side PowerShell Direct shims for Windows VM harness runs."""

from __future__ import annotations


def package_smoke_script() -> str:
    """Returns the PowerShell package-smoke script executed inside a Hyper-V guest."""

    return r"""
$ErrorActionPreference = 'Stop'
$secure = ConvertTo-SecureString $payload.password -AsPlainText -Force
$credential = [pscredential]::new($payload.username, $secure)
$vm = Get-VM -Name $payload.vmName -ErrorAction Stop
if ($payload.switchName) {
  Connect-VMNetworkAdapter -VMName $payload.vmName -SwitchName $payload.switchName
}
if ($vm.State -ne 'Off') {
  Stop-VM -Name $payload.vmName -TurnOff -Force
}
$snapshot = Get-VMSnapshot -VMName $payload.vmName -Name $payload.checkpointName -ErrorAction Stop
Restore-VMSnapshot -VMSnapshot $snapshot -Confirm:$false
if ($payload.switchName) {
  Connect-VMNetworkAdapter -VMName $payload.vmName -SwitchName $payload.switchName
}
Start-VM -Name $payload.vmName
$deadline = (Get-Date).AddMinutes(10)
$session = $null
do {
  Start-Sleep -Seconds 3
  try {
    $session = New-PSSession -VMName $payload.vmName -Credential $credential -ErrorAction Stop
  } catch {
    if ((Get-Date) -gt $deadline) { throw }
  }
} while (-not $session)
$guestRoot = 'C:\eMuleBBVmTest\' + $payload.runId + '\' + $payload.target
$guestZip = Join-Path $guestRoot (Split-Path -Leaf $payload.packageZip)
try {
  Invoke-Command -Session $session -ScriptBlock {
    param($root)
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $root | Out-Null
  } -ArgumentList $guestRoot
  Copy-Item -ToSession $session -Path $payload.packageZip -Destination $guestZip
  $guestResult = Invoke-Command -Session $session -ScriptBlock {
    param($root, $zipPath)
    $ErrorActionPreference = 'Stop'
    function New-Check($name, $status, $details) {
      [pscustomobject]@{ name = $name; status = $status; details = $details }
    }
    function ConvertTo-ProcessArgument([string] $argument) {
      if ($argument -notmatch '[\s"]') {
        return $argument
      }
      return '"' + ($argument -replace '"', '\"') + '"'
    }
    function Invoke-SmokeProcess($name, [string[]] $command, $expectedCode, $timeoutSeconds) {
      $stdout = Join-Path $script:artifacts ($name + '.stdout.txt')
      $stderr = Join-Path $script:artifacts ($name + '.stderr.txt')
      $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
      $startInfo.FileName = $command[0]
      $startInfo.Arguments = (($command[1..($command.Length - 1)] | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join ' ')
      $startInfo.UseShellExecute = $false
      $startInfo.RedirectStandardOutput = $true
      $startInfo.RedirectStandardError = $true
      $startInfo.CreateNoWindow = $true
      $process = [System.Diagnostics.Process]::Start($startInfo)
      if (-not $process.WaitForExit($timeoutSeconds * 1000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        Set-Content -Path $stdout -Value $process.StandardOutput.ReadToEnd() -Encoding UTF8
        Set-Content -Path $stderr -Value $process.StandardError.ReadToEnd() -Encoding UTF8
        return New-Check $name 'failed' @{ exitCode = $null; expectedExitCode = $expectedCode; timedOut = $true; stdout = $stdout; stderr = $stderr }
      }
      Set-Content -Path $stdout -Value $process.StandardOutput.ReadToEnd() -Encoding UTF8
      Set-Content -Path $stderr -Value $process.StandardError.ReadToEnd() -Encoding UTF8
      $status = if ($process.ExitCode -eq $expectedCode) { 'passed' } else { 'failed' }
      return New-Check $name $status @{ exitCode = $process.ExitCode; expectedExitCode = $expectedCode; stdout = $stdout; stderr = $stderr }
    }
    $script:artifacts = Join-Path $root 'artifacts'
    New-Item -ItemType Directory -Force -Path $script:artifacts | Out-Null
    $checks = @()
    $errors = @()
    $expanded = Join-Path $root 'expanded'
    Expand-Archive -LiteralPath $zipPath -DestinationPath $expanded -Force
    $appRoot = Join-Path $expanded 'eMuleBB'
    $exe = Join-Path $appRoot 'emulebb.exe'
    if (-not (Test-Path -LiteralPath $exe)) {
      $errors += 'Package did not contain eMuleBB\emulebb.exe.'
    } else {
      $checks += Invoke-SmokeProcess 'help' @($exe, '--help') 0 30
      $checks += Invoke-SmokeProcess 'unknown-switch' @($exe, '--not-a-real-emulebb-switch') 2 30
      $certDir = Join-Path $script:artifacts 'generated-cert'
      New-Item -ItemType Directory -Force -Path $certDir | Out-Null
      $checks += Invoke-SmokeProcess 'generate-webserver-cert' @(
        $exe,
        '--generate-webserver-cert',
        '--cert', (Join-Path $certDir 'webserver.crt'),
        '--key', (Join-Path $certDir 'webserver.key'),
        '--host', '127.0.0.1'
      ) 0 60
      $profile = Join-Path $root 'profile'
      $configDir = Join-Path $profile 'config'
      New-Item -ItemType Directory -Force -Path $configDir | Out-Null
      New-Item -ItemType Directory -Force -Path (Join-Path $profile 'incoming') | Out-Null
      New-Item -ItemType Directory -Force -Path (Join-Path $profile 'temp') | Out-Null
      @"
[eMule]
ConfirmExit=0
IncomingDir=$(Join-Path $profile 'incoming')
TempDir=$(Join-Path $profile 'temp')
BindAddr=
BindInterface=
NetworkED2K=0
NetworkKademlia=0
[WebServer]
Enabled=1
ApiKey=vm-smoke-api-key
Port=4711
BindAddr=127.0.0.1
UseHTTPS=0
[UPnP]
EnableUPnP=0
"@ | Set-Content -Path (Join-Path $configDir 'preferences.ini') -Encoding Unicode
      $appProcess = Start-Process -FilePath $exe -ArgumentList @('-ignoreinstances', '-c', $profile) -PassThru
      $restStatus = 'failed'
      try {
        $restDeadline = (Get-Date).AddSeconds(90)
        do {
          Start-Sleep -Seconds 2
          try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:4711/api/v1/status' -Headers @{ 'X-API-Key' = 'vm-smoke-api-key' } -TimeoutSec 5
            if ($response.StatusCode -eq 200) {
              $restStatus = 'passed'
              break
            }
          } catch {
          }
        } while ((Get-Date) -lt $restDeadline)
      } finally {
        Stop-Process -Id $appProcess.Id -Force -ErrorAction SilentlyContinue
      }
      $checks += New-Check 'first-run-rest-status' $restStatus @{ profile = $profile; url = 'http://127.0.0.1:4711/api/v1/status' }
    }
    $eventLogPath = Join-Path $script:artifacts 'application-events.json'
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = (Get-Date).AddHours(-2) } -MaxEvents 50 |
      Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message |
      ConvertTo-Json -Depth 4 | Set-Content -Path $eventLogPath -Encoding UTF8
    $guest = @{
      computerName = $env:COMPUTERNAME
      os = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber)
    }
    $status = if ($errors.Count -eq 0 -and (@($checks) | Where-Object { $_.status -ne 'passed' }).Count -eq 0) { 'passed' } else { 'failed' }
    $result = [pscustomobject]@{
      schema = 'emulebb.windows-vm-target-result.v1'
      status = $status
      generatedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
      guest = $guest
      packageZip = $zipPath
      appExe = $exe
      checks = $checks
      errors = $errors
      artifactsDir = $script:artifacts
    }
    $result | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $root 'target-result.json') -Encoding UTF8
    $result
  } -ArgumentList $guestRoot, $guestZip
  New-Item -ItemType Directory -Force -Path $payload.hostReportDir | Out-Null
  Copy-Item -FromSession $session -Path (Join-Path $guestRoot '*') -Destination $payload.hostReportDir -Recurse -Force
  $guestResult | ConvertTo-Json -Depth 8
}
finally {
  if ($session) { Remove-PSSession $session }
  if (-not $payload.keepRunning) {
    Stop-VM -Name $payload.vmName -Force
    Restore-VMSnapshot -VMName $payload.vmName -Name $payload.checkpointName -Confirm:$false
  }
}
"""


def local_ed2k_transfer_script() -> str:
    """Returns a minimal PowerShell Direct shim for the Python VM transfer runner."""

    return r"""
$ErrorActionPreference = 'Stop'
$secure = ConvertTo-SecureString $payload.password -AsPlainText -Force
$credential = [pscredential]::new($payload.username, $secure)
$targets = @($payload.win10, $payload.win11)
$sessions = @{}
$roots = @{}
$results = @{}
$pythons = @{}
$runners = @{}
$packageZips = @{}

function Wait-GuestSession($vmName) {
  $deadline = (Get-Date).AddMinutes(10)
  do {
    Start-Sleep -Seconds 3
    try {
      return New-PSSession -VMName $vmName -Credential $credential -ErrorAction Stop
    } catch {
      if ((Get-Date) -gt $deadline) { throw }
    }
  } while ($true)
}

function Restore-Guest($target) {
  $vm = Get-VM -Name $target.vmName -ErrorAction Stop
  if ($vm.State -ne 'Off') {
    Stop-VM -Name $target.vmName -TurnOff -Force
  }
  $snapshot = Get-VMSnapshot -VMName $target.vmName -Name $payload.checkpointName -ErrorAction Stop
  Restore-VMSnapshot -VMSnapshot $snapshot -Confirm:$false
  Start-VM -Name $target.vmName
  return Wait-GuestSession $target.vmName
}

function Invoke-GuestPython($session, $python, $runner, [string[]] $arguments) {
  $stdout = Invoke-Command -Session $session -ScriptBlock {
    param($python, $runner, [string[]] $arguments)
    $output = & $python $runner @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
      throw ('guest python failed with exit code ' + $LASTEXITCODE + ":`n" + (($output | ForEach-Object { $_.ToString() }) -join "`n"))
    }
    $output
  } -ArgumentList $python, $runner, $arguments
  return ($stdout -join "`n") | ConvertFrom-Json
}

function Ensure-GuestPython($session) {
  return Invoke-Command -Session $session -ScriptBlock {
    $candidates = @(
      'C:\Python313\python.exe',
      'C:\Python312\python.exe',
      'C:\Program Files\Python313\python.exe',
      'C:\Program Files\Python312\python.exe'
    )
    foreach ($candidate in $candidates) {
      if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        & $candidate -m pip --version | Out-Null
        return $candidate
      }
    }
    $command = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($command) {
      & $command.Source -m pip --version | Out-Null
      return $command.Source
    }
    throw 'Python with pip is not installed in the guest. Re-run vm-lab prepare to install the guest baseline.'
  }
}

try {
  foreach ($target in $targets) {
    $session = Restore-Guest $target
    $sessions[$target.target] = $session
    $root = 'C:\eMuleBBVmTest\' + $payload.runId + '\' + $target.target
    $roots[$target.target] = $root
    Invoke-Command -Session $session -ScriptBlock {
      param($root)
      if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
      New-Item -ItemType Directory -Force -Path $root | Out-Null
    } -ArgumentList $root
    $python = Ensure-GuestPython $session
    $guestZip = Join-Path $root (Split-Path -Leaf $payload.packageZip)
    $guestRunner = Join-Path $root 'windows_vm_local_ed2k.py'
    $guestProfiles = Join-Path $root 'vm_guest_profiles.py'
    Copy-Item -ToSession $session -Path $payload.packageZip -Destination $guestZip
    Copy-Item -ToSession $session -Path $payload.runnerPath -Destination $guestRunner
    Copy-Item -ToSession $session -Path $payload.profileHelperPath -Destination $guestProfiles
    if ($target.target -eq 'win10') {
      Copy-Item -ToSession $session -Path $payload.serverExe -Destination (Join-Path $root 'goed2k-server.exe')
    }
    $pythons[$target.target] = $python
    $runners[$target.target] = $guestRunner
    $packageZips[$target.target] = $guestZip
  }

  foreach ($target in $targets) {
    $args = @(
      'prepare-client',
      '--root', $roots[$target.target],
      '--target', $target.target,
      '--package-zip', $packageZips[$target.target],
      '--username', $payload.username,
      '--password', $payload.password,
      '--tcp-port', [string] $target.tcpPort,
      '--udp-port', [string] $target.udpPort,
      '--rest-port', [string] $target.restPort,
      '--api-key', $payload.apiKey,
      '--fixture-size-bytes', [string] $payload.fixtureSizeBytes
    )
    if ($target.target -eq 'win10') {
      $args += @('--server-exe', (Join-Path $roots[$target.target] 'goed2k-server.exe'), '--admin-token', $payload.adminToken)
    }
    $results[$target.target] = Invoke-GuestPython $sessions[$target.target] $pythons[$target.target] $runners[$target.target] $args
  }

  $server = Invoke-GuestPython $sessions['win10'] $pythons['win10'] $runners['win10'] @(
    'start-server',
    '--root', $roots['win10'],
    '--admin-token', $payload.adminToken
  )
  $serverAddress = $results['win10'].guest.ipv4

  foreach ($target in $targets) {
    $results[$target.target].checks += Invoke-GuestPython $sessions[$target.target] $pythons[$target.target] $runners[$target.target] @(
      'wait-rest',
      '--base-url', $results[$target.target].restBaseUrl,
      '--api-key', $payload.apiKey
    )
    $results[$target.target].checks += Invoke-GuestPython $sessions[$target.target] $pythons[$target.target] $runners[$target.target] @(
      'add-connect-server',
      '--base-url', $results[$target.target].restBaseUrl,
      '--api-key', $payload.apiKey,
      '--server-address', $serverAddress,
      '--server-port', '4661'
    )
    $results[$target.target].checks += Invoke-GuestPython $sessions[$target.target] $pythons[$target.target] $runners[$target.target] @(
      'wait-server-connected',
      '--base-url', $results[$target.target].restBaseUrl,
      '--api-key', $payload.apiKey
    )
  }

  $links = @{}
  foreach ($target in $targets) {
    $links[$target.target] = Invoke-GuestPython $sessions[$target.target] $pythons[$target.target] $runners[$target.target] @(
      'shared-link',
      '--base-url', $results[$target.target].restBaseUrl,
      '--api-key', $payload.apiKey,
      '--name', $results[$target.target].sample.name,
      '--path', $results[$target.target].sample.path
    )
    $results[$target.target].checks += $links[$target.target]
  }

  foreach ($target in $targets) {
    $results[$target.target].checks += Invoke-GuestPython $sessions[$target.target] $pythons[$target.target] $runners[$target.target] @(
      'wait-shared-stable',
      '--base-url', $results[$target.target].restBaseUrl,
      '--api-key', $payload.apiKey,
      '--settle-seconds', '10'
    )
  }

  $results['win10'].checks += Invoke-GuestPython $sessions['win10'] $pythons['win10'] $runners['win10'] @(
    'add-transfer',
    '--base-url', $results['win10'].restBaseUrl,
    '--api-key', $payload.apiKey,
    '--link', $links['win11'].link,
    '--source-address', $results['win11'].guest.ipv4,
    '--source-port', [string] $payload.win11.tcpPort
  )
  $results['win11'].checks += Invoke-GuestPython $sessions['win11'] $pythons['win11'] $runners['win11'] @(
    'add-transfer',
    '--base-url', $results['win11'].restBaseUrl,
    '--api-key', $payload.apiKey,
    '--link', $links['win10'].link,
    '--source-address', $results['win10'].guest.ipv4,
    '--source-port', [string] $payload.win10.tcpPort
  )

  $results['win10'].checks += Invoke-GuestPython $sessions['win10'] $pythons['win10'] $runners['win10'] @(
    'wait-completed',
    '--incoming-dir', $results['win10'].incomingDir,
    '--name', $results['win11'].sample.name,
    '--size', [string] $results['win11'].sample.size,
    '--sha256', $results['win11'].sample.sha256
  )
  $results['win11'].checks += Invoke-GuestPython $sessions['win11'] $pythons['win11'] $runners['win11'] @(
    'wait-completed',
    '--incoming-dir', $results['win11'].incomingDir,
    '--name', $results['win10'].sample.name,
    '--size', [string] $results['win10'].sample.size,
    '--sha256', $results['win10'].sample.sha256
  )

  foreach ($target in $targets) {
    $results[$target.target].status = 'passed'
  }
  [pscustomobject]@{
    schema = 'emulebb.windows-vm-local-ed2k-transfer-result.v1'
    status = 'passed'
    generatedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    server = $server
    links = $links
    targets = $results
  } | ConvertTo-Json -Depth 12
}
catch {
  [pscustomobject]@{
    schema = 'emulebb.windows-vm-local-ed2k-transfer-result.v1'
    status = 'failed'
    generatedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    error = @{ type = $_.Exception.GetType().FullName; message = $_.Exception.Message }
    targets = $results
  } | ConvertTo-Json -Depth 12
}
finally {
  foreach ($target in $targets) {
    $session = $sessions[$target.target]
    if ($session) {
      try {
        if (-not $payload.keepRunning) {
          Invoke-GuestPython $session $pythons[$target.target] $runners[$target.target] @('stop-runtime') | Out-Null
        }
        $destination = Join-Path $payload.hostReportDir $target.target
        New-Item -ItemType Directory -Force -Path $destination | Out-Null
        Copy-Item -FromSession $session -Path (Join-Path $roots[$target.target] '*') -Destination $destination -Recurse -Force
      } catch {
      }
      Remove-PSSession $session -ErrorAction SilentlyContinue
    }
    if (-not $payload.keepRunning) {
      Stop-VM -Name $target.vmName -Force -ErrorAction SilentlyContinue
      Restore-VMSnapshot -VMName $target.vmName -Name $payload.checkpointName -Confirm:$false -ErrorAction SilentlyContinue
    }
  }
}
"""


def profile_smoke_script() -> str:
    """Returns a PowerShell Direct shim for single-VM profile smoke runners."""

    return r"""
$ErrorActionPreference = 'Stop'
$secure = ConvertTo-SecureString $payload.password -AsPlainText -Force
$credential = [pscredential]::new($payload.username, $secure)
$vm = Get-VM -Name $payload.vmName -ErrorAction Stop
if ($payload.switchName) {
  Connect-VMNetworkAdapter -VMName $payload.vmName -SwitchName $payload.switchName
}
if ($vm.State -ne 'Off') {
  Stop-VM -Name $payload.vmName -TurnOff -Force
}
$snapshot = Get-VMSnapshot -VMName $payload.vmName -Name $payload.checkpointName -ErrorAction Stop
Restore-VMSnapshot -VMSnapshot $snapshot -Confirm:$false
if ($payload.switchName) {
  Connect-VMNetworkAdapter -VMName $payload.vmName -SwitchName $payload.switchName
}
Start-VM -Name $payload.vmName

function Wait-GuestSession($vmName) {
  $deadline = (Get-Date).AddMinutes(10)
  do {
    Start-Sleep -Seconds 3
    try {
      return New-PSSession -VMName $vmName -Credential $credential -ErrorAction Stop
    } catch {
      if ((Get-Date) -gt $deadline) { throw }
    }
  } while ($true)
}

function Ensure-GuestPython($session) {
  return Invoke-Command -Session $session -ScriptBlock {
    $candidates = @(
      'C:\Python313\python.exe',
      'C:\Python312\python.exe',
      'C:\Program Files\Python313\python.exe',
      'C:\Program Files\Python312\python.exe'
    )
    foreach ($candidate in $candidates) {
      if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        & $candidate -m pip --version | Out-Null
        return $candidate
      }
    }
    $command = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($command) {
      & $command.Source -m pip --version | Out-Null
      return $command.Source
    }
    throw 'Python with pip is not installed in the guest. Re-run vm-lab prepare to install the guest baseline.'
  }
}

function Invoke-GuestPython($session, $python, $runner, [string[]] $arguments, [string[]] $pythonPath = @()) {
  $stdout = Invoke-Command -Session $session -ScriptBlock {
    param($python, $runner, [string[]] $arguments, [string[]] $pythonPath)
    $previousPythonPath = $env:PYTHONPATH
    try {
      if ($pythonPath.Count -gt 0) {
        $env:PYTHONPATH = (($pythonPath + @($previousPythonPath)) | Where-Object { $_ }) -join [System.IO.Path]::PathSeparator
      }
      $output = & $python $runner @arguments 2>&1
      if ($LASTEXITCODE -ne 0) {
        throw ('guest python failed with exit code ' + $LASTEXITCODE + ":`n" + (($output | ForEach-Object { $_.ToString() }) -join "`n"))
      }
      $output
    } finally {
      $env:PYTHONPATH = $previousPythonPath
    }
  } -ArgumentList $python, $runner, $arguments, $pythonPath
  $jsonText = $stdout -join "`n"
  try {
    return $jsonText | ConvertFrom-Json
  } catch {
    throw ("guest python produced invalid JSON:`n" + $jsonText)
  }
}

function Copy-GuestArtifacts($session, $sourceRoot, $destination) {
  $snapshotRoot = $sourceRoot + '-artifact-snapshot'
  Invoke-Command -Session $session -ScriptBlock {
    param($sourceRoot, $snapshotRoot)
    if (Test-Path -LiteralPath $snapshotRoot) {
      Remove-Item -LiteralPath $snapshotRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $snapshotRoot | Out-Null
    $errors = @()
    Get-ChildItem -LiteralPath $sourceRoot -Force -Recurse | ForEach-Object {
      $relative = $_.FullName.Substring($sourceRoot.Length).TrimStart('\')
      $target = Join-Path $snapshotRoot $relative
      if ($_.PSIsContainer) {
        New-Item -ItemType Directory -Force -Path $target | Out-Null
        return
      }
      New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
      $sourceStream = $null
      $targetStream = $null
      try {
        $sourceStream = [System.IO.FileStream]::new(
          $_.FullName,
          [System.IO.FileMode]::Open,
          [System.IO.FileAccess]::Read,
          ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
        )
        $targetStream = [System.IO.FileStream]::new(
          $target,
          [System.IO.FileMode]::Create,
          [System.IO.FileAccess]::Write,
          [System.IO.FileShare]::None
        )
        $sourceStream.CopyTo($targetStream)
      } catch {
        $errors += [pscustomobject]@{ path = $_.FullName; error = $_.Exception.Message }
      } finally {
        if ($targetStream) { $targetStream.Dispose() }
        if ($sourceStream) { $sourceStream.Dispose() }
      }
    }
    if ($errors.Count -gt 0) {
      $errors | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $snapshotRoot 'artifact-copy-errors.json') -Encoding UTF8
      throw ('Failed to snapshot {0} guest artifact file(s).' -f $errors.Count)
    }
  } -ArgumentList $sourceRoot, $snapshotRoot
  try {
    for ($attempt = 1; $attempt -le 15; $attempt++) {
      try {
        Copy-Item -FromSession $session -Path (Join-Path $snapshotRoot '*') -Destination $destination -Recurse -Force
        return
      } catch {
        if ($attempt -eq 15) { throw }
        Start-Sleep -Seconds 3
      }
    }
  } finally {
    Invoke-Command -Session $session -ScriptBlock {
      param($snapshotRoot)
      if (Test-Path -LiteralPath $snapshotRoot) {
        Remove-Item -LiteralPath $snapshotRoot -Recurse -Force -ErrorAction SilentlyContinue
      }
    } -ArgumentList $snapshotRoot
  }
}

function Stop-GuestRuntime($session) {
  Invoke-Command -Session $session -ScriptBlock {
    Get-Process -Name emulebb -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName 'eMuleBB VM*' -ErrorAction SilentlyContinue |
      Stop-ScheduledTask -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
  }
}

$session = $null
$guestRoot = 'C:\eMuleBBVmTest\' + $payload.runId + '\' + $payload.target
$guestRunRoot = Split-Path -Parent $guestRoot
$guestZip = Join-Path $guestRoot (Split-Path -Leaf $payload.packageZip)
$guestRunner = Join-Path $guestRoot 'windows_vm_profile_smoke.py'
$guestProfiles = Join-Path $guestRoot 'vm_guest_profiles.py'
$guestCampaignScenarios = Join-Path $guestRoot 'campaign_scenarios.py'
$guestHarnessRoot = Join-Path $guestRoot 'harness'
$guestHarnessPackage = Join-Path $guestHarnessRoot 'emule_test_harness'
$guestHarnessManifests = Join-Path $guestHarnessRoot 'manifests'
$guestScriptsRoot = Join-Path $guestHarnessRoot 'scripts'
$guestToolsRoot = Join-Path $guestHarnessRoot 'tools'
$guestGoed2kServer = Join-Path $guestToolsRoot 'goed2k-server.exe'
$guestClient2Root = Join-Path $guestToolsRoot 'tracing-harness'
$guestClient2App = Join-Path $guestClient2Root 'emule.exe'
$guestAmuleBinRoot = Join-Path $guestToolsRoot 'amule\bin'
$guestAmuleDaemon = Join-Path $guestAmuleBinRoot 'amuled.exe'
$guestAmuleControl = Join-Path $guestAmuleBinRoot 'amulecmd.exe'
$guestToolingRestRoot = Join-Path $guestRoot 'emulebb-tooling\docs\rest'
$guestAppSourceRoot = Join-Path $guestRunRoot 'workspaces\workspace\app\emulebb-main\srchybrid'
try {
  $session = Wait-GuestSession $payload.vmName
  Invoke-Command -Session $session -ScriptBlock {
    param($root)
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $root | Out-Null
  } -ArgumentList $guestRoot
  $python = Ensure-GuestPython $session
  Copy-Item -ToSession $session -Path $payload.packageZip -Destination $guestZip
  Copy-Item -ToSession $session -Path $payload.runnerPath -Destination $guestRunner
  Copy-Item -ToSession $session -Path $payload.profileHelperPath -Destination $guestProfiles
  Copy-Item -ToSession $session -Path (Join-Path (Split-Path -Parent $payload.profileHelperPath) 'campaign_scenarios.py') -Destination $guestCampaignScenarios
  Invoke-Command -Session $session -ScriptBlock {
    param($harnessRoot, $scriptsRoot, $toolsRoot)
    New-Item -ItemType Directory -Force -Path $harnessRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $scriptsRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $toolsRoot | Out-Null
  } -ArgumentList $guestHarnessRoot, $guestScriptsRoot, $guestToolsRoot
  Copy-Item -ToSession $session -Path $payload.localSwarmHarnessPackagePath -Destination $guestHarnessPackage -Recurse -Force
  if ($payload.localSwarmManifestsPath) {
    Copy-Item -ToSession $session -Path $payload.localSwarmManifestsPath -Destination $guestHarnessManifests -Recurse -Force
  }
  foreach ($scriptPath in @($payload.localSwarmScriptPaths)) {
    Copy-Item -ToSession $session -Path $scriptPath -Destination (Join-Path $guestScriptsRoot (Split-Path -Leaf $scriptPath)) -Force
  }
  if ($payload.localSwarmRestOpenApiPath) {
    Invoke-Command -Session $session -ScriptBlock {
      param($root)
      New-Item -ItemType Directory -Force -Path $root | Out-Null
    } -ArgumentList $guestToolingRestRoot
    Copy-Item -ToSession $session -Path $payload.localSwarmRestOpenApiPath -Destination (Join-Path $guestToolingRestRoot 'REST-API-OPENAPI.yaml') -Force
  }
  if ($payload.localSwarmAppSourcePaths) {
    Invoke-Command -Session $session -ScriptBlock {
      param($root)
      New-Item -ItemType Directory -Force -Path $root | Out-Null
    } -ArgumentList $guestAppSourceRoot
    foreach ($sourcePath in @($payload.localSwarmAppSourcePaths)) {
      Copy-Item -ToSession $session -Path $sourcePath -Destination (Join-Path $guestAppSourceRoot (Split-Path -Leaf $sourcePath)) -Force
    }
  }
  if ($payload.localSwarmGoed2kServerExe) {
    Copy-Item -ToSession $session -Path $payload.localSwarmGoed2kServerExe -Destination $guestGoed2kServer -Force
  }
  if ($payload.localSwarmClient2AppExe) {
    Invoke-Command -Session $session -ScriptBlock {
      param($root)
      New-Item -ItemType Directory -Force -Path $root | Out-Null
    } -ArgumentList $guestClient2Root
    Copy-Item -ToSession $session -Path $payload.localSwarmClient2AppExe -Destination $guestClient2App -Force
  }
  if ($payload.localSwarmAmuleDaemonExe -or $payload.localSwarmAmuleControlExe) {
    Invoke-Command -Session $session -ScriptBlock {
      param($root)
      New-Item -ItemType Directory -Force -Path $root | Out-Null
    } -ArgumentList $guestAmuleBinRoot
  }
  if ($payload.localSwarmAmuleDaemonExe) {
    Copy-Item -ToSession $session -Path $payload.localSwarmAmuleDaemonExe -Destination $guestAmuleDaemon -Force
  }
  if ($payload.localSwarmAmuleControlExe) {
    Copy-Item -ToSession $session -Path $payload.localSwarmAmuleControlExe -Destination $guestAmuleControl -Force
  }
  $runnerArgs = @(
    '--profile', $payload.profileName,
    '--root', $guestRoot,
    '--target', $payload.target,
    '--package-zip', $guestZip,
    '--username', $payload.username,
    '--password', $payload.password,
    '--fixture-size-bytes', [string] $payload.fixtureSizeBytes,
    '--swarm-tier', [string] $payload.swarmTier,
    '--local-swarm-mode', $payload.localSwarmMode,
    '--harness-root', $guestHarnessRoot
  )
  if ($payload.localSwarmGoed2kServerExe) {
    $runnerArgs += @('--ed2k-server-exe', $guestGoed2kServer)
  }
  if ($payload.localSwarmClient2AppExe) {
    $runnerArgs += @('--client2-app-exe', $guestClient2App)
  }
  if ($payload.localSwarmAmuleDaemonExe) {
    $runnerArgs += @('--amule-daemon-exe', $guestAmuleDaemon)
  }
  if ($payload.localSwarmAmuleControlExe) {
    $runnerArgs += @('--amule-control-exe', $guestAmuleControl)
  }
  $guestResult = Invoke-GuestPython $session $python $guestRunner $runnerArgs @($guestHarnessRoot, $guestRoot)
  New-Item -ItemType Directory -Force -Path $payload.hostReportDir | Out-Null
  Stop-GuestRuntime $session
  Copy-GuestArtifacts $session $guestRoot $payload.hostReportDir
  $guestResult | ConvertTo-Json -Depth 12
}
finally {
  if ($session) { Remove-PSSession $session }
  if (-not $payload.keepRunning) {
    Stop-VM -Name $payload.vmName -Force -ErrorAction SilentlyContinue
    Restore-VMSnapshot -VMName $payload.vmName -Name $payload.checkpointName -Confirm:$false -ErrorAction SilentlyContinue
  }
}
"""


def hideme_live_wire_script() -> str:
    """Returns a PowerShell Direct shim for the Python hide.me live-wire runner."""

    return r"""
$ErrorActionPreference = 'Stop'
$secure = ConvertTo-SecureString $payload.password -AsPlainText -Force
$credential = [pscredential]::new($payload.username, $secure)
$targets = @($payload.win10, $payload.win11)
$sessions = @{}
$roots = @{}
$results = @{}
$pythons = @{}
$runners = @{}
$packageZips = @{}

function Wait-GuestSession($vmName) {
  $deadline = (Get-Date).AddMinutes(10)
  do {
    Start-Sleep -Seconds 3
    try {
      return New-PSSession -VMName $vmName -Credential $credential -ErrorAction Stop
    } catch {
      if ((Get-Date) -gt $deadline) { throw }
    }
  } while ($true)
}

function Restore-Guest($target) {
  $vm = Get-VM -Name $target.vmName -ErrorAction Stop
  if ($payload.vpnSwitchName) {
    Connect-VMNetworkAdapter -VMName $target.vmName -SwitchName $payload.vpnSwitchName
  }
  if ($vm.State -ne 'Off') {
    Stop-VM -Name $target.vmName -TurnOff -Force
  }
  $snapshot = Get-VMSnapshot -VMName $target.vmName -Name $payload.checkpointName -ErrorAction Stop
  Restore-VMSnapshot -VMSnapshot $snapshot -Confirm:$false
  if ($payload.vpnSwitchName) {
    Connect-VMNetworkAdapter -VMName $target.vmName -SwitchName $payload.vpnSwitchName
  }
  Start-VM -Name $target.vmName
  return Wait-GuestSession $target.vmName
}

function Invoke-GuestPython($session, $python, $runner, [string[]] $arguments) {
  $stdout = Invoke-Command -Session $session -ScriptBlock {
    param($python, $runner, [string[]] $arguments)
    $output = & $python $runner @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
      throw ('guest python failed with exit code ' + $LASTEXITCODE + ":`n" + (($output | ForEach-Object { $_.ToString() }) -join "`n"))
    }
    $output
  } -ArgumentList $python, $runner, $arguments
  return ($stdout -join "`n") | ConvertFrom-Json
}

function Ensure-GuestPython($session) {
  return Invoke-Command -Session $session -ScriptBlock {
    $candidates = @(
      'C:\Python313\python.exe',
      'C:\Python312\python.exe',
      'C:\Program Files\Python313\python.exe',
      'C:\Program Files\Python312\python.exe'
    )
    foreach ($candidate in $candidates) {
      if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        & $candidate -m pip --version | Out-Null
        return $candidate
      }
    }
    $command = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($command) {
      & $command.Source -m pip --version | Out-Null
      return $command.Source
    }
    throw 'Python with pip is not installed in the guest. Re-run vm-lab prepare to install the guest baseline.'
  }
}

function Start-HideMe($session) {
  Invoke-Command -Session $session -ScriptBlock {
    $ErrorActionPreference = 'Stop'
    $serviceExe = 'C:\Program Files (x86)\hide.me VPN\hidemesvc.exe'
    $appExe = 'C:\Program Files (x86)\hide.me VPN\Hide.me.exe'
    if (-not (Test-Path -LiteralPath $serviceExe -PathType Leaf)) {
      throw ('hide.me service executable is missing: ' + $serviceExe)
    }
    if (-not (Test-Path -LiteralPath $appExe -PathType Leaf)) {
      throw ('hide.me app executable is missing: ' + $appExe)
    }
    if (-not (Get-Service -Name hmevpnsvc -ErrorAction SilentlyContinue)) {
      sc.exe create hmevpnsvc binPath= $serviceExe start= auto DisplayName= 'hide.me VPN Service' depend= RasMan | Out-Null
      sc.exe description hmevpnsvc 'Provides network services for hide.me VPN' | Out-Null
    }
    Start-Service -Name hmevpnsvc -ErrorAction SilentlyContinue
    Get-Process -Name 'Hide.me' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    $task = 'eMuleBB Launch hide.me structured'
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute $appExe
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
    $principal = New-ScheduledTaskPrincipal -UserId 'emulebbtest' -RunLevel Highest -LogonType Interactive
    Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $task
  } | Out-Null
}

try {
  foreach ($target in $targets) {
    $session = Restore-Guest $target
    $sessions[$target.target] = $session
    Start-HideMe $session
    $root = 'C:\eMuleBBVmTest\' + $payload.runId + '\' + $target.target
    $roots[$target.target] = $root
    Invoke-Command -Session $session -ScriptBlock {
      param($root)
      if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
      New-Item -ItemType Directory -Force -Path $root | Out-Null
    } -ArgumentList $root
    $python = Ensure-GuestPython $session
    $guestZip = Join-Path $root (Split-Path -Leaf $payload.packageZip)
    $guestRunner = Join-Path $root 'windows_vm_hideme_live.py'
    $guestProfiles = Join-Path $root 'vm_guest_profiles.py'
    Copy-Item -ToSession $session -Path $payload.packageZip -Destination $guestZip
    Copy-Item -ToSession $session -Path $payload.runnerPath -Destination $guestRunner
    Copy-Item -ToSession $session -Path $payload.profileHelperPath -Destination $guestProfiles
    $pythons[$target.target] = $python
    $runners[$target.target] = $guestRunner
    $packageZips[$target.target] = $guestZip
  }

  foreach ($target in $targets) {
    $results[$target.target] = Invoke-GuestPython $sessions[$target.target] $pythons[$target.target] $runners[$target.target] @(
      'prepare-client',
      '--root', $roots[$target.target],
      '--target', $target.target,
      '--package-zip', $packageZips[$target.target],
      '--username', $payload.username,
      '--password', $payload.password,
      '--tcp-port', [string] $target.tcpPort,
      '--udp-port', [string] $target.udpPort,
      '--rest-port', [string] $target.restPort,
      '--api-key', $payload.apiKey
    )
    $results[$target.target].checks += Invoke-GuestPython $sessions[$target.target] $pythons[$target.target] $runners[$target.target] @(
      'wait-rest',
      '--base-url', $results[$target.target].restBaseUrl,
      '--api-key', $payload.apiKey
    )
    $results[$target.target].checks += Invoke-GuestPython $sessions[$target.target] $pythons[$target.target] $runners[$target.target] @(
      'assert-vpn-binding',
      '--base-url', $results[$target.target].restBaseUrl,
      '--api-key', $payload.apiKey
    )
    $results[$target.target].checks += Invoke-GuestPython $sessions[$target.target] $pythons[$target.target] $runners[$target.target] @(
      'import-server-met',
      '--base-url', $results[$target.target].restBaseUrl,
      '--api-key', $payload.apiKey
    )
    $results[$target.target].checks += Invoke-GuestPython $sessions[$target.target] $pythons[$target.target] $runners[$target.target] @(
      'connect-live-server',
      '--base-url', $results[$target.target].restBaseUrl,
      '--api-key', $payload.apiKey
    )
    $results[$target.target].checks += Invoke-GuestPython $sessions[$target.target] $pythons[$target.target] $runners[$target.target] @(
      'live-search',
      '--base-url', $results[$target.target].restBaseUrl,
      '--api-key', $payload.apiKey,
      '--trigger-download'
    )
    $results[$target.target].status = 'passed'
  }

  [pscustomobject]@{
    schema = 'emulebb.windows-vm-hideme-live-wire-result.v1'
    status = 'passed'
    generatedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    targets = $results
  } | ConvertTo-Json -Depth 12
}
catch {
  [pscustomobject]@{
    schema = 'emulebb.windows-vm-hideme-live-wire-result.v1'
    status = 'failed'
    generatedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    error = @{ type = $_.Exception.GetType().FullName; message = $_.Exception.Message }
    targets = $results
  } | ConvertTo-Json -Depth 12
}
finally {
  foreach ($target in $targets) {
    $session = $sessions[$target.target]
    if ($session) {
      try {
        if (-not $payload.keepRunning) {
          Invoke-GuestPython $session $pythons[$target.target] $runners[$target.target] @('stop-runtime') | Out-Null
        }
        $destination = Join-Path $payload.hostReportDir $target.target
        New-Item -ItemType Directory -Force -Path $destination | Out-Null
        Copy-Item -FromSession $session -Path (Join-Path $roots[$target.target] '*') -Destination $destination -Recurse -Force
      } catch {
      }
      Remove-PSSession $session -ErrorAction SilentlyContinue
    }
    if (-not $payload.keepRunning) {
      Stop-VM -Name $target.vmName -Force -ErrorAction SilentlyContinue
      Restore-VMSnapshot -VMName $target.vmName -Name $payload.checkpointName -Confirm:$false -ErrorAction SilentlyContinue
    }
  }
}
"""
