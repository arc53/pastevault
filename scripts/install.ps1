$ErrorActionPreference = "Stop"

$Repo = if ($env:PASTEVAULT_INSTALL_REPO) { $env:PASTEVAULT_INSTALL_REPO } else { "arc53/pastevault" }
$Version = if ($env:PASTEVAULT_INSTALL_VERSION) { $env:PASTEVAULT_INSTALL_VERSION } else { "latest" }
$InstallDir = if ($env:PASTEVAULT_INSTALL_DIR) { $env:PASTEVAULT_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Programs\PasteVault\bin" }

switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
  "X64" { $Arch = "x86_64" }
  "Arm64" { $Arch = "arm64" }
  default { throw "Unsupported architecture: $([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)" }
}

$ArchiveName = "pastevault_windows_$Arch.zip"
$ChecksumsName = "checksums.txt"

if ($Version -eq "latest") {
  $ArchiveUrl = "https://github.com/$Repo/releases/latest/download/$ArchiveName"
  $ChecksumsUrl = "https://github.com/$Repo/releases/latest/download/$ChecksumsName"
} else {
  $ArchiveUrl = "https://github.com/$Repo/releases/download/$Version/$ArchiveName"
  $ChecksumsUrl = "https://github.com/$Repo/releases/download/$Version/$ChecksumsName"
}

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("pastevault-install-" + [guid]::NewGuid())
$ArchivePath = Join-Path $TempDir $ArchiveName
$ChecksumsPath = Join-Path $TempDir $ChecksumsName
$ExtractDir = Join-Path $TempDir "extract"

New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
New-Item -ItemType Directory -Force -Path $ExtractDir | Out-Null

try {
  Write-Host "Downloading $ArchiveName..."
  Invoke-WebRequest -Uri $ArchiveUrl -OutFile $ArchivePath
  Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $ChecksumsPath

  $ExpectedHash = Select-String -Path $ChecksumsPath -Pattern ([regex]::Escape($ArchiveName) + "$") | ForEach-Object {
    ($_ -split "\s+")[0]
  }

  if (-not $ExpectedHash) {
    throw "Failed to find checksum for $ArchiveName"
  }

  $ActualHash = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($ActualHash -ne $ExpectedHash.ToLowerInvariant()) {
    throw "Checksum verification failed for $ArchiveName"
  }

  Expand-Archive -Path $ArchivePath -DestinationPath $ExtractDir -Force
  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  Copy-Item -Path (Join-Path $ExtractDir "pastevault.exe") -Destination (Join-Path $InstallDir "pastevault.exe") -Force

  $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
  $PathEntries = @()
  if ($UserPath) {
    $PathEntries = $UserPath -split ";" | Where-Object { $_ -ne "" }
  }

  if ($PathEntries -notcontains $InstallDir) {
    $NewPath = ($PathEntries + $InstallDir) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    Write-Host "Added $InstallDir to the user PATH."
  }

  Write-Host "Installed pastevault to $(Join-Path $InstallDir 'pastevault.exe')"
} finally {
  if (Test-Path $TempDir) {
    Remove-Item -Recurse -Force $TempDir
  }
}
