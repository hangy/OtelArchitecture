param(
    [string]$Version = "0.0.0.0",
    [string]$PublishRoot = "artifacts"
)

Write-Host "Package artifacts script starting. PublishRoot=$PublishRoot"

if (-not (Test-Path -Path $PublishRoot)) {
    Write-Host "PublishRoot does not exist: $PublishRoot"; exit 1
}

# Find all published folders matching the pattern created by publish script
$publishedDirs = Get-ChildItem -Path $PublishRoot -Directory | Where-Object { $_.Name -match "^wintokenbridge-" }
if ($publishedDirs.Count -eq 0) {
    Write-Host "No published directories found in $PublishRoot"; exit 1
}

foreach ($dir in $publishedDirs) {
    $name = $dir.Name
    if ($name -match "-fd-") {
        # framework-dependent -> zip
        $zipPath = Join-Path $PublishRoot "$name.zip"
        if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
        Compress-Archive -Path (Join-Path $dir.FullName '*') -DestinationPath $zipPath -Force
        Remove-Item $dir.FullName -Recurse -Force
        Write-Host "Created $zipPath"
    } elseif ($name -match "-sc-") {
        # self-contained -> zip for Windows, tar.gz for linux/osx
        if ($name -match "-win") {
            $zipPath = Join-Path $PublishRoot "$name.zip"
            if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
            Compress-Archive -Path (Join-Path $dir.FullName '*') -DestinationPath $zipPath -Force
            Remove-Item $dir.FullName -Recurse -Force
            Write-Host "Created $zipPath"
        } else {
            # assume unix-like: create tar.gz
            Push-Location $PublishRoot
            $tarGz = "$name.tar.gz"
            if (Test-Path $tarGz) { Remove-Item $tarGz -Force }
            tar -czf $tarGz $name
            Pop-Location
            Remove-Item $dir.FullName -Recurse -Force
            Write-Host "Created $tarGz"
        }
    } else {
        # unknown pattern => zip
        $zipPath = Join-Path $PublishRoot "$name.zip"
        if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
        Compress-Archive -Path (Join-Path $dir.FullName '*') -DestinationPath $zipPath -Force
        Remove-Item $dir.FullName -Recurse -Force
        Write-Host "Created $zipPath (unknown pattern)"
    }
}

Write-Host "Package artifacts script finished. Artifacts created in $PublishRoot"
