param(
    [string]$Version = "0.0.0.0",
    [string]$PublishRoot = "artifacts"
)

Write-Host "Publish artifacts script starting. Version=$Version, PublishRoot=$PublishRoot"

if (Test-Path -Path $PublishRoot) {
    Remove-Item $PublishRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $PublishRoot | Out-Null

$project = "src/AlbusKavaliro.WinTokenBridge/AlbusKavaliro.WinTokenBridge.csproj"
$DirectoryBuildProps = "Directory.Build.props"

try {
    $xml = [xml](Get-Content $DirectoryBuildProps)
    # Build property map from all PropertyGroup children
    $props = @{}
    foreach ($pg in $xml.Project.PropertyGroup) {
        foreach ($child in $pg.ChildNodes) {
            $name = $child.Name
            $value = $child.InnerText
            if (-not [string]::IsNullOrWhiteSpace($value)) { $props[$name] = $value }
        }
    }

    # Collect RuntimeWindows, RuntimeLinux, RuntimeOSX directly
    $parts = @()
    foreach ($k in @('RuntimeWindows', 'RuntimeLinux', 'RuntimeOSX')) {
        if ($props.ContainsKey($k) -and -not [string]::IsNullOrWhiteSpace($props[$k])) {
            $parts += ($props[$k] -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        }
    }

    if ($parts.Count -eq 0) {
        Write-Host "No RuntimeWindows/RuntimeLinux/RuntimeOSX found in $DirectoryBuildProps. Using defaults."
        $rids = @('win-x64', 'linux-x64')
    }
    else {
        $rids = $parts | Select-Object -Unique
    }
}
catch {
    Write-Host "Failed to parse ${DirectoryBuildProps}: $_. Exception. Using defaults."
    $rids = @('win-x64', 'linux-x64')
}

Write-Host "Target RIDs: $($rids -join ', ')"

foreach ($rid in $rids) {
    if ([string]::IsNullOrWhiteSpace($rid)) { continue }
    $rid = $rid.Trim()

    $ridIsWindows = $rid -like 'win*'
    $ridIsLinux = $rid -like 'linux*'
    $ridIsOsx = $rid -like 'osx*'

    if ($ridIsWindows) {
        # framework-dependent (FD)
        $outFd = Join-Path $PublishRoot "wintokenbridge-$Version-fd-$rid"
        Write-Host "Publishing FD for $rid -> $outFd"
        dotnet publish $Project -c Release -o $outFd -r $rid --no-self-contained -p:Version=$Version --no-restore

        # self-contained (SC)
        $outSc = Join-Path $PublishRoot "wintokenbridge-$Version-sc-$rid"
        Write-Host "Publishing SC for $rid -> $outSc"
        # For ASP.NET Core web projects AOT + PublishTrimmed may not produce a platform exe host.
        # Enable `UseAppHost=true` for Windows to ensure an .exe is produced. Avoid AOT and trimming for web projects.
        if ($ridIsWindows) {
            dotnet publish $Project -c Release -o $outSc -r $rid --self-contained true -p:Version=$Version -p:UseAppHost=true -p:PublishTrimmed=false -p:PublishAot=false --no-restore
        }
        else {
            dotnet publish $Project -c Release -o $outSc -r $rid --self-contained true -p:Version=$Version -p:PublishTrimmed=false -p:PublishAot=false --no-restore
        }
    }
    elseif ($ridIsLinux -or $ridIsOsx) {
        # for non-windows produce self-contained builds (portable)
        $outSc = Join-Path $PublishRoot "wintokenbridge-$Version-sc-$rid"
        Write-Host "Publishing SC for $rid -> $outSc"
        dotnet publish $Project -c Release -o $outSc -r $rid --self-contained true -p:Version=$Version -p:PublishTrimmed=false -p:PublishAot=false --no-restore
    }
    else {
        # unknown platform: produce self-contained by default
        $outSc = Join-Path $PublishRoot "wintokenbridge-$Version-sc-$rid"
        Write-Host "Publishing SC for unknown RID $rid -> $outSc"
        dotnet publish $Project -c Release -o $outSc -r $rid --self-contained true -p:Version=$Version -p:PublishTrimmed=false -p:PublishAot=false --no-restore
    }
}

Write-Host "Publish artifacts script finished."
