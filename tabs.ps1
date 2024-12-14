# Detect version of PowerShell
$posh = "powershell.exe" # PowerShell Core 5
if ($PSVersionTable.PSVersion.Major -eq 7) {
    $posh = "pwsh.exe" # PowerShell Core 7
}

# Recreate Docker containers
$cmd = {
    docker-compose down --timeout 0 --rmi local;
    docker-compose up --build -d;
    Write-Output "`r`nRun the command below in the attacker shell:`r`n  python attacker.py";
}
& $cmd

# Enter attacker's shell
$enter_bash = "docker-compose exec attacker bash"
if (Get-Command "wt" -ErrorAction SilentlyContinue) {
    wt new-tab -d $PSScriptRoot --title attacker -- $posh -NoExit -c $enter_bash
}
else {
    Invoke-Expression $enter_bash
}
