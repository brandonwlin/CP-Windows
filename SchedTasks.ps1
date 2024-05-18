powershell.exe -noprofile -executionpolicy bypass -file "%~dp0\SchedTasks.ps1"
# Getting Scheduled Tasks
Get-ScheduledTask | Select-Object TaskName | Set-Content -Encoding UTF8 .\DataFiles\SchedTasks.txt

# Sorting SchedTasks.txt
Get-Content .\DataFiles\SchedTasks.txt | Sort-Object | Get-Unique | Set-Content -Encoding UTF8 .\DataFiles\passthrough.txt
Get-Content .\DataFiles\passthrough.txt | Set-Content -Encoding UTF8 .\DataFiles\SchedTasks.txt

# Getting useless crap out of SchedTasks.txt
$lines = Get-Content .\DataFiles\SchedTasks.txt

for ($i=0; $i -lt $lines.Length; $i++) {
    $lines[$i] = $lines[$i].Substring(11)
    $lines[$i] = $lines[$i].Substring(0, $lines[$i].Length-1)
}

Write-Output $lines | Set-Content .\DataFiles\SchedTasks.txt

# Get a diff of the two files
Compare-Object (Get-Content .\DataFiles\SchedTasks.txt) (Get-Content .\DataFiles\SchedTasksWhitelist.txt) | Where-Object {$_.SideIndicator -eq "<="} 
