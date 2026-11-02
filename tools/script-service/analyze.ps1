$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -ErrorAction Stop
try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $settings = @{ Rules = @{ PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1') } } }
    $results = @(Invoke-ScriptAnalyzer -ScriptDefinition $request.script -IncludeRule PSUseCompatibleSyntax -Settings $settings)
    $results += @(Invoke-ScriptAnalyzer -ScriptDefinition $request.script)
    $seen = @{}
    $diagnostics = @($results | ForEach-Object {
        $key = "$($_.RuleName):$($_.Extent.StartOffset):$($_.Extent.EndOffset):$($_.Message)"
        if ($seen.ContainsKey($key)) { return }
        $seen[$key] = $true
        $blocking = $_.Severity.ToString() -eq 'ParseError' -or $_.RuleName -eq 'PSUseCompatibleSyntax'
        $severity = if ($blocking) { 'error' } elseif ($_.Severity.ToString() -eq 'Information') { 'info' } else { 'warning' }
        @{
            from = $_.Extent.StartOffset
            to = $_.Extent.EndOffset
            severity = $severity
            blocking = $blocking
            message = "$($_.RuleName): $($_.Message)"
            source = 'PSScriptAnalyzer'
        }
    } | Sort-Object -Property blocking -Descending | Select-Object -First 200)
    [Console]::WriteLine((@{ diagnostics = $diagnostics } | ConvertTo-Json -Depth 8 -Compress))
} catch {
    [Console]::Error.WriteLine('PowerShell analysis failed')
    exit 1
}
