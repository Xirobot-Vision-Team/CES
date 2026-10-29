#requires -Version 7.0
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
try {
    $taskRequest = [Console]::In.ReadToEnd() | ConvertFrom-Json -Depth 100
    if ($taskRequest.method -notin @('GET','POST','PATCH')) { throw 'Invalid method' }
    if (-not $taskRequest.path.StartsWith('/') -or $taskRequest.path.StartsWith('//')) { throw 'Invalid path' }
    $taskHandler = [Net.Http.HttpClientHandler]::new()
    $taskHandler.AllowAutoRedirect = $false
    $taskClient = [Net.Http.HttpClient]::new($taskHandler)
    $taskClient.Timeout = [TimeSpan]::FromSeconds(25)
    $taskMessage = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($taskRequest.method), ('https://api.github.com' + $taskRequest.path))
    $taskMessage.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $taskRequest.token)
    $taskMessage.Headers.UserAgent.ParseAdd('CES-operator-host')
    $taskMessage.Headers.Accept.ParseAdd('application/vnd.github+json')
    if ($null -ne $taskRequest.payload) {
        $taskBody = $taskRequest.payload | ConvertTo-Json -Depth 100 -Compress
        $taskMessage.Content = [Net.Http.StringContent]::new($taskBody, [Text.UTF8Encoding]::new($false), 'application/json')
    }
    $taskResponse = $taskClient.SendAsync($taskMessage).GetAwaiter().GetResult()
    $taskBytes = $taskResponse.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
    if ($taskBytes.Length -gt 4194304) { throw 'Response limit' }
    [ordered]@{status_code=[int]$taskResponse.StatusCode;body_base64=[Convert]::ToBase64String($taskBytes)} | ConvertTo-Json -Compress
    $taskResponse.Dispose()
    $taskMessage.Dispose()
    $taskClient.Dispose()
} catch {
    $taskInnerType = if ($null -ne $_.Exception.InnerException) { $_.Exception.InnerException.GetType().Name } else { $null }
    [ordered]@{error='NATIVE_HTTP_FAILED';error_type=$_.Exception.GetType().Name;inner_type=$taskInnerType} | ConvertTo-Json -Compress
    exit 1
}

