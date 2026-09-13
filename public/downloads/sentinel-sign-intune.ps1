[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$InputBundle,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$CertificateThumbprint,
    [Parameter(Mandatory=$true)][ValidatePattern('^https://')][string]$TimestampServer
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

$bundle=(Resolve-Path -LiteralPath $InputBundle).Path
if([IO.Path]::GetExtension($bundle) -cne '.zip'){throw 'InputBundle must be a ZIP file'}
if(Test-Path -LiteralPath $OutputDirectory){throw 'OutputDirectory must not already exist'}
$parent=Split-Path -Parent ([IO.Path]::GetFullPath($OutputDirectory))
if(-not (Test-Path -LiteralPath $parent -PathType Container)){throw 'OutputDirectory parent does not exist'}

$certificate=@(Get-ChildItem Cert:\CurrentUser\My,Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -ceq $CertificateThumbprint.ToUpperInvariant()})
if($certificate.Count -ne 1){throw 'Exactly one matching signing certificate is required'}
$certificate=$certificate[0]
$codeSigningOid='1.3.6.1.5.5.7.3.3'
if(-not $certificate.HasPrivateKey -or $certificate.NotBefore -gt (Get-Date) -or $certificate.NotAfter -le (Get-Date) -or $codeSigningOid -notin @($certificate.EnhancedKeyUsageList.ObjectId.Value)){throw 'Certificate is not a currently valid code-signing certificate with a private key'}

New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
try {
    Expand-Archive -LiteralPath $bundle -DestinationPath $OutputDirectory
    $manifestPath=Join-Path $OutputDirectory 'intune-deployment-manifest.json'
    $manifest=Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    if($manifest.schema -cne 'sentinel.intune-deployment/v1' -or $manifest.execution.script_signature_state -cne 'pilot_unsigned'){throw 'Input bundle is not an unsigned Sentinel Intune release'}
    $signable=@('intune-windows-detect.ps1','intune-windows-remediate.ps1','intune-compliance-discovery.ps1','sentinel-configure-windows.ps1','sentinel-enroll-windows.ps1','sentinel-quarantine-restore-windows.ps1','rollback-sentinel-windows.ps1','uninstall-sentinel-windows.ps1')
    foreach($name in $signable){
        $path=Join-Path $OutputDirectory $name
        if(-not (Test-Path -LiteralPath $path -PathType Leaf)){throw "Missing signable artifact: $name"}
        $result=Set-AuthenticodeSignature -LiteralPath $path -Certificate $certificate -HashAlgorithm SHA256 -TimestampServer $TimestampServer
        if($result.Status -ne 'Valid'){throw "Signing failed for ${name}: $($result.Status)"}
        $verified=Get-AuthenticodeSignature -LiteralPath $path
        if($verified.Status -ne 'Valid' -or $verified.SignerCertificate.Thumbprint -cne $certificate.Thumbprint){throw "Signature verification failed for $name"}
    }
    foreach($property in $manifest.artifacts.PSObject.Properties){
        $path=Join-Path $OutputDirectory ([string]$property.Value.file)
        if(-not (Test-Path -LiteralPath $path -PathType Leaf)){throw "Missing manifest artifact: $($property.Value.file)"}
        $property.Value.sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
    }
    $manifest.execution.script_signature_state='production_signed'
    $manifest | Add-Member -NotePropertyName signing -NotePropertyValue ([ordered]@{certificate_thumbprint=$certificate.Thumbprint.ToLowerInvariant();timestamp_server=$TimestampServer;signed_at=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();verified_files=$signable})
    [IO.File]::WriteAllText($manifestPath,($manifest | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    $temporaryZip=Join-Path ([IO.Path]::GetTempPath()) ('sentinel-signed-'+[guid]::NewGuid().ToString('N')+'.zip')
    try {
        Compress-Archive -Path (Join-Path $OutputDirectory '*') -DestinationPath $temporaryZip -CompressionLevel Optimal
        Move-Item -LiteralPath $temporaryZip -Destination (Join-Path $OutputDirectory 'sentinel-enterprise-bundle.zip')
    } finally { if(Test-Path -LiteralPath $temporaryZip){Remove-Item -LiteralPath $temporaryZip -Force} }
    [ordered]@{ok=$true;output_directory=[IO.Path]::GetFullPath($OutputDirectory);certificate_thumbprint=$certificate.Thumbprint.ToLowerInvariant();signed_files=$signable.Count;secrets_embedded=$false} | ConvertTo-Json -Compress
} catch {
    if(Test-Path -LiteralPath $OutputDirectory){Remove-Item -LiteralPath $OutputDirectory -Recurse -Force}
    throw
}
