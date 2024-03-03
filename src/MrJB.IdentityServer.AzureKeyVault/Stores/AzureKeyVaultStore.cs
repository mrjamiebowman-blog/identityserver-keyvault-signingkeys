using Azure.Security.KeyVault.Certificates;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using MrJB.IdentityServer.AzureKeyVault.Configuration;
using System.Security.Cryptography.X509Certificates;

namespace MrJB.IdentityServer.SigningKeys.Stores;

public class AzureKeyVaultStore : ISigningCredentialStore, IValidationKeysStore
{
    // logging
    private readonly ILogger<AzureKeyVaultStore> _logger;

    private const string MemoryCacheKey = "SigningCerts";
    private const string SigningAlgorithm = SecurityAlgorithms.RsaSha256;

    private readonly IMemoryCache _cache;

    private readonly SemaphoreSlim _cacheLock;
    private readonly CertificateClient _certificateClient;
    private readonly SigningKeysConfiguration _signingCredentialsConfig;

    public AzureKeyVaultStore(ILogger<AzureKeyVaultStore> logger, CertificateClient certificateClient, SigningKeysConfiguration signingCredentialsConfig, IMemoryCache cache)
    {
        // logging
        _logger = logger;

        _certificateClient = certificateClient;
        _signingCredentialsConfig = signingCredentialsConfig;
        _cache = cache;

        _cacheLock = new SemaphoreSlim(1);
    }

    public async Task<SigningCredentials> GetSigningCredentialsAsync()
    {
        await _cacheLock.WaitAsync();

        try
        {
            var (active, _) = await _cache.GetOrCreateAsync(MemoryCacheKey, RefreshCacheAsync);
            return active;
        }
        finally
        {
            _cacheLock.Release();
        }
    }

    public async Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync()
    {
        await _cacheLock.WaitAsync();

        try
        {
            var (_, secondary) = await _cache.GetOrCreateAsync(MemoryCacheKey, RefreshCacheAsync);
            return secondary;
        }
        finally
        {
            _cacheLock.Release();
        }
    }

    public async Task<(SigningCredentials active, IEnumerable<SecurityKeyInfo> secondary)> RefreshCacheAsync(ICacheEntry cache)
    {
        // cache expiration
        cache.AbsoluteExpiration = DateTimeOffset.Now.AddMilliseconds(_signingCredentialsConfig.CacheExpiration);

        // all enabled certificates with versions
        var enabledCertificateVersions = await GetAllEnabledCertificateVersionsAsync(_certificateClient, _signingCredentialsConfig.CertificateNameSigning);

        // get active & secondary certificates`
        var active = await GetActiveCertificateAsync(_certificateClient, _signingCredentialsConfig.RolloverHours, enabledCertificateVersions);
        var secondary = await GetSecondaryCertificatesAsync(_certificateClient, enabledCertificateVersions);

        return (active, secondary);
    }

    public static async Task<List<CertificateProperties>> GetAllEnabledCertificateVersionsAsync(CertificateClient certificateClient, string certName)
    {
        // return type
        var certs = new List<CertificateProperties>();

        // get properties of certs
        var asyncCerts = certificateClient.GetPropertiesOfCertificateVersionsAsync(certName);

        await foreach (CertificateProperties cp in asyncCerts)
        {
            certs.Add(cp);
        }

        certs = certs
                .Where(certVersion => certVersion.Enabled == true)
                .Where(certVersion => certVersion.CreatedOn.HasValue && certVersion.CreatedOn.Value <= DateTime.Now)
                .Where(certVersion => certVersion.ExpiresOn.HasValue && certVersion.ExpiresOn.Value >= DateTime.Now)
                .OrderByDescending(certVersion => certVersion.CreatedOn)
                .ToList();

        // take 2
        certs = certs.Take(2).ToList();

        return certs;
    }

    public static async Task<SigningCredentials> GetActiveCertificateAsync(CertificateClient certificateClient, int rollOverHours, List<CertificateProperties> enabledCertificateVersions)
    {
        var rolloverTime = DateTimeOffset.UtcNow.AddHours(-rollOverHours);

        var filteredEnabledCertificateVersions = enabledCertificateVersions
            .Where(certVersion => certVersion.CreatedOn < rolloverTime)
            .ToList();

        if (filteredEnabledCertificateVersions.Any())
        {
            var certificates = await GetCertificateAsync(certificateClient, filteredEnabledCertificateVersions.First());
            return new SigningCredentials(certificates, SigningAlgorithm);
        }
        else if (enabledCertificateVersions.Any())
        {
            var certificate = await GetCertificateAsync(certificateClient, enabledCertificateVersions.First());

            // if no certificates older than the rollover duration was found, pick the first enabled version of the certificate.
            return new SigningCredentials(certificate, SigningAlgorithm);
        }
        else
        {
            // no certs found
            return default;
        }
    }

    public static async Task<X509SecurityKey> GetCertificateAsync(CertificateClient certificateClient, CertificateProperties item)
    {
        X509Certificate2 certificate = await certificateClient.DownloadCertificateAsync(item.Name);
        return new X509SecurityKey(certificate);
    }

    public static async Task<List<SecurityKeyInfo>> GetSecondaryCertificatesAsync(CertificateClient certificateClient, List<CertificateProperties> enabledCertificateVersions)
    {
        var keys = await Task.WhenAll(enabledCertificateVersions.Select(item => GetCertificateAsync(certificateClient, item)));
        return keys
            .Select(key => new SecurityKeyInfo { Key = key, SigningAlgorithm = SigningAlgorithm })
            .ToList();
    }
}

