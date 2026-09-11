using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AegisAgent.Models;

namespace AegisAgent.Services;

/// <summary>
/// 报告上报器 — HTTPS + HMAC-SHA256 签名 + 离线队列。
/// 移植自 public/downloads/aegis_agent.py 的上报逻辑。
/// </summary>
public class ReporterService : IDisposable
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(15) };
    private readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web);
    private const int MaxQueueSize = 200;

    private static string QueueDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AegisAgent", "queue");

    /// <summary>提交报告到 Collector</summary>
    public async Task<bool> SubmitAsync(Report report, AgentConfig config)
    {
        try
        {
            var url = $"{config.CollectorUrl.TrimEnd('/')}/v1/report";
            var body = JsonSerializer.SerializeToUtf8Bytes(report, _json);

            using var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Content = new ByteArrayContent(body);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            request.Headers.Add("X-Device-ID", report.DeviceId);
            request.Headers.Add("X-Agent-Version", report.AgentVersion);

            // HMAC-SHA256 签名
            if (!string.IsNullOrEmpty(config.HmacSecret))
            {
                using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(config.HmacSecret));
                var sig = Convert.ToHexString(hmac.ComputeHash(body)).ToLowerInvariant();
                request.Headers.Add("X-Report-Signature", sig);
            }
            if (!string.IsNullOrEmpty(config.Token))
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", config.Token);

            var response = await _http.SendAsync(request);
            if (response.IsSuccessStatusCode)
            {
                await DrainQueueAsync(config);
                return true;
            }
            if ((int)response.StatusCode >= 500) Enqueue(body);
            return false;
        }
        catch
        {
            Enqueue(JsonSerializer.SerializeToUtf8Bytes(report, _json));
            return false;
        }
    }

    /// <summary>离线队列：有界、原子写入</summary>
    private void Enqueue(byte[] data)
    {
        Directory.CreateDirectory(QueueDir);
        var existing = Directory.GetFiles(QueueDir, "*.json");
        if (existing.Length >= MaxQueueSize)
        {
            var oldest = existing.OrderBy(File.GetCreationTimeUtc).First();
            File.Delete(oldest);
        }
        var name = $"{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}-{Guid.NewGuid().ToString()[..8]}.json";
        var tmp = Path.Combine(QueueDir, name + ".tmp");
        var dest = Path.Combine(QueueDir, name);
        File.WriteAllBytes(tmp, data);
        File.Move(tmp, dest, overwrite: true);
    }

    /// <summary>排空离线队列</summary>
    private async Task DrainQueueAsync(AgentConfig config)
    {
        if (!Directory.Exists(QueueDir)) return;
        var files = Directory.GetFiles(QueueDir, "*.json").OrderBy(f => f).Take(10);
        foreach (var file in files)
        {
            try
            {
                var data = await File.ReadAllBytesAsync(file);
                var report = JsonSerializer.Deserialize<Report>(data, _json);
                if (report is null) { File.Delete(file); continue; }
                var ok = await SubmitAsync(report, config);
                if (ok) File.Delete(file);
            }
            catch { File.Delete(file); }
        }
    }

    public void Dispose() => _http.Dispose();
}
