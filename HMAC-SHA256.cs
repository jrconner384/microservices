using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace crypto.sha256
{
    public static class HMAC_SHA256
    {
        [FunctionName("HMAC_SHA256")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("Calculating HMAC with SHA-256.");
            var unixNow = (int)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            log.LogInformation($"Current Unix timestamp: {unixNow}");
            var publicKey = req.Headers["publicKey"];
            var payload = $"{unixNow}.{publicKey}";
            log.LogInformation($"Plain-text payload: {payload}");
            var payloadBytes = Encoding.ASCII.GetBytes(payload);
            // The method currently expects the key to be passed in the HTTP request. This is obviously not secure.
            // This should be changed to use AKV or some other secure system.
            var privateKey = Encoding.ASCII.GetBytes(req.Headers["privateKey"]);
            string hashHex;

            // Compute the hash, convert it to a hex string, remove the hyphens separating the values, and convert to lower case.
            using (var hmac = new HMACSHA256(privateKey)) {
                hashHex = BitConverter.ToString(hmac.ComputeHash(payloadBytes)).Replace("-", "").ToLower();
            }

            log.LogInformation($"Hashed payload: {hashHex}");
            return (ActionResult)new OkObjectResult(hashHex);
        }
    }
}
