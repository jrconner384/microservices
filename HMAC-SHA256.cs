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
            var payload = req.Headers["payload"];
            var payloadBytes = Encoding.ASCII.GetBytes(payload);
            // The method currently expects the key to be passed in the HTTP request. This is obviously not secure.
            // This should be changed to use AKV or some other secure system.
            var key = Encoding.ASCII.GetBytes(req.Headers["key"]);
            string hashHex;

            // Compute the hash, convert it to a hex string, remove the hyphens separating the values, and convert to lower case.
            using (var hmac = new HMACSHA256(key)) {
                hashHex = BitConverter.ToString(hmac.ComputeHash(payloadBytes)).Replace("-", "").ToLower();
            }

            return (ActionResult)new OkObjectResult(hashHex);
        }
    }
}
