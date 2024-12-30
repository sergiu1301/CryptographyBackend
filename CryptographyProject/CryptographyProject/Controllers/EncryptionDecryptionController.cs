using CryptographyProject.Models;
using CryptographyProject.Services;
using Microsoft.AspNetCore.Mvc;

namespace CryptographyProject.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class EncryptionDecryptionController : ControllerBase
    {
        [HttpPost("Encrypt")]
        public ActionResult<CryptoResponse> Encrypt([FromBody] CryptoRequest req)
        {
            if (req == null || string.IsNullOrWhiteSpace(req.Text))
                return BadRequest("Invalid request. 'text' required.");

            // Apelăm RC5Service
            string cipherHex;
            try
            {
                cipherHex = RC5Service.Encrypt(req.W, req.R, req.Text, req.Key ?? "");
            }
            catch (Exception ex)
            {
                return BadRequest($"Eroare: {ex.Message}");
            }

            return Ok(new CryptoResponse { Result = cipherHex });
        }

        [HttpPost("Decrypt")]
        public ActionResult<CryptoResponse> Decrypt([FromBody] CryptoRequest req)
        {
            if (req == null || string.IsNullOrWhiteSpace(req.Text))
                return BadRequest("Invalid request. 'text' required.");

            string plain;
            try
            {
                plain = RC5Service.Decrypt(req.W, req.R, req.Text, req.Key ?? "");
            }
            catch (Exception ex)
            {
                return BadRequest($"Eroare: {ex.Message}");
            }

            return Ok(new CryptoResponse { Result = plain });
        }
    }
}
