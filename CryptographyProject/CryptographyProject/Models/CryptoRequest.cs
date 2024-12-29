using System.ComponentModel.DataAnnotations;

namespace CryptographyProject.Models;
public class CryptoRequest
{
    [Required]
    public int W { get; set; }
    [Required]
    public int R { get; set; }
    [Required]
    public string Text { get; set; }
    [Required]
    public string Key { get; set; }
}