using System.ComponentModel.DataAnnotations;

namespace EcommAPI.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }
        public string? Name { get; set; }

        public string? Username { get; set; }

        public string? Password { get; set; }

        public string? Email { get; set; }  

        public string? Role { get; set; }

        public string? Token { get; set; }

        public string? RefreshToken { get; set; }

        public DateTime? ExpiryTime { get; set; }

        public string? ResetPasswordToken { get; set; }
        public DateTime? ResetPasswordExpiry { get; set; }

    }
}
