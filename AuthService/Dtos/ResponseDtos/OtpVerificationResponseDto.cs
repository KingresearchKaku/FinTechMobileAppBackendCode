namespace AuthService.Models
{
    public class OtpVerificationResponseDto
    {


        public Guid MobileUserId { get; set; }
        public string MobileNumber { get; set; }
        public string otp { get; set; }

        public string CountryCode { get; set; }

        public string Name { get; set; }

        public string Email { get; set; }

        public string? DeviceToken { get; set; }

        public string? AccessToken { get; set; }
            public string? RefreshToken { get; set; }

        public string? FcmToken { get; set; }

        public string? Version { get; set; }

        public bool isExistingUser { get; set; }

        public bool isVerified { get; set; }

        public DateTime OtpGeneratedAt { get; set; }

        public int OtpAttempts { get; set; }
    








    }
}
