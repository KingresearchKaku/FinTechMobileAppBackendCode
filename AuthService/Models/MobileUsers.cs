namespace AuthService.Models
{

    //Model for users who register or log in using their mobile number. This model includes fields for storing user information, OTP details, verification status, and device-related information. It also includes fields for soft deletion and tracking existing users.
    public class MobileUsers
    {
        public int Id { get; set; }

        public Guid MobileUserId { get; set; }   // NOT NULL ✅

        public string MobileNumber { get; set; } // NOT NULL ✅

        public string? Gender { get; set; }

        public string? City { get; set; }

        public string? CountryCode { get; set; }

        public string? Name { get; set; }

        public string? Email { get; set; }

        public string? Otp { get; set; }
        public string? DateOfBirth { get; set; }


        public int? OtpAttempts { get; set; }

        public DateTime? OtpGeneratedAt { get; set; }

        public bool? IsVerified { get; set; }

        public DateTime? CreatedAt { get; set; }

        public DateTime? UpdatedAt { get; set; }

        public string? DeviceToken { get; set; }

        public string? RefreshToken { get; set; }

        public string? AccessToken { get; set; }


        public string? FcmToken { get; set; }

        public string? Version { get; set; }

        public bool? isDeleted { get; set; }

        public DateTime? DeletedAt { get; set; }

        public bool? isActive { get; set; }

        public bool? isExistingUser { get; set; }
    }
}