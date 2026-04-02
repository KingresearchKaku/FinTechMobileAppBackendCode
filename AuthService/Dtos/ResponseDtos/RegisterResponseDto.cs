namespace AuthService.Models
{
    public class RegisterResponseDto
    {

        public Guid MobileUserId { get; set; }
        public string MobileNumber { get; set; }

        public string Name { get; set; }

        public string Email { get; set; }

        public string DateOfBirth { get; set; }
        public string Gender { get; set; }

    public string City { get; set; }


        public string? DeviceToken { get; set; }

     public string? AccessToken { get; set; }
            public string? RefreshToken { get; set; }

        public string? FcmToken { get; set; }

   
        public bool isExistingUser { get; set; }

        public bool isVerified { get; set; }




    }
}
