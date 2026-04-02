namespace AuthService.Models
{
    public class RegisterRequestDto
    {

        public Guid MobileUserId { get; set; }


        public string Name { get; set; }

        public string Email { get; set; }

        public string DateOfBirth { get; set; }

        public string Gender { get; set; }

        public string City { get; set; }



    }
}
