using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        //OtpLogin Api 
        [HttpPost("otp-login")]
        public IActionResult OtpLogin()
        {
            // Implement OTP login logic here
            return Ok("OTP login successful");
        }


        //Otp verification Api 
        [HttpPost("otp-verification")]
        public IActionResult OtpVerification()
        {
            // Implement OTP login logic here
            return Ok("OTP Verify successful");
        }

        //OtpLogin Api 
        [HttpPost("user-register")]
        public IActionResult ManageUserDetails()
        {
            // Implement OTP login logic here
            return Ok("OTP Verify successful");
        }



        //OtpLogin Api 
        [HttpGet("get-user-details")]
        public IActionResult GetUserDetailsById()
        {
            // Implement OTP login logic here
            return Ok("OTP Verify successful");
        }


        //Method to update FCM token for the user
        [HttpPost("update-fcm-token")]
        public IActionResult UpdateFcmToken()
        {
            // Implement OTP login logic here
            return Ok("OTP Verify successful");

        }

        [HttpGet("get-api-version")])]
        public IActionResult GetApiVersion()
        {
            return Ok("AuthService API Version 1.0");


        }








    }
}
