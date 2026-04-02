using AuthService.Data;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

namespace AuthService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        // private readonly ILogger<AuthController> _logger;
        private readonly IAuthService _authService;

            private readonly IConfiguration _config;    

        public AuthController(IAuthService authService, IConfiguration config   )
        {
            _authService = authService;
            _config = config;


            
        }



    [HttpGet("check-db")]
    public async Task<IActionResult> CheckDb()
    {
        try
        {
            using var connection = new SqlConnection(
                _config.GetConnectionString("DefaultConnection")
            );

            await connection.OpenAsync();

            return Ok("✅ Database Connected");
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"❌ Connection Failed: {ex.Message}");
        }
    }



   
        //OtpLogin Api 
        [HttpPost("otp-login")]
        public async Task<IActionResult> OtpLogin(LoginRequestDto loginRequestDto)
        {
            

            // Implement OTP login logic here
            return Ok( await _authService.OtpLoginAsync(loginRequestDto));
        }


        //Otp verification Api 
        [HttpPost("otp-verification")]
        public async Task<IActionResult>  OtpVerification(OtpVerifyRequestDto otpVerifyRequestDto)
        {
            // Implement OTP login logic here
            return Ok( await _authService.VerifyOtpAsync(otpVerifyRequestDto));
        }

        //OtpLogin Api 
        [HttpPost("user-register")]
        public async Task<IActionResult> ManageUserDetails(RegisterRequestDto registerRequestDto)
        {
            // Implement OTP login logic here
            return Ok(await _authService.ManageUserDetailsAsync(registerRequestDto));
        }


[Authorize]
        //OtpLogin Api 
        [HttpGet("get-user-details")]
        public async Task<IActionResult> GetUserDetailsById()
        {
            // Implement OTP login logic here
            return Ok( await _authService.GetUserDetailsAsync());
        }


        //Method to update FCM token for the user
        [HttpPost("update-fcm-token")]
        public async Task<IActionResult> UpdateFcmToken(string NewFcmToken)
        {
            // Implement OTP login logic here
            return Ok(await _authService.UpdateFcmTokenAsync(NewFcmToken));
        }


        //Method to get api version
        [HttpGet("get-api-version")]
        public async Task<IActionResult> GetApiVersion()
        {
            return Ok(await _authService.GetAppVersionAsync());


        }

        //Method to refresh JWT token using refresh token we will get new access token and new refresh token
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken(string RefreshToken, Guid MobileUserId)
        {
            return Ok(await _authService.RefreshTokenAsync(RefreshToken, MobileUserId));
        }


        //Method to logout user
        [HttpPost("logout")]
        public async Task<IActionResult> Logout(LogoutRequestDto logoutRequestDto)
        {
            // Implement logout logic here
            return Ok( await _authService.LogoutAsync(logoutRequestDto));
        }

    







    }
}
