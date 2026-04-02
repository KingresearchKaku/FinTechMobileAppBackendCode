using System.Security.Claims;
using AuthService.Data;
using AuthService.Models;
using Microsoft.EntityFrameworkCore;
using Shared.Common;

namespace AuthService.Services
{
    public class AuthService : IAuthService
    {

        private readonly AuthDbContext _dbContext;
        private readonly IConfiguration _config;

        private readonly JwtService _jwtService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private Guid GetUserIdFromToken()
        {
            var user = _httpContextAccessor.HttpContext?.User;

            if (user == null)
                return Guid.Empty;

            var userIdClaim = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userIdClaim))
                return Guid.Empty;

            return Guid.Parse(userIdClaim);
        }

        public AuthService(AuthDbContext dbContext, IConfiguration config, JwtService jwtService, IHttpContextAccessor httpContextAccessor)
        {
            _dbContext = dbContext;
            _config = config;
            _jwtService = jwtService;
            _httpContextAccessor = httpContextAccessor;
        }
        // 1️⃣ LOGIN → Send OTP
        public async Task<CommonApiResponse<LoginResponseDto>> OtpLoginAsync(LoginRequestDto loginRequestDto)
        {
            if (loginRequestDto == null || string.IsNullOrEmpty(loginRequestDto.MobileNumber))
                throw new ArgumentException("Invalid login request");

            if (loginRequestDto.MobileNumber.Length != 10 || !loginRequestDto.MobileNumber.All(char.IsDigit))
                throw new ArgumentException("Invalid mobile number format");

            if (loginRequestDto.MobileNumber.StartsWith('0'))
                throw new ArgumentException("Mobile number should not start with 0");

            var otp = new Random().Next(100000, 999999).ToString();
            var userInDb = await _dbContext.MobileUsers.FirstOrDefaultAsync(u => u.MobileNumber == loginRequestDto.MobileNumber);

            Guid mobileUserId;

            if (userInDb == null)
            {
                // New user — create record
                mobileUserId = Guid.NewGuid();
                await _dbContext.MobileUsers.AddAsync(new MobileUsers
                {
                    MobileUserId = mobileUserId,
                    MobileNumber = loginRequestDto.MobileNumber,
                    CountryCode = loginRequestDto.CountryCode,
                    Otp = otp,
                    OtpAttempts = 1,
                    OtpGeneratedAt = DateTime.UtcNow,
                    CreatedAt = DateTime.UtcNow,
                    isActive = true,
                    isExistingUser = false
                });
            }

            else if (userInDb.isDeleted == true)
            {
                return new CommonApiResponse<LoginResponseDto>
                {
                    StatusCode = 400,
                    Message = "This mobile number is Deleted. Please contact support.",

                };
            }
            else if (userInDb.isActive == false)
            {
                return new CommonApiResponse<LoginResponseDto>
                {
                    StatusCode = 404,
                    Message = "User Not Found. Please contact support.",

                };
            }
            else
            {
                mobileUserId = userInDb.MobileUserId;

                // Check OTP attempts in the last 1 hour — max 3 allowed
                var oneHourAgo = DateTime.UtcNow.AddHours(-1);
                if (userInDb.OtpGeneratedAt >= oneHourAgo && userInDb.OtpAttempts >= 3)
                    return new CommonApiResponse<LoginResponseDto>
                    {
                        StatusCode = 400,
                        Message = "Maximum OTP attempts exceeded. Please try again after 1 hour.",

                    };


                // Reset counter if the 1-hour window has expired
                if (userInDb.OtpGeneratedAt < oneHourAgo)
                    userInDb.OtpAttempts = 0;

                userInDb.Otp = otp;
                userInDb.OtpAttempts += 1;
                userInDb.OtpGeneratedAt = DateTime.UtcNow;
                userInDb.UpdatedAt = DateTime.UtcNow;
                userInDb.isExistingUser = false;
            }

            await _dbContext.SaveChangesAsync();

            return new CommonApiResponse<LoginResponseDto>
            {
                StatusCode = 200,
                Message = "OTP sent successfully",
                Data = new LoginResponseDto
                {
                    MobileUserId = mobileUserId,
                    MobileNumber = loginRequestDto.MobileNumber,
                    CountryCode = loginRequestDto.CountryCode,
                    otp = otp

                }
            };
        }






        // 2️⃣ VERIFY OTP → Login success + Token
        public async Task<CommonApiResponse<OtpVerificationResponseDto>> VerifyOtpAsync(OtpVerifyRequestDto otpVerifyRequestDto)
        {
            if (otpVerifyRequestDto.MobileUserId == Guid.Empty || string.IsNullOrEmpty(otpVerifyRequestDto.Otp))
            {
                return new CommonApiResponse<OtpVerificationResponseDto>
                {
                    StatusCode = 400,
                    Message = "Invalid OTP verification request",

                };

            }

            if (otpVerifyRequestDto.Otp.Length != 6 || !otpVerifyRequestDto.Otp.All(char.IsDigit))
            {
                return new CommonApiResponse<OtpVerificationResponseDto>
                {
                    StatusCode = 400,
                    Message = "Invalid OTP format",

                };
            }
            var UserInDb = await _dbContext.MobileUsers.FirstOrDefaultAsync(u => u.MobileUserId == otpVerifyRequestDto.MobileUserId);

            if (UserInDb == null || UserInDb.isDeleted == true)
            {
                return new CommonApiResponse<OtpVerificationResponseDto>
                {
                    StatusCode = 404,
                    Message = "User not found. Please contact support.",

                };
            }
            if (UserInDb.Otp != otpVerifyRequestDto.Otp)
            {
                return new CommonApiResponse<OtpVerificationResponseDto>
                {
                    StatusCode = 400,
                    Message = "Invalid OTP. Please try again.",
                };
            }

            if (UserInDb.OtpGeneratedAt == null || UserInDb.OtpGeneratedAt < DateTime.UtcNow.AddMinutes(-5))
            {
                return new CommonApiResponse<OtpVerificationResponseDto>
                {
                    StatusCode = 400,
                    Message = "OTP has expired. Please request a new one.",
                };
            }
            // Generate Tokens
            var accessToken = _jwtService.GenerateAccessToken(
                UserInDb.MobileUserId.ToString(),
                UserInDb.MobileNumber);


            // ✅ 5. Generate NEW refresh token (rotation)
            var refreshToken = Guid.NewGuid().ToString() + DateTime.UtcNow.Ticks + UserInDb.MobileUserId.ToString();




            await _dbContext.SaveChangesAsync();


            UserInDb.IsVerified = true;
            UserInDb.DeviceToken = otpVerifyRequestDto.DeviceToken;
            UserInDb.FcmToken = otpVerifyRequestDto.FcmToken;
            UserInDb.Version = otpVerifyRequestDto.Version;
            UserInDb.UpdatedAt = DateTime.UtcNow;
            UserInDb.RefreshToken = refreshToken;
            UserInDb.AccessToken = accessToken;




            await _dbContext.SaveChangesAsync();

            return new CommonApiResponse<OtpVerificationResponseDto>
            {
                StatusCode = 200,
                Message = "OTP verified successfully",
                Data = new OtpVerificationResponseDto
                {
                    MobileUserId = UserInDb.MobileUserId,
                    MobileNumber = UserInDb.MobileNumber,
                    CountryCode = UserInDb.CountryCode,
                    Name = UserInDb.Name,
                    Email = UserInDb.Email,
                    DeviceToken = UserInDb.DeviceToken,
                    FcmToken = UserInDb.FcmToken,
                    Version = UserInDb.Version,
                    isExistingUser = UserInDb.isExistingUser ?? false,
                    isVerified = UserInDb.IsVerified ?? false,
                    OtpGeneratedAt = UserInDb.OtpGeneratedAt ?? DateTime.MinValue,
                    OtpAttempts = UserInDb.OtpAttempts ?? 0,
                    otp = UserInDb.Otp,
                    RefreshToken = UserInDb.RefreshToken,
                    AccessToken = UserInDb.AccessToken
                }
            };







        }

        // 3️⃣ GET USER DETAILS (after login)
        public async Task<CommonApiResponse<UserDetailsResponseDto>> GetUserDetailsAsync()
        {
            var userId = GetUserIdFromToken();

            if (userId == Guid.Empty)
            {
                return new CommonApiResponse<UserDetailsResponseDto>
                {
                    StatusCode = 401,
                    Message = "Unauthorized"
                };
            }
            var user = await _dbContext.MobileUsers
             .FirstOrDefaultAsync(x => x.MobileUserId == userId);


            if (user == null)
            {
                return new CommonApiResponse<UserDetailsResponseDto>
                {
                    StatusCode = 404,
                    Message = "User not found"
                };
            }
            return new CommonApiResponse<UserDetailsResponseDto>
            {
                StatusCode = 200,
                Message = "User details fetched successfully",
                Data = new UserDetailsResponseDto
                {
                    MobileUserId = user.MobileUserId,
                    MobileNumber = user.MobileNumber,
                    DateOfBirth = user.DateOfBirth,
                    Name = user.Name,
                    Email = user.Email,
                    City = user.City,
                }
            };

        }

        // 4️⃣ REGISTER / UPDATE USER
        public async Task<CommonApiResponse<RegisterResponseDto>> ManageUserDetailsAsync(RegisterRequestDto registerRequestDto)
        {
            if (registerRequestDto == null || registerRequestDto.MobileUserId == Guid.Empty)
            {
                return new CommonApiResponse<RegisterResponseDto>
                {
                    StatusCode = 400,
                    Message = "Invalid user details request",

                };
            }
            if (string.IsNullOrEmpty(registerRequestDto.Name) || string.IsNullOrEmpty(registerRequestDto.Email) || string.IsNullOrEmpty(registerRequestDto.DateOfBirth))
            {
                return new CommonApiResponse<RegisterResponseDto>
                {
                    StatusCode = 400,
                    Message = "Name, Email and Date of Birth are required fields",

                };
            }

            var UserInDb = await _dbContext.MobileUsers.FirstOrDefaultAsync(u => u.MobileUserId == registerRequestDto.MobileUserId && u.isActive == true && u.isDeleted == false);
            if (UserInDb == null)
            {
                return new CommonApiResponse<RegisterResponseDto>
                {
                    StatusCode = 404,
                    Message = "User not found. Please contact support.",

                };
            }
            // ✅ 4. Generate new Access Token
            var AccessToken = _jwtService.GenerateAccessToken(
                UserInDb.MobileUserId.ToString(),
                UserInDb.MobileNumber
            );

            // ✅ 5. Generate NEW refresh token (rotation)
            var newRefreshToken = Guid.NewGuid().ToString() + DateTime.UtcNow.Ticks + UserInDb.MobileUserId.ToString();

            UserInDb.Name = registerRequestDto.Name;
            UserInDb.Email = registerRequestDto.Email;
            UserInDb.DateOfBirth = registerRequestDto.DateOfBirth;
            UserInDb.Gender = registerRequestDto.Gender;
            UserInDb.City = registerRequestDto.City;
            UserInDb.isExistingUser = true;
            UserInDb.AccessToken = AccessToken; // Keep existing tokens unchanged
            UserInDb.RefreshToken = newRefreshToken;
            UserInDb.UpdatedAt = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();
            return new CommonApiResponse<RegisterResponseDto>
            {

                StatusCode = 200,
                Message = "User details updated successfully",
                Data = new RegisterResponseDto
                {
                    MobileUserId = UserInDb.MobileUserId,
                    MobileNumber = UserInDb.MobileNumber,
                    Name = UserInDb.Name,
                    Email = UserInDb.Email,
                    DateOfBirth = UserInDb.DateOfBirth,
                }



            };
        }

        // 5️⃣ REFRESH TOKEN
        public async Task<CommonApiResponse<RefreshTokenResponseDto>> RefreshTokenAsync(string RefreshToken, Guid MobileUserId)
        {
            if (string.IsNullOrEmpty(RefreshToken) || MobileUserId == Guid.Empty)
            {
                return new CommonApiResponse<RefreshTokenResponseDto>
                {
                    StatusCode = 400,
                    Message = "Invalid request"
                };
            }

            var UserInDb = await _dbContext.MobileUsers.FirstOrDefaultAsync(u => u.MobileUserId == MobileUserId && u.RefreshToken == RefreshToken && u.isActive == true && u.isDeleted == false);

            if (UserInDb == null)
            {
                return new CommonApiResponse<RefreshTokenResponseDto>
                {
                    StatusCode = 401,
                    Message = "Invalid refresh token or user not found"
                };
            }


            // ✅ 4. Generate new Access Token
            var newAccessToken = _jwtService.GenerateAccessToken(
                UserInDb.MobileUserId.ToString(),
                UserInDb.MobileNumber
            );

            // ✅ 5. Generate NEW refresh token (rotation)
            var newRefreshToken = Guid.NewGuid().ToString() + DateTime.UtcNow.Ticks + UserInDb.MobileUserId.ToString();

            UserInDb.AccessToken = newAccessToken;
            UserInDb.RefreshToken = newRefreshToken;
            UserInDb.UpdatedAt = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();
            // ✅ 6. Response
            return new CommonApiResponse<RefreshTokenResponseDto>
            {
                StatusCode = 200,
                Message = "Token refreshed successfully",
                Data = new RefreshTokenResponseDto
                {
                    MobileUserId = UserInDb.MobileUserId,
                    AccessToken = newAccessToken,
                    RefreshToken = newRefreshToken
                }
            };


        }





        // 6️⃣ UPDATE FCM TOKEN
        public Task<CommonApiResponse<bool>> UpdateFcmTokenAsync(string NewFcmToken)
        {
            throw new NotImplementedException();
        }

        // 7️⃣ LOGOUT
        public Task<CommonApiResponse<bool>> LogoutAsync(LogoutRequestDto logoutRequestDto)
        {
            throw new NotImplementedException();
        }

        // 8️⃣ APP VERSION (independent)
        public Task<CommonApiResponse<string>> GetAppVersionAsync()
        {
            throw new NotImplementedException();
        }






    }

    //Jwt token generation method



}



