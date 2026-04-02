using AuthService.Models;
using Shared.Common;

namespace AuthService.Services
{
    public interface IAuthService
    {
        
        public Task<CommonApiResponse<LoginResponseDto>> OtpLoginAsync(LoginRequestDto loginRequestDto);
        public Task<CommonApiResponse<OtpVerificationResponseDto>> VerifyOtpAsync(OtpVerifyRequestDto otpVerifyRequestDto);

        public Task<CommonApiResponse<RegisterResponseDto>> ManageUserDetailsAsync(RegisterRequestDto registerRequestDto);

       public Task<CommonApiResponse<UserDetailsResponseDto>> GetUserDetailsAsync();

       public Task<CommonApiResponse<bool>> UpdateFcmTokenAsync(string NewFcmToken);

       public Task<CommonApiResponse<RefreshTokenResponseDto>> RefreshTokenAsync(string RefreshToken ,Guid MobileUserId);

       public Task<CommonApiResponse<string>> GetAppVersionAsync();

       public Task<CommonApiResponse<bool>> LogoutAsync(LogoutRequestDto logoutRequestDto);

        
    }


}
