using System.Security.Claims;
using AuthService.Data;
using AuthService.Dtos;
using AuthService.Infrastructure;
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
        private readonly ILogger<AuthService> _logger;

        private const int MaxOtpVerifyAttempts = 5;
        private const int OtpExpiryMinutes = 5;
        private const int RefreshTokenExpiryDays = 30;

        public AuthService(
            AuthDbContext dbContext,
            IConfiguration config,
            JwtService jwtService,
            IHttpContextAccessor httpContextAccessor,
            ILogger<AuthService> logger)
        {
            _dbContext = dbContext;
            _config = config;
            _jwtService = jwtService;
            _httpContextAccessor = httpContextAccessor;
            _logger = logger;
        }

        private Guid GetUserIdFromToken()
        {
            var claim = _httpContextAccessor.HttpContext?.User
                .FindFirst(ClaimTypes.NameIdentifier)?.Value;
            return Guid.TryParse(claim, out var userId) ? userId : Guid.Empty;
        }

        // 1️⃣ SEND OTP
        public async Task<ApiResponse<SendOtpResponseDto>> SendOtpAsync(SendOtpRequestDto request)
        {
            if (string.IsNullOrWhiteSpace(request.MobileNumber) ||
                request.MobileNumber.Length != 10 ||
                !request.MobileNumber.All(char.IsDigit) ||
                request.MobileNumber[0] == '0')
            {
                return ApiResponse<SendOtpResponseDto>.Fail("Invalid mobile number format.", 400);
            }

            var user = await _dbContext.MobileUsers
                .FirstOrDefaultAsync(u => u.MobileNumber == request.MobileNumber);
            var otp = GenerateOtp();
            Guid mobileUserId;

            if (user == null)
            {
                // New user — generate OTP in the legacy [Otp] column
                mobileUserId = Guid.NewGuid();


                await _dbContext.MobileUsers.AddAsync(new MobileUser
                {
                    MobileUserId = mobileUserId,
                    MobileNumber = request.MobileNumber,
                    CountryCode = request.CountryCode,
                    Otp = otp,
                    OtpAttempts = 0,
                    OtpGeneratedAt = DateTime.UtcNow,
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true,
                    IsDeleted = false,
                    IsVerified = false,
                    IsExistingUser = false
                });

                _logger.LogInformation("OTP sent to new user. UserId: {UserId}", mobileUserId);
                // TODO: Integrate SMS provider — send 'otp' to request.MobileNumber
            }
            else
            {
                if (!user.IsActive)
                    return ApiResponse<SendOtpResponseDto>.Fail(
                        "Account is inactive. Please contact support.",
                        403);

                mobileUserId = user.MobileUserId;

                user.Otp = otp;
                user.OtpAttempts = 0; // Reset failed verification attempts on new OTP
                user.OtpGeneratedAt = DateTime.UtcNow;
                user.CountryCode = request.CountryCode;
                user.UpdatedAt = DateTime.UtcNow;

                _logger.LogInformation("OTP resent. UserId: {UserId}", mobileUserId);
                // TODO: Integrate SMS provider — send 'otp' to user.MobileNumber
            }

            await _dbContext.SaveChangesAsync();

            return ApiResponse<SendOtpResponseDto>.Ok(
                new SendOtpResponseDto
                {
                    MobileUserId = mobileUserId,
                    MobileNumber = request.MobileNumber,
                    CountryCode = request.CountryCode,
                    Otp = otp,

                },
                "OTP sent successfully.");
        }

        // 2️⃣ VERIFY OTP
        public async Task<ApiResponse<VerifyOtpResponseDto>> VerifyOtpAsync(VerifyOtpRequestDto request)
        {
            if (request.MobileUserId == Guid.Empty || string.IsNullOrWhiteSpace(request.Otp))
                return ApiResponse<VerifyOtpResponseDto>.Fail("Invalid request.", 400);

            if (request.Otp.Length != 6 || !request.Otp.All(char.IsDigit))
                return ApiResponse<VerifyOtpResponseDto>.Fail("OTP must be exactly 6 digits.", 400);

            var user = await _dbContext.MobileUsers
                .FirstOrDefaultAsync(u => u.MobileUserId == request.MobileUserId);

            if (user == null)
                return ApiResponse<VerifyOtpResponseDto>.Fail("User not found.", 404);

            if (!user.IsActive)
                return ApiResponse<VerifyOtpResponseDto>.Fail(
                    "Account is inactive. Please contact support.",
                    403);

            // Locked out after too many wrong attempts
            if (user.OtpAttempts >= MaxOtpVerifyAttempts)
            {
                _logger.LogWarning("OTP verify lockout hit. UserId: {UserId}", user.MobileUserId);
                return ApiResponse<VerifyOtpResponseDto>.Fail(
                    "Too many failed attempts. Please request a new OTP.",
                    429);
            }

            // OTP expiry check
            if (user.OtpGeneratedAt == null ||
                user.OtpGeneratedAt < DateTime.UtcNow.AddMinutes(-OtpExpiryMinutes))
            {
                return ApiResponse<VerifyOtpResponseDto>.Fail(
                    "OTP has expired. Please request a new one.",
                    400);
            }

            if (user.Otp != request.Otp)
            {
                user.OtpAttempts += 1;

                // Clear OTP on final failed attempt to force re-request
                if (user.OtpAttempts >= MaxOtpVerifyAttempts)
                {
                    user.Otp = null;
                    user.OtpGeneratedAt = null;
                }

                user.UpdatedAt = DateTime.UtcNow;
                await _dbContext.SaveChangesAsync();

                _logger.LogWarning("Invalid OTP. UserId: {UserId}, Attempt: {Attempt}",
                    user.MobileUserId, user.OtpAttempts);
                return ApiResponse<VerifyOtpResponseDto>.Fail("Invalid OTP.", 400);
            }

            // OTP verified — generate tokens
            var accessToken = _jwtService.GenerateAccessToken(
                user.MobileUserId.ToString(), user.MobileNumber, user.Name);

            var (rawRefreshToken, refreshTokenHash) =
                _jwtService.GenerateRefreshToken(RefreshTokenExpiryDays);

            // Consume OTP (cannot be reused), set verified state, store hashed refresh token
            user.IsVerified = true;
            user.Otp = null;
            user.OtpGeneratedAt = null;
            user.OtpAttempts = 0;
            user.RefreshTokenHash = refreshTokenHash;
            user.DeviceToken = request.DeviceToken;
            user.FcmToken = request.FcmToken;
            user.LastKnownAppVersion = request.AppVersion;
            user.UpdatedAt = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("OTP verified successfully. UserId: {UserId}", user.MobileUserId);

            return ApiResponse<VerifyOtpResponseDto>.Ok(
                new VerifyOtpResponseDto
                {
                    MobileUserId = user.MobileUserId,
                    MobileNumber = user.MobileNumber,
                    CountryCode = user.CountryCode,
                    Name = user.Name,
                    Email = user.Email,
                    IsExistingUser = user.IsExistingUser,
                    AccessToken = accessToken,
                    RefreshToken = rawRefreshToken // Raw token sent to client; hash stored in DB
                },
                "OTP verified successfully.");
        }

        // 3️⃣ REGISTER USER — requires [Authorize]
        public async Task<ApiResponse<RegisterUserResponseDto>> RegisterUserAsync(RegisterUserRequestDto request)
        {
            var userId = GetUserIdFromToken();
            if (userId == Guid.Empty)
                return ApiResponse<RegisterUserResponseDto>.Fail("Unauthorized.", 401);

            if (string.IsNullOrWhiteSpace(request.Name) ||
                string.IsNullOrWhiteSpace(request.Email) ||
                string.IsNullOrWhiteSpace(request.DateOfBirth))
            {
                return ApiResponse<RegisterUserResponseDto>.Fail(
                    "Name, Email, and Date of Birth are required.",
                    400);
            }

            var user = await _dbContext.MobileUsers
                .FirstOrDefaultAsync(u => u.MobileUserId == userId && u.IsActive);

            if (user == null)
                return ApiResponse<RegisterUserResponseDto>.Fail("User not found.", 404);

            user.Name = request.Name;
            user.Email = request.Email;
            user.DateOfBirth = request.DateOfBirth;
            user.Gender = request.Gender;
            user.City = request.City;
            user.IsExistingUser = true; // Mark profile as complete
            user.UpdatedAt = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("User profile registered. UserId: {UserId}", userId);

            return ApiResponse<RegisterUserResponseDto>.Ok(
                new RegisterUserResponseDto
                {
                    MobileUserId = user.MobileUserId,
                    MobileNumber = user.MobileNumber,
                    Name = user.Name,
                    Email = user.Email,
                    DateOfBirth = user.DateOfBirth,
                    Gender = user.Gender,
                    City = user.City,
                    IsExistingUser = user.IsExistingUser
                },
                "Registration completed successfully.");
        }

        // 4️⃣ GET USER DETAILS — requires [Authorize]
        public async Task<ApiResponse<UserDetailsResponseDto>> GetUserDetailsAsync()
        {
            var userId = GetUserIdFromToken();
            if (userId == Guid.Empty)
                return ApiResponse<UserDetailsResponseDto>.Fail("Unauthorized.", 401);

            var user = await _dbContext.MobileUsers
                .FirstOrDefaultAsync(u => u.MobileUserId == userId);

            if (user == null)
                return ApiResponse<UserDetailsResponseDto>.Fail("User not found.", 404);

            return ApiResponse<UserDetailsResponseDto>.Ok(new UserDetailsResponseDto
            {
                MobileUserId = user.MobileUserId,
                MobileNumber = user.MobileNumber,
                Name = user.Name,
                Email = user.Email,
                DateOfBirth = user.DateOfBirth,
                Gender = user.Gender,
                City = user.City
            });
        }

        // 5️⃣ REFRESH TOKEN — tokens sent in POST body, never in URL
        public async Task<ApiResponse<RefreshTokenResponseDto>> RefreshTokenAsync(RefreshTokenRequestDto request)
        {
            if (request.MobileUserId == Guid.Empty || string.IsNullOrWhiteSpace(request.RefreshToken))
                return ApiResponse<RefreshTokenResponseDto>.Fail("Invalid request.", 400);

            var tokenHash = JwtService.HashValue(request.RefreshToken);

            var user = await _dbContext.MobileUsers
                .FirstOrDefaultAsync(u =>
                    u.MobileUserId == request.MobileUserId &&
                    u.RefreshTokenHash == tokenHash &&
                    u.IsActive);

            if (user == null)
            {
                _logger.LogWarning("Invalid refresh token attempt. UserId: {UserId}", request.MobileUserId);
                return ApiResponse<RefreshTokenResponseDto>.Fail(
                    "Invalid or expired refresh token.",
                    401);
            }

            var refreshTokenExpiresAt = JwtService.TryGetRefreshTokenExpiry(
                request.RefreshToken,
                out var embeddedRefreshTokenExpiry)
                ? embeddedRefreshTokenExpiry
                : (user.UpdatedAt ?? user.CreatedAt).AddDays(RefreshTokenExpiryDays);

            if (refreshTokenExpiresAt < DateTime.UtcNow)
            {
                _logger.LogWarning("Expired refresh token used. UserId: {UserId}", user.MobileUserId);
                user.RefreshTokenHash = null;
                user.UpdatedAt = DateTime.UtcNow;
                await _dbContext.SaveChangesAsync();

                return ApiResponse<RefreshTokenResponseDto>.Fail(
                    "Refresh token has expired. Please log in again.",
                    401);
            }

            var newAccessToken = _jwtService.GenerateAccessToken(
                user.MobileUserId.ToString(), user.MobileNumber, user.Name);

            var (newRawRefreshToken, newRefreshTokenHash) =
                _jwtService.GenerateRefreshToken(RefreshTokenExpiryDays);

            // Rotation: old token invalidated, new token issued
            user.RefreshTokenHash = newRefreshTokenHash;
            user.UpdatedAt = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("Token rotated. UserId: {UserId}", user.MobileUserId);

            return ApiResponse<RefreshTokenResponseDto>.Ok(
                new RefreshTokenResponseDto
                {
                    AccessToken = newAccessToken,
                    RefreshToken = newRawRefreshToken
                },
                "Token refreshed successfully.");
        }

        // 6️⃣ UPDATE FCM TOKEN — requires [Authorize]
        public async Task<ApiResponse<bool>> UpdateFcmTokenAsync(string fcmToken)
        {
            var userId = GetUserIdFromToken();
            if (userId == Guid.Empty)
                return ApiResponse<bool>.Fail("Unauthorized.", 401);

            if (string.IsNullOrWhiteSpace(fcmToken))
                return ApiResponse<bool>.Fail("FCM token is required.", 400);

            var user = await _dbContext.MobileUsers
                .FirstOrDefaultAsync(u => u.MobileUserId == userId && u.IsActive);

            if (user == null)
                return ApiResponse<bool>.Fail("User not found.", 404);

            user.FcmToken = fcmToken;
            user.UpdatedAt = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();

            return ApiResponse<bool>.Ok(true, "FCM token updated successfully.");
        }

        // 7️⃣ LOGOUT — requires [Authorize]; invalidates refresh token server-side
        public async Task<ApiResponse<bool>> LogoutAsync()
        {
            var userId = GetUserIdFromToken();
            if (userId == Guid.Empty)
                return ApiResponse<bool>.Fail("Unauthorized.", 401);

            var user = await _dbContext.MobileUsers
                .FirstOrDefaultAsync(u => u.MobileUserId == userId);

            if (user == null)
                return ApiResponse<bool>.Fail("User not found.", 404);

            user.RefreshTokenHash = null;
            user.UpdatedAt = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("User logged out. UserId: {UserId}", userId);
            return ApiResponse<bool>.Ok(true, "Logged out successfully.");
        }

        // 8️⃣ GET APP VERSION — public endpoint; returns minimum required version from config
        public async Task<ApiResponse<string>> GetAppVersionAsync()
        {
            await Task.CompletedTask;
            var minimumVersion = _config["AppSettings:MinimumAppVersion"] ?? "1.0.0";
            return ApiResponse<string>.Ok(minimumVersion);
        }

        // Cryptographically secure 6-digit OTP
        private static string GenerateOtp() =>
            System.Security.Cryptography.RandomNumberGenerator.GetInt32(100000, 1000000).ToString();
    }
}
