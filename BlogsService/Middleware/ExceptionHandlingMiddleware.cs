using Shared.Common;
using System.Net;
using System.Text.Json;

namespace BlogsService.Middleware
{
    public class ExceptionHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ExceptionHandlingMiddleware> _logger;
        private readonly IHostEnvironment _environment;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        public ExceptionHandlingMiddleware(
            RequestDelegate next,
            ILogger<ExceptionHandlingMiddleware> logger,
            IHostEnvironment environment)
        {
            _next = next;
            _logger = logger;
            _environment = environment;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled exception on {Method} {Path}: {Message}",
                    context.Request.Method, context.Request.Path, ex.Message);

                context.Response.ContentType = "application/json";
                context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;

                var response = ApiResponse<object>.Fail(
                    "An unexpected error occurred. Please try again later.",
                    (int)HttpStatusCode.InternalServerError);

                if (_environment.IsDevelopment())
                {
                    response.Errors.Add($"{ex.GetType().Name}: {ex.Message}");

                    if (ex.InnerException is not null)
                    {
                        response.Errors.Add(
                            $"{ex.InnerException.GetType().Name}: {ex.InnerException.Message}");
                    }
                }

                await context.Response.WriteAsync(
                    JsonSerializer.Serialize(response, JsonOptions));
            }
        }
    }
}
