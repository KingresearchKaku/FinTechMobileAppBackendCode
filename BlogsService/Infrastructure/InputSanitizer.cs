using System.Net;
using Ganss.Xss;

namespace BlogsService.Infrastructure
{
    /// <summary>
    /// Centralised input sanitisation. All user-supplied text/HTML/URLs that ends up
    /// stored in the database (or rendered back to clients) MUST go through this.
    /// </summary>
    public static class InputSanitizer
    {
        // Single shared instance — HtmlSanitizer is thread-safe.
        private static readonly HtmlSanitizer Sanitizer = CreateSanitizer();

        private static HtmlSanitizer CreateSanitizer()
        {
            var s = new HtmlSanitizer();

            // Lock URL schemes to safe ones — blocks javascript:, data:, vbscript:, etc.
            s.AllowedSchemes.Clear();
            s.AllowedSchemes.Add("http");
            s.AllowedSchemes.Add("https");
            s.AllowedSchemes.Add("mailto");

            // Forbid event handlers (onclick, onerror, onload, …) — attackers' favourite XSS vector.
            s.AllowedAttributes.Remove("style");
            foreach (var attr in s.AllowedAttributes.Where(a => a.StartsWith("on")).ToList())
                s.AllowedAttributes.Remove(attr);

            return s;
        }

        /// <summary>
        /// For rich-text fields (blog Content). Allows safe HTML tags, strips scripts/iframes/event-handlers.
        /// </summary>
        public static string SanitizeHtml(string? input) =>
            string.IsNullOrEmpty(input) ? string.Empty : Sanitizer.Sanitize(input);

        /// <summary>
        /// For plain-text fields (Title, comment Message, UserName). HTML-encodes everything,
        /// so even if the client renders it raw, no script can execute.
        /// </summary>
        public static string SanitizeText(string? input) =>
            string.IsNullOrEmpty(input) ? string.Empty : WebUtility.HtmlEncode(input.Trim());

        /// <summary>
        /// Validates an image URL. Accepts only absolute http/https URLs.
        /// Returns null for invalid input — caller decides whether that's a 400 or default image.
        /// </summary>
        public static string? SanitizeImageUrl(string? input)
        {
            if (string.IsNullOrWhiteSpace(input)) return null;

            if (!Uri.TryCreate(input.Trim(), UriKind.Absolute, out var uri)) return null;
            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) return null;

            return uri.ToString();
        }
    }
}
