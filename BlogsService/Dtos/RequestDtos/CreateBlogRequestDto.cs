using System.ComponentModel.DataAnnotations;

namespace BlogsService.Dtos
{
    public class CreateBlogRequestDto
    {
        [Required]
        [StringLength(200, MinimumLength = 3, ErrorMessage = "Title must be 3-200 characters.")]
        public string Title { get; set; } = null!;

        [Required]
        [StringLength(50_000, MinimumLength = 10, ErrorMessage = "Content must be 10-50000 characters.")]
        public string Content { get; set; } = null!;

        [Url(ErrorMessage = "ImageUrl must be a valid http/https URL.")]
        [StringLength(2048)]
        public string? ImageUrl { get; set; }
    }
}
