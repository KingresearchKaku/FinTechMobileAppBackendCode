using System.ComponentModel.DataAnnotations;

namespace BlogsService.Dtos
{
    public class AddCommentRequestDto
    {
        [Required]
        public int BlogId { get; set; }

        [Required]
        [StringLength(2000, MinimumLength = 1, ErrorMessage = "Comment must be 1-2000 characters.")]
        public string Message { get; set; } = null!;
    }

    public class UpdateCommentRequestDto
    {
        [Required]
        public int BlogId { get; set; }

        [Required]
        public int CommentId { get; set; }

        [Required]
        [StringLength(2000, MinimumLength = 1, ErrorMessage = "Comment must be 1-2000 characters.")]
        public string Message { get; set; } = null!;
    }
}
