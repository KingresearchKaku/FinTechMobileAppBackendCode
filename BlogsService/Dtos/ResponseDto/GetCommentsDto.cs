namespace BlogsService.Dtos
{
    public class CommentResponseDto
    {
        public int Id { get; set; }
        public string? Message { get; set; }
        public string? UserName { get; set; }
        public DateTime CreatedAt { get; set; }
    }

    public class CommentListResponseDto
    {
        public List<CommentResponseDto> Comments { get; set; } = [];
        public int TotalCount { get; set; }
        public int PageNumber { get; set; }
        public int PageSize { get; set; }
    }
}
