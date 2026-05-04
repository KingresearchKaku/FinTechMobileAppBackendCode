namespace BlogsService.Dtos
{
    public class GetCommentsRequestDto
    {
        public int BlogId {get; set;}
        public int PageNumber { get; set; } = 1;
        public int PageSize { get; set; } = 10;
  }
}
