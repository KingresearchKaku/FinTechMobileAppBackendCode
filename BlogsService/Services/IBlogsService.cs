using BlogsService.Dtos;
using Shared.Common;

namespace BlogsService.Services
{
    public interface IBlogsService
    {
        Task<ApiResponse<CreateBlogRequestDto>> CreateBlog(CreateBlogRequestDto request);
        Task<ApiResponse<BlogListResponseDto>> GetAllBlogs(GetBlogRequestDto request);
        Task<ApiResponse<ManageBlogResponseDto>> ManageBlog(ManageBlogRequestDto request);
        Task<ApiResponse<bool>> DeleteBlogById(int blogId);
        Task<ApiResponse<bool>> ManageLikeBlogById(int blogId);

        Task<ApiResponse<bool>> AddComment(AddCommentRequestDto request);
        Task<ApiResponse<bool>> ManageCommentBlogById(UpdateCommentRequestDto request);
        Task<ApiResponse<CommentListResponseDto>> GetComments(GetCommentsRequestDto request);
        Task<ApiResponse<bool>> DeleteCommentBlogById(int blogId, int commentId);
    }
}
