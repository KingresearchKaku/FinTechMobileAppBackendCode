using BlogsService.Dtos;
using BlogsService.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace BlogsService.Controllers
{
    [Authorize]
    [Route("api/blogs")]
    [ApiController]
    [EnableRateLimiting("otp")]
    public class BlogsController : ControllerBase
    {
        private readonly IBlogsService _blogsService;

        public BlogsController(IBlogsService blogsService)
        {
            _blogsService = blogsService;
        }

        /// <summary>Create a new blog post.</summary>
        [HttpPost("add-blog")]
        public async Task<IActionResult> CreateBlog([FromBody] CreateBlogRequestDto request) =>
            Ok(await _blogsService.CreateBlog(request));

        /// <summary>List blogs with pagination.</summary>
        [HttpGet("get-all-blogs")]
        public async Task<IActionResult> GetAllBlogs([FromQuery] GetBlogRequestDto request) =>
            Ok(await _blogsService.GetAllBlogs(request));

        /// <summary>Update an existing blog post (owner only).</summary>
        [HttpPut("update-blog/{id:int}")]
        public async Task<IActionResult> UpdateBlog(int id, [FromBody] ManageBlogRequestDto request)
        {
            // Route id is authoritative — prevent body/route mismatch
            request.Id = id;
            return Ok(await _blogsService.ManageBlog(request));
        }

        /// <summary>Soft-delete a blog post (owner only).</summary>
        [HttpDelete("delete-blog/{id:int}")]
        public async Task<IActionResult> DeleteBlog(int id) =>
            Ok(await _blogsService.DeleteBlogById(id));

        /// <summary>Toggle like/unlike on a blog post.</summary>
        [HttpPost("toggle-like/{id:int}")]
        public async Task<IActionResult> ToggleLike(int id) =>
            Ok(await _blogsService.ManageLikeBlogById(id));

        /// <summary>List comments for a blog post (paginated, flat list).</summary>
        [HttpGet("get-comments/{id:int}")]
        public async Task<IActionResult> GetComments(int id, [FromQuery] GetCommentsRequestDto request)
        {
            request.BlogId = id;
            return Ok(await _blogsService.GetComments(request));
        }

        /// <summary>Add a comment to a blog post.</summary>
        [HttpPost("add-comment/{id:int}")]
        public async Task<IActionResult> AddComment(int id, [FromBody] AddCommentRequestDto request)
        {
            request.BlogId = id;
            return Ok(await _blogsService.AddComment(request));
        }

        /// <summary>Edit a comment (author only).</summary>
        [HttpPut("update-comment")]
        public async Task<IActionResult> UpdateComment(
            int id,
            int commentId,
            [FromBody] UpdateCommentRequestDto request)
        {
            request.BlogId = id;
            request.CommentId = commentId;
            return Ok(await _blogsService.ManageCommentBlogById(request));
        }

        /// <summary>Soft-delete a comment (author or blog owner).</summary>
        [HttpDelete("delete-comment")]
        public async Task<IActionResult> DeleteComment(int id, int commentId) =>
            Ok(await _blogsService.DeleteCommentBlogById(id, commentId));
    }
}
