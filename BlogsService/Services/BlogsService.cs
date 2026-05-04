
using System.Security.Claims;
using BlogsService.Data;
using BlogsService.Dtos;
using BlogsService.Infrastructure;
using BlogsService.Models;
using Microsoft.EntityFrameworkCore;
using Shared.Common;

namespace BlogsService.Services
{
    public class BlogsService : IBlogsService
    {

        private readonly BlogsDbContext _context;
        private readonly IHttpContextAccessor _httpContextAccessor;
        public BlogsService(BlogsDbContext context, IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _httpContextAccessor = httpContextAccessor;
        }

        //Method to Get GUID of the currently logged in user from the JWT token
        private Guid GetUserIdFromToken()
        {
            var claim = _httpContextAccessor.HttpContext?.User
              .FindFirst(ClaimTypes.NameIdentifier)?.Value;
            return Guid.TryParse(claim, out var userId) ? userId : Guid.Empty;

        }

        // Reads the user's display name from the JWT 'name' claim issued by AuthService.
        // Falls back to "Anonymous" if the token doesn't carry it (older tokens / not yet registered).
        private string GetUserNameFromToken() =>
            _httpContextAccessor.HttpContext?.User.FindFirst(ClaimTypes.Name)?.Value
            ?? "Anonymous";



        //Create Blog
        public async Task<ApiResponse<CreateBlogRequestDto>> CreateBlog(CreateBlogRequestDto request)
        {
            var userId = GetUserIdFromToken();
            if (userId == Guid.Empty)
                return ApiResponse<CreateBlogRequestDto>.Fail("Unauthorized.", 401);
            if (request.Title == null || request.Content == null)
                return ApiResponse<CreateBlogRequestDto>.Fail("Title and Content are required.", 400);

            // Reject javascript: / data: / etc. — only http(s) URLs allowed.
            var safeImageUrl = InputSanitizer.SanitizeImageUrl(request.ImageUrl);
            if (!string.IsNullOrWhiteSpace(request.ImageUrl) && safeImageUrl is null)
                return ApiResponse<CreateBlogRequestDto>.Fail(
                    "ImageUrl must be a valid http/https URL.", 400);

            var blog = new Blog
            {
                Title = InputSanitizer.SanitizeText(request.Title),
                Content = InputSanitizer.SanitizeHtml(request.Content),
                ImageUrl = safeImageUrl ?? string.Empty,
                AuthorName = GetUserNameFromToken(),
                AuthorDescription = string.Empty,
                CreatedAt = DateTime.UtcNow,
                CreatedBy = userId,
            };
            await _context.Blogs.AddAsync(blog);
            await _context.SaveChangesAsync();

            return ApiResponse<CreateBlogRequestDto>.Ok(new CreateBlogRequestDto
            {
                Title = blog.Title,
                Content = blog.Content,
                ImageUrl = blog.ImageUrl
            });
        }


        public async Task<ApiResponse<BlogListResponseDto>> GetAllBlogs(GetBlogRequestDto getBlogRequestDto)
        {

            var userId = GetUserIdFromToken();
            if (userId == Guid.Empty)
                return ApiResponse<BlogListResponseDto>.Fail("Unauthorized.", 401);

            var pageNumber = getBlogRequestDto.PageNumber <= 0 ? 1 : getBlogRequestDto.PageNumber;
            var pageSize = getBlogRequestDto.PageSize <= 0 ? 10 : getBlogRequestDto.PageSize;
            var query = _context.Blogs.AsNoTracking();

            // Global query filter handles !IsDeleted, so this counts only live blogs.
            var totalBlogs = await query.CountAsync();

            var likedBlogIds = await _context.BlogLikes
                .Where(l => l.UserId == userId)
                .Select(l => l.BlogId)
                .ToListAsync();

            var blogs = await query
                .OrderByDescending(b => b.CreatedAt)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .Select(x => new BlogResponseDto
                {
                    Id = x.Id,
                    Title = x.Title,
                    Content = x.Content,
                    ImageUrl = x.ImageUrl,
                    CreatedAt = x.CreatedAt,
                    Author = new AuthorDto
                    {
                        Name = x.AuthorName,
                        Description = x.AuthorDescription
                    },
                    LikesCount = x.LikesCount,
                    CommentsCount = x.CommentsCount, // cached column — no per-row subquery
                    IsLikedByCurrentUser = likedBlogIds.Contains(x.Id),
                })
                .ToListAsync();


            return ApiResponse<BlogListResponseDto>.Ok(new BlogListResponseDto
            {
                Blogs = blogs,
                TotalCount = totalBlogs,
                PageNumber = pageNumber,
                PageSize = pageSize
            });

        }

        //Method Manage the Blog (Create/Update)
        public async Task<ApiResponse<ManageBlogResponseDto>> ManageBlog(ManageBlogRequestDto request)
        {
            var userId = GetUserIdFromToken();
            if (userId == Guid.Empty)
                return ApiResponse<ManageBlogResponseDto>.Fail("Unauthorized.", 401);

            var blog = await _context.Blogs
                .FirstOrDefaultAsync(b => b.Id == request.Id && !b.IsDeleted);

            if (blog == null)
                return ApiResponse<ManageBlogResponseDto>.Fail("Blog not found.", 404);

            // 🔐 Only the blog's owner can update it
            if (blog.CreatedBy != userId)
                return ApiResponse<ManageBlogResponseDto>.Fail("Forbidden.", 403);

            blog.Title = InputSanitizer.SanitizeText(request.Title);
            blog.Content = InputSanitizer.SanitizeHtml(request.Content);
            blog.UpdatedAt = DateTime.UtcNow;
            // Do NOT touch CreatedBy — ownership is immutable.

            await _context.SaveChangesAsync();



            return ApiResponse<ManageBlogResponseDto>.Ok(new ManageBlogResponseDto
            {
                Id = blog.Id,
                Title = blog.Title,
                Content = blog.Content
            });

        }


        public async Task<ApiResponse<bool>> DeleteBlogById(int blogId)
        {
            var userId = GetUserIdFromToken();
            if (userId == Guid.Empty)
                return ApiResponse<bool>.Fail("Unauthorized.", 401);

            // ✅ Get blog first
            var blog = await _context.Blogs
                .FirstOrDefaultAsync(b => b.Id == blogId && !b.IsDeleted);

            if (blog == null)
                return ApiResponse<bool>.Fail("Blog not found", 404);

            // 🔐 Only owner can delete
            if (blog.CreatedBy != userId)
                return ApiResponse<bool>.Fail("Forbidden", 403);

            // ✅ Soft delete
            blog.IsDeleted = true;
            blog.DeletedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();

            return ApiResponse<bool>.Ok(true, "Blog deleted successfully");




        }





        public async Task<ApiResponse<bool>> ManageCommentBlogById(UpdateCommentRequestDto request)
        {
            var userId = GetUserIdFromToken();
            if (userId == Guid.Empty)
                return ApiResponse<bool>.Fail("Unauthorized.", 401);

            // Single round-trip — fetch the comment scoped to the blog
            var comment = await _context.Comments
                .FirstOrDefaultAsync(c => c.Id == request.CommentId && c.BlogId == request.BlogId);

            if (comment == null)
                return ApiResponse<bool>.Fail("Comment not found.", 404);

            // 🔐 Only the author can edit their own comment
            if (comment.UserId != userId)
                return ApiResponse<bool>.Fail("Forbidden.", 403);

            comment.Message = InputSanitizer.SanitizeText(request.Message);
            comment.UpdatedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();
            return ApiResponse<bool>.Ok(true, "Comment updated successfully.");
        }

        public async Task<ApiResponse<bool>> ManageLikeBlogById(int blogId)
        {
            var userId = GetUserIdFromToken();
            if (userId == Guid.Empty)
                return ApiResponse<bool>.Fail("Unauthorized.", 401);

            var blog = await _context.Blogs.FirstOrDefaultAsync(b => b.Id == blogId);
            if (blog == null)
                return ApiResponse<bool>.Fail("Blog not found.", 404);

            var existingLike = await _context.BlogLikes
                .FirstOrDefaultAsync(x => x.BlogId == blogId && x.UserId == userId);

            bool isLiked;
            if (existingLike != null)
            {
                _context.BlogLikes.Remove(existingLike);
                if (blog.LikesCount > 0) blog.LikesCount--;
                isLiked = false;
            }
            else
            {
                _context.BlogLikes.Add(new BlogLikes
                {
                    BlogId = blogId,
                    UserId = userId,
                    CreatedAt = DateTime.UtcNow
                });
                blog.LikesCount++;
                isLiked = true;
            }

            // SaveChangesAsync is already atomic. The unique index UX_BlogLikes_Blog_User
            // makes concurrent double-likes fail with a DbUpdateException at the DB level.
            await _context.SaveChangesAsync();

            return ApiResponse<bool>.Ok(isLiked, "Like status updated.");
        }


        //Method to Add the Comment
        public async Task<ApiResponse<bool>> AddComment(AddCommentRequestDto request)
        {
            var userId = GetUserIdFromToken();
            if (userId == Guid.Empty)
                return ApiResponse<bool>.Fail("Unauthorized.", 401);

            var blog = await _context.Blogs.FirstOrDefaultAsync(b => b.Id == request.BlogId);
            if (blog == null)
                return ApiResponse<bool>.Fail("Blog not found.", 404);

            var comment = new Comments
            {
                Message = InputSanitizer.SanitizeText(request.Message),
                BlogId = request.BlogId,
                UserId = userId,
                UserName = GetUserNameFromToken(),
                CreatedAt = DateTime.UtcNow
            };

            _context.Comments.Add(comment);
            blog.CommentsCount++; // keep cached count in sync

            await _context.SaveChangesAsync();
            return ApiResponse<bool>.Ok(true, "Comment added successfully.");
        }


        //Method to returning all comments from Selected blog
        public async Task<ApiResponse<CommentListResponseDto>> GetComments(GetCommentsRequestDto request)
        {
            var userId = GetUserIdFromToken();
            if (userId == Guid.Empty)
                return ApiResponse<CommentListResponseDto>.Fail("Unauthorized.", 401);

            var blogExists = await _context.Blogs.AnyAsync(b => b.Id == request.BlogId);
            if (!blogExists)
                return ApiResponse<CommentListResponseDto>.Fail("Blog not found.", 404);

            var pageNumber = request.PageNumber <= 0 ? 1 : request.PageNumber;
            var pageSize = request.PageSize <= 0 ? 10 : request.PageSize;

            // Soft-deleted comments are filtered out by the global query filter.
            var query = _context.Comments
                .AsNoTracking()
                .Where(c => c.BlogId == request.BlogId);

            var totalCount = await query.CountAsync();

            var comments = await query
                .OrderByDescending(c => c.CreatedAt)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .Select(x => new CommentResponseDto
                {
                    Id = x.Id,
                    Message = x.Message,
                    UserName = x.UserName ?? "Anonymous",
                    CreatedAt = x.CreatedAt
                })
                .ToListAsync();

            return ApiResponse<CommentListResponseDto>.Ok(
                new CommentListResponseDto
                {
                    Comments = comments,
                    TotalCount = totalCount,
                    PageNumber = pageNumber,
                    PageSize = pageSize
                },
                "Comments fetched successfully.");
        }



        public async Task<ApiResponse<bool>> DeleteCommentBlogById(int blogId, int commentId)
        {
            var userId = GetUserIdFromToken();
            if (userId == Guid.Empty)
                return ApiResponse<bool>.Fail("Unauthorized.", 401);

            var comment = await _context.Comments
                .FirstOrDefaultAsync(c => c.Id == commentId && c.BlogId == blogId);
            if (comment == null)
                return ApiResponse<bool>.Fail("Comment not found.", 404);

            // Tracked because we'll decrement CommentsCount in the same SaveChanges.
            var blog = await _context.Blogs.FirstOrDefaultAsync(b => b.Id == blogId);
            if (blog == null)
                return ApiResponse<bool>.Fail("Blog not found.", 404);

            // 🔐 Comment author OR blog owner can delete
            if (comment.UserId != userId && blog.CreatedBy != userId)
                return ApiResponse<bool>.Fail("Forbidden.", 403);

            // Soft delete + keep cached count consistent
            comment.IsDeleted = true;
            comment.DeletedAt = DateTime.UtcNow;
            if (blog.CommentsCount > 0) blog.CommentsCount--;

            await _context.SaveChangesAsync();
            return ApiResponse<bool>.Ok(true, "Comment deleted.");
        }




    }
}
