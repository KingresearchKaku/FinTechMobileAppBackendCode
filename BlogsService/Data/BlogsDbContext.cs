using BlogsService.Models;
using Microsoft.EntityFrameworkCore;

namespace BlogsService.Data
{
    public class BlogsDbContext : DbContext
    {
        public BlogsDbContext(DbContextOptions<BlogsDbContext> options) : base(options) { }

        public DbSet<Blog> Blogs { get; set; }
        public DbSet<BlogLikes> BlogLikes { get; set; }
        public DbSet<Comments> Comments { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // ── Blog ──────────────────────────────────────────────────────────
            modelBuilder.Entity<Blog>(entity =>
            {
                entity.HasKey(e => e.Id);

                entity.Property(e => e.Title).IsRequired().HasMaxLength(200);
                entity.Property(e => e.Content).IsRequired();
                entity.Property(e => e.AuthorName).HasMaxLength(100);
                entity.Property(e => e.AuthorDescription).HasMaxLength(500);
                entity.Property(e => e.ImageUrl).HasMaxLength(2048);
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.IsDeleted).HasDefaultValue(false);

                entity.HasIndex(e => e.CreatedBy).HasDatabaseName("IX_Blogs_CreatedBy");
                entity.HasIndex(e => e.CreatedAt).HasDatabaseName("IX_Blogs_CreatedAt");
                entity.HasIndex(e => e.IsDeleted).HasDatabaseName("IX_Blogs_IsDeleted");

                // Soft-delete filter — deleted blogs are invisible to all queries
                entity.HasQueryFilter(e => !e.IsDeleted);
            });

            // ── BlogLikes ─────────────────────────────────────────────────────
            modelBuilder.Entity<BlogLikes>(entity =>
            {
                entity.HasKey(e => e.Id);

                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");

                // Unique composite index — DB-enforced "one like per user per blog",
                // closes the race-condition window for double-likes.
                entity.HasIndex(e => new { e.BlogId, e.UserId })
                    .IsUnique()
                    .HasDatabaseName("UX_BlogLikes_Blog_User");

                entity.HasIndex(e => e.UserId).HasDatabaseName("IX_BlogLikes_UserId");

                // Restrict on Blog delete — soft-delete is the only delete pattern.
                entity.HasOne(e => e.Blog)
                    .WithMany()
                    .HasForeignKey(e => e.BlogId)
                    .OnDelete(DeleteBehavior.Restrict);
            });

            // ── Comments ──────────────────────────────────────────────────────
            modelBuilder.Entity<Comments>(entity =>
            {
                entity.HasKey(e => e.Id);

                entity.Property(e => e.Message).IsRequired().HasMaxLength(2000);
                entity.Property(e => e.UserName).HasMaxLength(100);
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.IsDeleted).HasDefaultValue(false);

                entity.HasIndex(e => e.BlogId).HasDatabaseName("IX_Comments_BlogId");
                entity.HasIndex(e => e.UserId).HasDatabaseName("IX_Comments_UserId");
                entity.HasIndex(e => e.CreatedAt).HasDatabaseName("IX_Comments_CreatedAt");

                entity.HasOne(e => e.Blog)
                    .WithMany()
                    .HasForeignKey(e => e.BlogId)
                    .OnDelete(DeleteBehavior.Restrict);

                // Soft-delete filter — deleted comments are invisible to all queries
                entity.HasQueryFilter(e => !e.IsDeleted);
            });

            base.OnModelCreating(modelBuilder);
        }
    }
}
