namespace BlogsService.Models
{

    public class Blog
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public string Content { get; set; }

        public string AuthorName { get; set; }
        public string AuthorDescription { get; set; }

        public Guid CreatedBy { get; set; }
        public string ImageUrl { get; set; }

        public int LikesCount { get; set; }
        public int CommentsCount { get; set; }

        public bool IsDeleted { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        public DateTime? DeletedAt { get; set; }


    }

    public class BlogLikes
    {
        public int Id { get; set; }
        public int BlogId { get; set; }
        public Guid UserId { get; set; }
        public DateTime CreatedAt { get; set; }

        public Blog Blog { get; set; }

    }

    public class Comments
    {
        public int Id { get; set; }
        public int BlogId { get; set; }

        public string Message { get; set; }
        public string UserName { get; set; }

        public Guid UserId { get; set; }

        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }

        public bool IsDeleted { get; set; }
        public DateTime? DeletedAt { get; set; }

        public Blog Blog { get; set; }
    }
}





//   CREATE TABLE Blogs (
//     Id INT IDENTITY(1,1) PRIMARY KEY,
//     Title NVARCHAR(200) NOT NULL,
//     Content NVARCHAR(MAX),
//     AuthorName NVARCHAR(100),
//     AuthorDescription NVARCHAR(500),
//     CreatedBy UNIQUEIDENTIFIER NOT NULL,
//     ImageUrl NVARCHAR(500),

//     LikesCount INT DEFAULT 0,
//     CommentsCount INT DEFAULT 0,

//     IsDeleted BIT DEFAULT 0,
//     CreatedAt DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
//     UpdatedAt DATETIME2,
//     DeletedAt DATETIME2 NULL
// );


// CREATE TABLE BlogLikes (
//     Id INT IDENTITY(1,1) PRIMARY KEY,
//     BlogId INT NOT NULL,
//     UserId UNIQUEIDENTIFIER NOT NULL,
//     CreatedAt DATETIME2 NOT NULL DEFAULT GETUTCDATE(),

//     CONSTRAINT FK_BlogLikes_Blog FOREIGN KEY (BlogId) REFERENCES Blogs(Id)
// );


// CREATE TABLE Comments (
//     Id INT IDENTITY(1,1) PRIMARY KEY,
//     BlogId INT NOT NULL,
//     Message NVARCHAR(MAX),
//     UserName NVARCHAR(100),
//     UserId UNIQUEIDENTIFIER NOT NULL,

//     CreatedAt DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
//     UpdatedAt DATETIME2,

//     IsDeleted BIT DEFAULT 0,
//     DeletedAt DATETIME2 NULL,

//     CONSTRAINT FK_Comments_Blog FOREIGN KEY (BlogId) REFERENCES Blogs(Id)
// );