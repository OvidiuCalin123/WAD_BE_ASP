﻿using Microsoft.EntityFrameworkCore;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {
    }

    public DbSet<LoginUserModel> LoginUser { get; set; }
    public DbSet<JobPostingsModel> JobPostings { get; set; }
}