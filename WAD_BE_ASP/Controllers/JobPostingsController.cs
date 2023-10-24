using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace WAD_Backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class JobPostingsController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;

        public JobPostingsController(ApplicationDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        [HttpGet]
        public IActionResult Get()
        {
            var token = Request.Headers["Authorization"].FirstOrDefault()?.Replace("Bearer ", "");

            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]);
                var validationParameters = new TokenValidationParameters
                {
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                };

                var principal = tokenHandler.ValidateToken(token, validationParameters, out _);

                var email = principal.Identity.Name;

                var user = _context.LoginUser.FirstOrDefault(u => u.Email == email);

                if (user != null)
                {   
                    var jobPostings = _context.JobPostings.ToList();

                    if (jobPostings == null || jobPostings.Count == 0)
                    {
                        return NotFound();
                    }

                    return Ok(jobPostings);

                }
                else
                {
                    return NotFound("Job postings not found.");
                }
            }
            catch (Exception ex)
            {

                return BadRequest($"JWT validation failed: {ex.Message}");
            }

           
        }

        [HttpDelete("{id}")]
        public IActionResult Delete(int id)
        {
            try
            {
                var jobPosting = _context.JobPostings.Find(id);

                if (jobPosting == null)
                {
                    return NotFound();
                }

                _context.JobPostings.Remove(jobPosting);
                _context.SaveChanges();

                return Ok(NoContent());
            }
            catch (Exception ex)
            {
                return BadRequest($"An error occurred while deleting the job posting: {ex.Message}");
            }
        }

        [HttpPut("{id}")]
        public IActionResult Put(int id, [FromBody] JobPostingsModel updatedJobPosting)
        {
            try
            {
                var existingJobPosting = _context.JobPostings.Find(id);

                if (existingJobPosting == null)
                {
                    return NotFound();
                }

               
                existingJobPosting.company = updatedJobPosting.company;
                existingJobPosting.salary = updatedJobPosting.salary;
                existingJobPosting.position = updatedJobPosting.position;
                existingJobPosting.location = updatedJobPosting.location;
                existingJobPosting.jobType = updatedJobPosting.jobType;
                existingJobPosting.dateEntered = updatedJobPosting.dateEntered;
                existingJobPosting.description = updatedJobPosting.description;

                _context.SaveChanges();

                return Ok(existingJobPosting);
            }
            catch (Exception ex)
            {
                return BadRequest($"An error occurred while updating the job posting: {ex.Message}");
            }
        }
    }
}
