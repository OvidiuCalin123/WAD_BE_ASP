using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;

namespace WAD_Backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginUserController : ControllerBase
    {

        private readonly ApplicationDbContext _context;


        public LoginUserController(ApplicationDbContext context)
        {
            _context = context;
        }


        [HttpGet]
        public IActionResult Get([FromQuery] string email, [FromQuery] string password)
        {
            var users = _context.LoginUser.ToList();

            var filteredUsers = users.Where(user => user.Email == email && user.Password == password).ToList();

            if (filteredUsers.Any())
            {
                return Ok(filteredUsers);
            }
            else
            {
                return NotFound();
            }
        }

        // POST api/<LoginController>
        [HttpPost]
        public void Post([FromBody] string value)
        {
        }

        // PUT api/<LoginController>/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/<LoginController>/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
