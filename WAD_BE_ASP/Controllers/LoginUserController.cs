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


        [HttpPost]
        public IActionResult Post([FromQuery] string name, [FromQuery] string email, [FromQuery] string password)
        {
            try
            {
                var newUser = new LoginUserModel
                {
                    Name = name,
                    Email = email,
                    Password = password
                };

                _context.LoginUser.Add(newUser);
                _context.SaveChanges();

                return Ok("User created successfully.");
            }
            catch (Exception ex)
            {
                return BadRequest($"Error: {ex.Message}");
            }
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
