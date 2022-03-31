using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace WishME.Model
{
    public class LoginModel
    {


        [EmailAddress]
        [StringLength(50)]
        [Required(ErrorMessage = "Email is a required field")]
        public string Email { get; set; }

        [DataType(DataType.Password)]
        [StringLength(50, MinimumLength = 6)]
        [Required(ErrorMessage = "Password is a required field")]
        public string Password { get; set; }
    }
}
