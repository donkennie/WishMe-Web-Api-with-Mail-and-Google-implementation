using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WishME.Model
{
    public class UserManagerResponse
    {

        public string Message { get; set; }

        public bool IsSuccess { get; set; }

        public IEnumerable<string> Errors { get; set; }

        public DateTime? ExpireDate { get; set; }
    }
}
