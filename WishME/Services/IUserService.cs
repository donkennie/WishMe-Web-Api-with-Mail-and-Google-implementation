using System.Threading.Tasks;
using WishME.Model;

namespace WishME.Services
{
    public interface IUserService
    {

        Task<UserManagerResponse> RegisterUserAsync(RegisterModel model);
        Task<UserManagerResponse> LoginUserAsync(LoginModel model);
        Task<UserManagerResponse> ConfirmEmailAsync(string userId, string token);
        Task<UserManagerResponse> ForgotPasswordAsync(string email);
        Task<UserManagerResponse> ResetPasswordAsync(ResetPasswordModel model);

    }
}
