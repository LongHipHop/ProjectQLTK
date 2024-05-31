using System.Text.Json;
using QLTK.Models;

namespace QLTK.Helper
{
    public class AccountSessionManager
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AccountSessionManager(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        public Account? GetCurrentAccount()
        {
            var userData = _httpContextAccessor?.HttpContext?.Session.GetString("CurrentAccount");
            return userData == null ? null : JsonSerializer.Deserialize<Account>(userData);
        }
    }
}
