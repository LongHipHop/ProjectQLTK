using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using QLTK.Helper;
using QLTK.Models;
using Microsoft.IdentityModel.Tokens;

namespace QLTK.Controllers
{
    public class AccountsController : Controller
    {
        private readonly AccountSessionManager _accountSessionManager;
        private readonly FptLoginAppContext _context;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IMemoryCache _cache;
        public AccountsController(FptLoginAppContext context, IHttpContextAccessor httpContextAccessor, IMemoryCache cache)
        {
            _context = context;
            _httpContextAccessor = httpContextAccessor;
            _cache = cache;
        }

        // GET: Accounts
        public async Task<IActionResult> Index()
        {
            return View(await _context.Accounts.ToListAsync());
        }

        // GET: Accounts/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var account = await _context.Accounts
                .FirstOrDefaultAsync(m => m.Id == id);
            if (account == null)
            {
                return NotFound();
            }

            return View(account);
        }

        // GET: Accounts/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Accounts/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,Username,Password,ConfirmPassword,Fullname,Email,Phone,Gender,Birtday,Address,Image,Userstatus,CreateAt,UpdateAt,RoleId")] Account account)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return View(account);
                }

                // Kiểm tra mật khẩu rỗng
                if (string.IsNullOrEmpty(account.Password))
                {
                    ModelState.AddModelError("Password", "Password is required.");
                    return View(account);
                }

                // Kiểm tra xác nhận mật khẩu rỗng
                if (string.IsNullOrEmpty(account.ConfirmPassword))
                {
                    ModelState.AddModelError("ConfirmPassword", "Confirm password is required.");
                    return View(account);
                }

                // Kiểm tra định dạng email hợp lệ
                if (!IsValidEmail(account.Email))
                {
                    ModelState.AddModelError("Email", "Invalid email address.");
                    return View(account);
                }

                // Kiểm tra xác nhận mật khẩu khớp
                if (account.Password != account.ConfirmPassword)
                {
                    ModelState.AddModelError("ConfirmPassword", "Confirm password does not match the password.");
                    return View(account);
                }

                // Hash mật khẩu
                account.Password = GetMd5Hash(account.Password);

                // Thiết lập ngày hiện tại cho CreateAt và UpdateAt
                account.Userstatus = "Online";
                account.CreateAt = DateOnly.FromDateTime(DateTime.Now);
                account.UpdateAt = DateOnly.FromDateTime(DateTime.Now);

                // Thiết lập RoleId
                account.RoleId = 2; // Hoặc giá trị mặc định khác

                _context.Add(account);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", "An error occurred while processing your request.");
                return View(account);
            }
        }

        // GET: Accounts/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var account = await _context.Accounts.FindAsync(id);
            if (account == null)
            {
                return NotFound();
            }
            return View(account);
        }

        // POST: Accounts/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,Username,Fullname,Email,Phone,Gender,Birtday,Address,Image,RoleId")] Account account)
        {
            if (id != account.Id)
            {
                return NotFound();
            }

            var existingAccount = await _context.Accounts.FindAsync(id);
            if (existingAccount == null)
            {
                return NotFound();
            }

            // Cập nhật các trường cần thay đổi
            existingAccount.Fullname = account.Fullname;
            existingAccount.Phone = account.Phone;
            existingAccount.Gender = account.Gender;
            existingAccount.Birtday = account.Birtday;
            existingAccount.Address = account.Address;
            existingAccount.Image = account.Image;
            existingAccount.UpdateAt = DateOnly.FromDateTime(DateTime.Now);
            existingAccount.RoleId = account.RoleId;
            if (!ModelState.IsValid)
            {
                try
                {
                    _context.Update(existingAccount);
                    await _context.SaveChangesAsync();

                    TempData["SuccessMessage"] = "Thông tin cá nhân đã được cập nhật thành công.";

                    return RedirectToAction(nameof(Index));
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!AccountExists(account.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
            }

            return View(account);
        }

        // GET: Accounts/Edit/5
        public async Task<IActionResult> EditProfile(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var account = await _context.Accounts.FindAsync(id);
            if (account == null)
            {
                return NotFound();
            }
            return View(account);
        }

        // POST: Accounts/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditProfile(int id, [Bind("Id,Username,Fullname,Email,Phone,Gender,Birtday,Address,Image")] Account account)
        {
            if (id != account.Id)
            {
                return NotFound();
            }

            var existingAccount = await _context.Accounts.FindAsync(id);
            if (existingAccount == null)
            {
                return NotFound();
            }

            // Cập nhật các trường cần thay đổi
            existingAccount.Fullname = account.Fullname;
            existingAccount.Phone = account.Phone;
            existingAccount.Gender = account.Gender;
            existingAccount.Birtday = account.Birtday;
            existingAccount.Address = account.Address;
            existingAccount.Image = account.Image;
            existingAccount.UpdateAt = DateOnly.FromDateTime(DateTime.Now);

            if (!ModelState.IsValid)
            {
                try
                {
                    _context.Update(existingAccount);
                    await _context.SaveChangesAsync();

                    TempData["SuccessMessage"] = "Thông tin cá nhân đã được cập nhật thành công.";
                    return RedirectToAction("ProfileUser", new { id = account.Id });
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!AccountExists(account.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
            }

            return View(account);
        }


        // GET: Accounts/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var account = await _context.Accounts
                .FirstOrDefaultAsync(m => m.Id == id);
            if (account == null)
            {
                return NotFound();
            }

            return View(account);
        }

        // POST: Accounts/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var account = await _context.Accounts.FindAsync(id);
            if (account != null)
            {
                _context.Accounts.Remove(account);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool AccountExists(int id)
        {
            return _context.Accounts.Any(e => e.Id == id);
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(string email, string password)
        {
            // Check for empty fields
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
            {
                ModelState.AddModelError("", "Email và mật khẩu không được để trống.");
                return View();
            }

            // Check for valid email format
            if (!IsValidEmail(email))
            {
                ModelState.AddModelError("", "Định dạng email không hợp lệ.");
                return View();
            }

            try
            {
                var user = _context.Accounts.SingleOrDefault(u => u.Email == email);

                if (user != null)
                {
                    // Create MD5 hash from the input password
                    string hashedPasswordInput = GetMd5Hash(password);

                    // Compare the hashed input password with the stored password
                    if (user.Password == hashedPasswordInput)
                    {
                        var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, email)
                    // Add other claims if needed
                };

                        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                        var principal = new ClaimsPrincipal(identity);

                        await _httpContextAccessor.HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, new AuthenticationProperties
                        {
                            IsPersistent = true // Cookie will persist after closing the browser
                        });

                        // Create session to store non-sensitive user information
                        _httpContextAccessor.HttpContext.Session.SetString("Email", email);

                        // Redirect to a default page or dashboard after successful login
                        switch (user.RoleId)
                        {
                            case 1:
                                return RedirectToAction("Index", "Accounts");
                            case 2:
                                return RedirectToAction("ProfileUser", "Accounts", new { id = user.Id });
                            case 3:
                                return RedirectToAction("HRM", "Accounts", new { id = user.Id });
                            default:
                                return RedirectToAction("Login", "Accounts");
                        }
                    }
                    else
                    {
                        // Incorrect password
                        ModelState.AddModelError("", "Tên đăng nhập hoặc mật khẩu không đúng.");
                    }
                }
                else
                {
                    // User not found
                    ModelState.AddModelError("", "Tên đăng nhập hoặc mật khẩu không đúng.");
                }
            }
            catch (Exception ex)
            {
                // Log the exception
                // For example, using a logging framework like Serilog
                // Log.Error(ex, "An error occurred while logging in.");
                ModelState.AddModelError("", "Đã xảy ra lỗi trong quá trình đăng nhập. Vui lòng thử lại.");
            }

            return View();
        }



        // Hàm để lấy chuỗi MD5 của mật khẩu
        public static string GetMd5Hash(string input)
        {
            using (MD5 md5Hash = MD5.Create())
            {
                byte[] data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(input));

                StringBuilder sBuilder = new StringBuilder();

                for (int i = 0; i < data.Length; i++)
                {
                    sBuilder.Append(data[i].ToString("x2"));
                }

                return sBuilder.ToString();
            }
        }

        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            if (remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
                return RedirectToAction(nameof(Login));
            }

            var info = await HttpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme); // Phương thức AuthenticateAsync cần sử dụng GoogleDefaults.AuthenticationScheme
            if (info == null)
            {
                ModelState.AddModelError(string.Empty, "Error loading external login information.");
                return RedirectToAction(nameof(Login));
            }

            // Xử lý thông tin đăng nhập từ Google
            // ...

            return RedirectToAction("Index", "Home");
        }

        // login with google method  
        public IActionResult LoginWithGoogle()
        {
            string redirectUrl = Url.Action("GoogleResponse", "Accounts");
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        public async Task<IActionResult> GoogleResponse()
        {
            var authenticateResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (!authenticateResult.Succeeded)
                return BadRequest();

            var userInfo = new
            {
                Email = authenticateResult.Principal.FindFirstValue(ClaimTypes.Email),
                Name = authenticateResult.Principal.FindFirstValue(ClaimTypes.Name),
                GivenName = authenticateResult.Principal.FindFirstValue(ClaimTypes.GivenName),
            };

            if (userInfo != null)
            {
                var account = _context.Accounts.FirstOrDefault(x => x.Email == userInfo.Email);
                if (account == null)
                {
                    _httpContextAccessor.HttpContext.Session.SetString("Email", userInfo.Email);
                    _httpContextAccessor.HttpContext.Session.SetString("Name", userInfo.Name);
                    return RedirectToAction("CompleteProfile");
                }
                else
                {
                    switch (account.RoleId)
                    {
                        case 1:
                            {
                                return RedirectToAction("Index", "Accounts");
                                break;
                            }
                        case 2:
                            {
                                return RedirectToAction("ProfileUser", "Accounts", new { id = account.Id });
                                break;
                            }
                        case 3:
                            {
                                return RedirectToAction("HRM", "Accounts", new { id = account.Id });
                                break;
                            }
                        default:
                            return RedirectToAction("Login", "Accounts");
                    }
                }
            }

            return RedirectToAction("Login");
        }


        public IActionResult CompleteProfile()
        {
            var email = _httpContextAccessor.HttpContext.Session.GetString("Email");
            var name = _httpContextAccessor.HttpContext.Session.GetString("Name");
            if (string.IsNullOrEmpty(email))
            {
                return RedirectToAction("Login");
            }

            var model = new Account
            {
                Email = email,
                Fullname = name
            };

            return View(model);
        }   

        [HttpPost]
        public IActionResult CompleteProfile(Account model)
        {
            if (!ModelState.IsValid)
            {
                try
                {
                    var hashedPassword = GetMd5Hash(model.Password);

                    var account = new Account
                    {
                        Username = model.Username,
                        Fullname = model.Fullname,
                        Email = model.Email,
                        Phone = model.Phone,
                        Gender = model.Gender,
                        Birtday = model.Birtday,
                        Address = model.Address,
                        Image = model.Image,
                        Userstatus = "Online",
                        CreateAt = DateOnly.FromDateTime(DateTime.Now),
                        UpdateAt = DateOnly.FromDateTime(DateTime.Now),
                        Password = hashedPassword,
                        RoleId = 2 // Assuming a default role ID
                    };

                    _context.Accounts.Add(account);
                    _context.SaveChanges();
                    return RedirectToAction("Login", "Accounts");
                }
                catch (Exception ex)
                {
                    // Log the exception (ex) as needed
                    // For example, using a logging framework like Serilog
                    // Log.Error(ex, "An error occurred while creating the account.");
                    ViewBag.ErrorMessage = "An error occurred while creating the account. Please try again.";
                }
            }
            else
            {
                ViewBag.ErrorMessage = "Please correct the form errors and try again.";
            }

            return View(model);
        }


        //Logout
        public IActionResult Logout()
        {
            // Xóa thông tin đăng nhập
            HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            // Xóa hết session
            _httpContextAccessor.HttpContext.Session.Clear();

            // Chuyển hướng đến trang đăng nhập
            return RedirectToAction("Login", "Accounts");
        }


        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            var user = _context.Accounts.FirstOrDefault(u => u.Email == email);
            if (user == null)
            {
                // Email không tồn tại trong cơ sở dữ liệu, bạn có thể thực hiện một số xử lý ở đây, ví dụ, hiển thị một thông báo lỗi.
                return View();
            }

            _context.SaveChanges();

            // Gửi mật khẩu mới qua email
            SendOTPByEmail(email); // Hàm này để gửi mật khẩu mới qua email.

            return RedirectToAction("VerifyOTP", "Accounts");
        }

        private void SendOTPByEmail(string email)
        {
            
            HttpContext.Session.SetString("email", email);
            // Generate a random OTP with 6 digits
            string otp = GenerateRandomOTP(6);

            // Store the OTP and its expiration time in a cache or database
            _cache.Set(email + "_OTP", otp);
            _cache.Set(email + "_OTP_Expiry", DateTime.UtcNow.AddMinutes(3)); // Set expiration time to 3 minutes

            // Replace the values below with your SMTP account information
            string smtpServer = "smtp.gmail.com";
            int smtpPort = 587; // Can be changed based on your SMTP configuration
            string smtpUsername = "truongtranlong23@gmail.com"; // Your SMTP username
            string smtpPassword = "wtnd aeqg mdwu ahuu"; // Your SMTP password

            using (SmtpClient smtpClient = new SmtpClient(smtpServer, smtpPort))
            {
                smtpClient.UseDefaultCredentials = false;
                smtpClient.Credentials = new NetworkCredential(smtpUsername, smtpPassword);
                smtpClient.EnableSsl = true; // Add this line if you are using SSL
                smtpClient.DeliveryMethod = SmtpDeliveryMethod.Network;

                MailMessage mailMessage = new MailMessage();
                mailMessage.From = new MailAddress("truongtranlong23@gmail.com", "Hi you! This is QLTK");
                mailMessage.To.Add(email);
                mailMessage.Subject = "Your One-Time Password (OTP)";
                mailMessage.Body = $"Your OTP is: {otp}. This OTP is valid for 3 minutes."; // Update the validity period

                smtpClient.Send(mailMessage);
            }
        }

        [HttpGet]
        public IActionResult VerifyOTP()
        {
            return View();
        }

        [HttpPost]
        public ActionResult VerifyOTP(Account account)
        {
            var email = HttpContext.Session.GetString("email");
            Console.WriteLine(account.Otp);
            if (string.IsNullOrEmpty(account.Otp) || string.IsNullOrEmpty(email))
            {
                // Kiểm tra nếu otp hoặc email là null hoặc rỗng
                TempData["ErrorMessage"] = "OTP or email cannot be empty.";
                return RedirectToAction("ForgotPassword", "Accounts", new { email = email });
            }

            // Lấy OTP và thời gian hết hạn từ cache hoặc cơ sở dữ liệu
            string storedOTP = _cache.Get<string>(email + "_OTP");
            DateTime? expiryTime = _cache.Get<DateTime?>(email + "_OTP_Expiry");

            if (string.IsNullOrEmpty(storedOTP) || expiryTime == null || expiryTime < DateTime.UtcNow)
            {
                // OTP không hợp lệ hoặc đã hết hạn
                TempData["ErrorMessage"] = "Invalid or expired OTP.";
                return RedirectToAction("ForgotPassword", "Accounts", new { email = email });
            }

            // So sánh OTP được nhập với OTP được lưu trữ
            if (account.Otp.Trim().Equals(storedOTP, StringComparison.OrdinalIgnoreCase))
            {
                // OTP chính xác, chuyển hướng sang trang đặt lại mật khẩu
                return RedirectToAction("ResetPassword", "Accounts", new { email = email });
            }
            else
            {
                // OTP không chính xác
                TempData["ErrorMessage"] = "Incorrect OTP.";
                return RedirectToAction("VerifyOTP", "Accounts", new { email = email });
            }
        }

        [HttpGet]
        public IActionResult VerifyOTPRegister()
        {
            return View();
        }

        [HttpPost]
        public ActionResult VerifyOTPRegister(Account account)
        {
            var email = HttpContext.Session.GetString("email");
            Console.WriteLine(account.Otp);
            if (string.IsNullOrEmpty(account.Otp) || string.IsNullOrEmpty(email))
            {
                // Kiểm tra nếu otp hoặc email là null hoặc rỗng
                TempData["ErrorMessage"] = "OTP or email cannot be empty.";
                return RedirectToAction("Register", "Accounts", new { email = email });
            }

            // Lấy OTP và thời gian hết hạn từ cache hoặc cơ sở dữ liệu
            string storedOTP = _cache.Get<string>(email + "_OTP");
            DateTime? expiryTime = _cache.Get<DateTime?>(email + "_OTP_Expiry");

            if (string.IsNullOrEmpty(storedOTP) || expiryTime == null || expiryTime < DateTime.UtcNow)
            {
                // OTP không hợp lệ hoặc đã hết hạn
                TempData["ErrorMessage"] = "Invalid or expired OTP.";
                return RedirectToAction("Register", "Accounts", new { email = email });
            }

            // So sánh OTP được nhập với OTP được lưu trữ
            if (account.Otp.Trim().Equals(storedOTP, StringComparison.OrdinalIgnoreCase))
            {
                // OTP chính xác, chuyển hướng sang trang đặt lại mật khẩu
                return RedirectToAction("CompleteProfile", "Accounts", new { email = email });
            }
            else
            {
                // OTP không chính xác
                TempData["ErrorMessage"] = "Incorrect OTP.";
                return RedirectToAction("Register", "Accounts", new { email = email });
            }
        }


        // Generate a random OTP with the specified number of digits
        private string GenerateRandomOTP(int length)
        {
            Random random = new Random();
            StringBuilder otp = new StringBuilder(length);
            for (int i = 0; i < length; i++)
            {
                otp.Append(random.Next(0, 10)); // Random number between 0 and 9 (inclusive)
            }
            return otp.ToString();
        }

        [HttpGet]
        public IActionResult ResetPassword()
        {
            return View();
        }

        [HttpPost]
        public ActionResult ResetPassword(Account model)
        {
            // Ensure the model is not null and is valid according to data annotations
            if (model == null || !ModelState.IsValid)
            {
                return View(model);
            }

            try
            {
                // Retrieve the currently logged-in user's account from session
                var currentAccount = _accountSessionManager.GetCurrentAccount();
                if (currentAccount == null)
                {
                    // If no user is logged in, redirect to the login page
                    return RedirectToAction("Login", "Accounts");
                }



                // Ensure the new password and confirmation password match
                if (model.NewPassword != model.ConfirmNewPassword)
                {
                    // If the new password and confirmation do not match, show an error
                    ModelState.AddModelError("ConfirmNewPassword", "Mật khẩu xác nhận không khớp.");
                    return View(model);
                }

                // Hash the new password before storing it
                string hashedNewPassword = GetMd5Hash(model.NewPassword);

                // Retrieve the account from the database to update its password
                var accountInDb = _context.Accounts.FirstOrDefault(a => a.Id == currentAccount.Id);
                if (accountInDb != null)
                {
                    // Update the password and save changes to the database
                    accountInDb.Password = hashedNewPassword;
                    _context.Update(accountInDb);
                    _context.SaveChanges();
                }
                else
                {
                    // If the account is not found in the database, show an error
                    ModelState.AddModelError("", "Không tìm thấy tài khoản trong cơ sở dữ liệu.");
                    return View(model);
                }

                // Display a success message and redirect to the login page
                TempData["ChangePasswordSuccess"] = "Mật khẩu đã được thay đổi thành công.";
                return RedirectToAction("Login", "Accounts");
            }
            catch (Exception ex)
            {
                // Log the exception (if logging is set up)
                // _logger.LogError(ex, "Error occurred while resetting password");

                // Show a generic error message to the user
                ModelState.AddModelError("", "Đã xảy ra lỗi khi thay đổi mật khẩu.");
                return View(model);
            }
        }


        public async Task<IActionResult> ProfileUser(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var account = await _context.Accounts
                .FirstOrDefaultAsync(m => m.Id == id);
            if (account == null)
            {
                return NotFound();
            }

            return View(account);
        }

        // Register
        public IActionResult Register()
        {
            return View();
        }

        // POST: Accounts/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register([Bind("Email")] Account account)
        {
            // Check if the email is already associated with an existing account
            var existingAccount = _context.Accounts.FirstOrDefault(a => a.Email.ToLower() == account.Email.ToLower());
            if (existingAccount != null)
            {
                // Display an error message indicating that the email is already in use
                ModelState.AddModelError("Email", "This email is already associated with an existing account.");
                return View(account);
            }

            // Check if the email is valid
            if (!IsValidEmail(account.Email))
            {
                // Display an error message indicating that the email is invalid
                ModelState.AddModelError("", "Please enter a valid email address.");
                return View(account);
            }

            if (!ModelState.IsValid)
            {
                // Store email in session and send OTP
                _httpContextAccessor.HttpContext.Session.SetString("Email", account.Email);
                SendOTPByEmail(account.Email);

                // Redirect to VerifyOTPRegister action
                return RedirectToAction("VerifyOTPRegister", "Accounts");
            }

            return View(account);
        }

        private bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }

        public async Task<IActionResult> HRM()
        {
            return View(await _context.Accounts.ToListAsync());
        }

        // GET: Accounts/Edit/5
        public async Task<IActionResult> EditHRM(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var account = await _context.Accounts.FindAsync(id);
            if (account == null)
            {
                return NotFound();
            }
            return View(account);
        }

        // POST: Accounts/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditHRM(int id, [Bind("Id,Username,Fullname,Phone,Gender,Birtday,Address,Image,UpdateAt")] Account account)
        {
            if (id != account.Id)
            {
                return NotFound();
            }

            var existingAccount = await _context.Accounts.FindAsync(id);
            if (existingAccount == null)
            {
                return NotFound();
            }

            // Cập nhật các trường cần thay đổi
            existingAccount.Fullname = account.Fullname;
            existingAccount.Phone = account.Phone;
            existingAccount.Gender = account.Gender;
            existingAccount.Birtday = account.Birtday;
            existingAccount.Address = account.Address;
            existingAccount.Image = account.Image;
            existingAccount.UpdateAt = DateOnly.FromDateTime(DateTime.Now);

            if (!ModelState.IsValid)
            {
                try
                {
                    _context.Update(existingAccount);
                    await _context.SaveChangesAsync();

                    TempData["SuccessMessage"] = "Thông tin cá nhân đã được cập nhật thành công.";
                    return RedirectToAction("ProfileUser", new { id = account.Id });
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!AccountExists(account.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
            }

            return View(account);
        }

        public async Task<IActionResult> DetailsHRM(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var account = await _context.Accounts
                .FirstOrDefaultAsync(m => m.Id == id);
            if (account == null)
            {
                return NotFound();
            }

            return View(account);
        }
    }
}
