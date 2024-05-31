using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace QLTK.Models;

public partial class Account
{
    public int Id { get; set; }


    public string Username { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    [Required]
    [NotMapped]
    [DataType(DataType.Password)]
    [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
    public string ConfirmPassword { get; set; }

    public string Fullname { get; set; }

    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid Email Address")]
    public string Email { get; set; }

    [Phone(ErrorMessage = "Invalid Phone Number")]
    public string Phone { get; set; }

    public string Gender { get; set; }

    [Required(ErrorMessage = "Birthday is required")]
    [DataType(DataType.Date)]
    public DateOnly Birtday { get; set; }

    public string Address { get; set; }

    public string Image { get; set; }

    public string Userstatus { get; set; } 

    public DateOnly CreateAt { get; set; }

    public DateOnly UpdateAt { get; set; }

    public int RoleId { get; set; }


    [Required(ErrorMessage = "Vui lòng nhập mật khẩu hiện tại.")]
    [DataType(DataType.Password)]
    [NotMapped]
    public string CurrentPassword { get; set; }

    [Required(ErrorMessage = "Vui lòng nhập mật khẩu mới.")]
    [DataType(DataType.Password)]
    [MinLength(6, ErrorMessage = "Mật khẩu mới phải có ít nhất 6 ký tự.")]
    [NotMapped]
    public string NewPassword { get; set; }

    [Required(ErrorMessage = "Vui lòng xác nhận mật khẩu mới.")]
    [DataType(DataType.Password)]
    [Compare("NewPassword", ErrorMessage = "Mật khẩu xác nhận không khớp.")]
    [NotMapped]
    public string ConfirmNewPassword { get; set; }

    [NotMapped]
    public string Otp { get; set; }
}
