using BaseLibrary.DTOs;
using BaseLibrary.Responses;

namespace ClientLibrary.Services.Contracts
{
    public interface IUserAccountService
    {
        Task<GeneralResponse> CreateAsync(Register user);
        Task<LoginResponse> SignInAsync(LoginDTO user);
        Task<GeneralResponse> RefreshTokenAsync(RefreshToken user);
        Task<WeatherForecast[]> GetWeatherFrecast();
    }
}
