
namespace BaseLibrary.Responses
{
    public record GeneralResponse(bool Flag, string Message = null)
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
    }
}
