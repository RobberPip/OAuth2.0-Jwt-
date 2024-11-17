using AuthenticationService.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using System.Text;
using System.Linq;
using AuthenticationService.Models;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpClient();
// Добавляем JwtSettings из конфигурационного файла
builder.Services.Configure<JwtSettingsModel>(builder.Configuration.GetSection("JwtSettings"));

// Регистрируем AuthService
builder.Services.AddTransient<AuthService>();

// Добавляем аутентификацию JWT
builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettingsModel>();
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.Zero,
            ValidIssuer = jwtSettings.Issuer,
            ValidAudience = jwtSettings.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Secret))
        };
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                Console.WriteLine($"Authentication failed: {context.Exception}");
                return Task.CompletedTask;
            }
        };
    });

// Добавляем контроллеры
builder.Services.AddControllers();

// Swagger для документации (если нужно)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Настройка middleware для разработки
app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();

// Включаем аутентификацию и авторизацию
app.UseAuthentication(); // Важно: добавьте эту строку перед UseAuthorization
app.UseAuthorization();

app.MapControllers();

app.Run();
