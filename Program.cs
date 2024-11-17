using AuthenticationService.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using System.Text;
using System.Linq;
using AuthenticationService.Models;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpClient();
// ��������� JwtSettings �� ����������������� �����
builder.Services.Configure<JwtSettingsModel>(builder.Configuration.GetSection("JwtSettings"));

// ������������ AuthService
builder.Services.AddTransient<AuthService>();

// ��������� �������������� JWT
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

// ��������� �����������
builder.Services.AddControllers();

// Swagger ��� ������������ (���� �����)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// ��������� middleware ��� ����������
app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();

// �������� �������������� � �����������
app.UseAuthentication(); // �����: �������� ��� ������ ����� UseAuthorization
app.UseAuthorization();

app.MapControllers();

app.Run();
