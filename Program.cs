using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "Tenant1OrTenant2";
    options.DefaultChallengeScheme = "Tenant1OrTenant2";
})
    .AddJwtBearer("Tenant1Auth", options =>
    {
        options.Audience = builder.Configuration["Tenant1:Audience"];
        options.Authority = builder.Configuration["Tenant1:Authority"];
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidIssuer = builder.Configuration["Tenant1:Issuer"],
            ValidAudience = builder.Configuration["Tenant1:Audience"],
        };
    })
    .AddJwtBearer("Tenant2Auth", options =>
     {
         options.Audience = builder.Configuration["Tenant2:Audience"];
         options.Authority = builder.Configuration["Tenant2:Authority"];
         options.TokenValidationParameters = new TokenValidationParameters
         {
             ValidateIssuer = true,
             ValidateAudience = true,
             ValidateIssuerSigningKey = true,
             ValidateLifetime = true,
             ValidIssuer = builder.Configuration["Tenant2:Issuer"],
             ValidAudience = builder.Configuration["Tenant2:Audience"],
         };
     })

    .AddPolicyScheme("Tenant1OrTenant2", "Tenant1OrTenant2", options =>
    {
        options.ForwardDefaultSelector = context =>
        {
            string authorization = context.Request.Headers[HeaderNames.Authorization];
            if (string.IsNullOrEmpty(authorization))
            {
                var token = authorization.Substring("Bearer ".Length).Trim();
                var jwtHandler = new JwtSecurityTokenHandler();
                if (jwtHandler.CanReadToken(token))
                {
                    var issuer = jwtHandler.ReadJwtToken(token).Issuer;
                    if (issuer == builder.Configuration["Tenant2:Issuer"])
                    {
                        return "Tenant2Auth";
                    }
                }
            }
            return "Tenant1Auth";
        };
    });

    builder.Services.AddAuthorization(options =>
    {
        var commonPolicy = new AuthorizationPolicyBuilder("Tenant1Auth","Tenant2Auth")
        .RequireAuthenticatedUser().Build();
        options.AddPolicy("Tenant1Or2Policy",commonPolicy);
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
