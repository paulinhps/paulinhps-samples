using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Paulinhps.Samples.Blazor.Migrations
{
    /// <inheritdoc />
    public partial class AddDefaultRoles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: ["Id", "Name", "NormalizedName", "ConcurrencyStamp"],
                values: new object[,]
                {
                    {Guid.NewGuid().ToString(), "admin", "admin".ToUpper(), Guid.NewGuid().ToString() },
                    {Guid.NewGuid().ToString(), "user", "user".ToUpper(), Guid.NewGuid().ToString() },
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Name",
                keyValues: ["admin", "user"]);
        }
    }
}
