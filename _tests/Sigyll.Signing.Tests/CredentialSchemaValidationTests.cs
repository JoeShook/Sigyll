#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Shouldly;
using Sigyll.Vc.Services;
using Xunit;

namespace Sigyll.Signing.Tests;

/// <summary>A credential's claims are checked against its schema before it is issued.</summary>
public class CredentialSchemaValidationTests
{
    // The preset MemberCredential schema (Program.cs).
    private const string MemberSchema = """
        {
          "$schema": "https://json-schema.org/draft/2020-12/schema",
          "type": "object",
          "required": ["name", "role"],
          "properties": {
            "name":         { "type": "string", "minLength": 1 },
            "role":         { "type": "string", "minLength": 1 },
            "organization": { "type": "string" }
          },
          "additionalProperties": false
        }
        """;

    private const string RicherSchema = """
        {
          "$schema": "https://json-schema.org/draft/2020-12/schema",
          "type": "object",
          "required": ["npi", "specialties"],
          "properties": {
            "npi":         { "type": "string", "pattern": "^[0-9]{10}$" },
            "level":       { "enum": ["junior", "senior"] },
            "years":       { "type": "integer", "minimum": 0, "maximum": 80 },
            "specialties": { "type": "array", "minItems": 1, "items": { "$ref": "#/$defs/specialty" } }
          },
          "$defs": {
            "specialty": {
              "type": "object",
              "required": ["code"],
              "properties": { "code": { "type": "string" } }
            }
          }
        }
        """;

    [Theory]
    [InlineData("""{ "name": "Joe", "role": "eng" }""")]
    [InlineData("""{ "name": "Joe", "role": "eng", "organization": "Sigyll" }""")]
    public async Task ClaimsThatFitTheSchema_Pass(string claims) =>
        (await CredentialSchemaService.ValidateClaimsAsync(MemberSchema, claims)).ShouldBeNull();

    [Theory]
    [InlineData("""{ "name": "Joe" }""", "role")]                                // a required claim is missing
    [InlineData("""{ "name": "Joe", "role": "eng", "extra": 1 }""", "extra")]    // a claim the schema doesn't allow
    [InlineData("""{ "name": 5, "role": "eng" }""", "name")]                     // wrong type
    [InlineData("""{ "name": "", "role": "eng" }""", "name")]                    // too short
    public async Task ClaimsThatDontFit_AreRefused_NamingTheClaim(string claims, string claim)
    {
        var error = await CredentialSchemaService.ValidateClaimsAsync(MemberSchema, claims);

        error.ShouldNotBeNull();
        error.ShouldContain(claim);
    }

    [Fact]
    public async Task ClaimsThatAreNotAnObject_AreRefused() =>
        (await CredentialSchemaService.ValidateClaimsAsync(MemberSchema, """["Joe", "eng"]""")).ShouldNotBeNull();

    [Fact]
    public async Task PatternsEnumsRangesArraysAndLocalReferences_AreEnforced()
    {
        (await CredentialSchemaService.ValidateClaimsAsync(RicherSchema,
            """{ "npi": "1234567890", "level": "senior", "years": 12, "specialties": [ { "code": "207Q00000X" } ] }"""))
            .ShouldBeNull();

        (await CredentialSchemaService.ValidateClaimsAsync(RicherSchema, """{ "npi": "12345", "specialties": [ { "code": "x" } ] }"""))
            .ShouldNotBeNull();   // pattern
        (await CredentialSchemaService.ValidateClaimsAsync(RicherSchema, """{ "npi": "1234567890", "level": "chief", "specialties": [ { "code": "x" } ] }"""))
            .ShouldNotBeNull();   // enum
        (await CredentialSchemaService.ValidateClaimsAsync(RicherSchema, """{ "npi": "1234567890", "years": 99, "specialties": [ { "code": "x" } ] }"""))
            .ShouldNotBeNull();   // maximum
        (await CredentialSchemaService.ValidateClaimsAsync(RicherSchema, """{ "npi": "1234567890", "specialties": [] }"""))
            .ShouldNotBeNull();   // minItems
        (await CredentialSchemaService.ValidateClaimsAsync(RicherSchema, """{ "npi": "1234567890", "specialties": [ { } ] }"""))
            .ShouldNotBeNull();   // the $ref'd definition's required claim
    }

    [Fact]
    public async Task ASchemaThatIsNotJson_IsReported() =>
        (await CredentialSchemaService.ValidateClaimsAsync("{ not json", """{ "name": "Joe" }""")).ShouldStartWith("Schema parse error");

    [Fact]
    public async Task ClaimsThatAreNotJson_AreReported() =>
        (await CredentialSchemaService.ValidateClaimsAsync(MemberSchema, "{ not json")).ShouldStartWith("Claims parse error");

    [Theory]
    [InlineData("const", """{ "properties": { "role": { "const": "eng" } } }""")]
    [InlineData("contains", """{ "properties": { "tags": { "type": "array", "contains": { "type": "string" } } } }""")]
    [InlineData("prefixItems", """{ "properties": { "pair": { "prefixItems": [ { "type": "string" } ] } } }""")]
    [InlineData("if", """{ "if": { "required": ["a"] }, "then": { "required": ["b"] } }""")]
    [InlineData("dependentRequired", """{ "dependentRequired": { "a": ["b"] } }""")]
    [InlineData("dependencies", """{ "dependencies": { "a": ["b"] } }""")]
    [InlineData("propertyNames", """{ "propertyNames": { "maxLength": 3 } }""")]
    [InlineData("unevaluatedProperties", """{ "properties": { "a": { } }, "unevaluatedProperties": false }""")]
    [InlineData("unevaluatedProperties", """{ "$defs": { "d": { "unevaluatedProperties": false } } }""")]
    public async Task ASchemaUsingAKeywordSigyllCanNotEnforce_IsRefused(string keyword, string schema)
    {
        CredentialSchemaService.CheckSchema(schema)!.ShouldContain($"\"{keyword}\"");
        // A schema stored before the check still can't let claims through unchecked.
        (await CredentialSchemaService.ValidateClaimsAsync(schema, "{}"))!.ShouldContain($"\"{keyword}\"");
    }

    [Theory]
    [InlineData("https://example.com/schema.json")]
    [InlineData("other.json#/definitions/x")]
    [InlineData("file:///etc/passwd")]
    public async Task ASchemaReferringOutsideItself_IsRefused_WithoutFetchingAnything(string reference)
    {
        var schema = $$"""{ "properties": { "a": { "$ref": "{{reference}}" } } }""";

        CredentialSchemaService.CheckSchema(schema)!.ShouldContain("refers outside itself");
        (await CredentialSchemaService.ValidateClaimsAsync(schema, """{ "a": 1 }"""))!.ShouldContain("refers outside itself");
    }

    [Theory]
    [InlineData("""{ "properties": { "const": { "type": "string" }, "if": { "type": "string" } } }""")]   // claims named like keywords
    [InlineData("""{ "properties": { "level": { "enum": [ { "const": 1 } ] } } }""")]                      // keyword-like data
    [InlineData("""{ "required": ["contains"] }""")]
    public void KeywordNamesUsedAsClaimNamesOrData_AreAllowed(string schema) =>
        CredentialSchemaService.CheckSchema(schema).ShouldBeNull();

    [Fact]
    public void ThePresetAndRicherSchemas_AreAccepted()
    {
        CredentialSchemaService.CheckSchema(MemberSchema).ShouldBeNull();
        CredentialSchemaService.CheckSchema(RicherSchema).ShouldBeNull();
    }

    [Fact]
    public async Task Formats_AreEnforced()
    {
        const string schema = """{ "properties": { "email": { "type": "string", "format": "email" } } }""";

        (await CredentialSchemaService.ValidateClaimsAsync(schema, """{ "email": "joe@example.com" }""")).ShouldBeNull();
        (await CredentialSchemaService.ValidateClaimsAsync(schema, """{ "email": "not an address" }""")).ShouldNotBeNull();
    }
}
