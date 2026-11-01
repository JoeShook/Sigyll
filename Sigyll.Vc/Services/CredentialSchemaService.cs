#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using NJsonSchema;
using NJsonSchema.Validation;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Security;
using Sigyll.Common.ViewModels;

namespace Sigyll.Vc.Services;

public class CredentialSchemaService
{
    private readonly IDbContextFactory<SigyllDbContext> _dbFactory;
    private readonly IOperatorContext _operator;
    private readonly ILogger<CredentialSchemaService> _logger;

    public CredentialSchemaService(
        IDbContextFactory<SigyllDbContext> dbFactory,
        IOperatorContext operatorContext,
        ILogger<CredentialSchemaService> logger)
    {
        _dbFactory = dbFactory;
        _operator = operatorContext;
        _logger = logger;
    }

    public async Task<List<CredentialSchema>> GetAllAsync(CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.View);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.CredentialSchemas
            .OrderByDescending(s => s.IsPreset)
            .ThenBy(s => s.Name)
            .ToListAsync(ct);
    }

    public async Task<CredentialSchema?> GetByIdAsync(int id, CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.View);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.CredentialSchemas.FindAsync([id], ct);
    }

    public async Task<CredentialSchema> SaveAsync(CredentialSchema entity, CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.Administer);

        // Only a schema Sigyll can fully enforce is stored (CheckSchema), and it must load as a JSON Schema.
        if (CheckSchema(entity.ClaimsSchemaJson) is { } schemaError)
            throw new InvalidOperationException($"ClaimsSchemaJson can't be used: {schemaError}");
        try { await JsonSchema.FromJsonAsync(entity.ClaimsSchemaJson, ct); }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"ClaimsSchemaJson is not a valid JSON Schema: {ex.Message}", ex);
        }

        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        if (entity.Id > 0)
        {
            var existing = await db.CredentialSchemas.FindAsync([entity.Id], ct);
            if (existing != null)
            {
                db.Entry(existing).CurrentValues.SetValues(entity);
                await db.SaveChangesAsync(ct);
                return existing;
            }
        }

        db.CredentialSchemas.Add(entity);
        await db.SaveChangesAsync(ct);
        return entity;
    }

    public async Task DeleteAsync(int id, CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.Administer);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entity = await db.CredentialSchemas.FindAsync([id], ct);
        if (entity != null && !entity.IsPreset)
        {
            db.CredentialSchemas.Remove(entity);
            await db.SaveChangesAsync(ct);
        }
    }

    public async Task<List<ImpactItem>> GetDeletionImpactAsync(int schemaId, CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.View);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var impacts = new List<ImpactItem>();

        var count = await db.IssuedCredentials.CountAsync(c => c.CredentialSchemaId == schemaId, ct);
        if (count > 0)
            impacts.Add(new ImpactItem(count, "issued credential(s) reference this schema", ImpactSeverity.Warning));

        return impacts;
    }

    /// <summary>
    /// JSON Schema keywords the validator (NJsonSchema) would ignore. A schema using one is refused rather than
    /// accepted with that rule unenforced.
    /// </summary>
    public static readonly IReadOnlySet<string> UnsupportedKeywords = new HashSet<string>(StringComparer.Ordinal)
    {
        "const", "contains", "minContains", "maxContains", "prefixItems", "if", "then", "else",
        "dependentRequired", "dependentSchemas", "dependencies", "propertyNames",
        "unevaluatedProperties", "unevaluatedItems", "$dynamicRef", "$dynamicAnchor", "$recursiveRef",
        "$recursiveAnchor", "contentSchema",
    };

    // Keywords whose value maps names to subschemas; the names are claims, not keywords.
    private static readonly HashSet<string> SchemaMaps = new(StringComparer.Ordinal)
    {
        "properties", "patternProperties", "$defs", "definitions",
    };

    // Keywords whose value is data, not a schema.
    private static readonly HashSet<string> DataValues = new(StringComparer.Ordinal)
    {
        "enum", "examples", "default", "required",
    };

    /// <summary>
    /// Why a schema can't be used, or null when it can: it isn't JSON, uses a keyword the validator would ignore
    /// (<see cref="UnsupportedKeywords"/>), or refers outside itself (a <c>$ref</c> not starting with <c>#</c>,
    /// which would make the validator fetch it).
    /// </summary>
    public static string? CheckSchema(string schemaJson)
    {
        JsonDocument document;
        try { document = JsonDocument.Parse(schemaJson); }
        catch (JsonException ex) { return $"Schema parse error: {ex.Message}"; }

        using (document)
            return CheckSubschema(document.RootElement, "#");
    }

    private static string? CheckSubschema(JsonElement schema, string path)
    {
        if (schema.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in schema.EnumerateArray())
                if (CheckSubschema(item, $"{path}/{index++}") is { } error)
                    return error;
            return null;
        }
        if (schema.ValueKind != JsonValueKind.Object)
            return null;

        foreach (var property in schema.EnumerateObject())
        {
            var at = $"{path}/{property.Name}";
            if (UnsupportedKeywords.Contains(property.Name))
                return $"Schema uses \"{property.Name}\" at {path}, which Sigyll can't enforce.";
            if (property.Name == "$ref"
                && !(property.Value.ValueKind == JsonValueKind.String && property.Value.GetString()!.StartsWith('#')))
                return $"Schema refers outside itself at {at}; only references within the schema (\"#/...\") are allowed.";
            if (DataValues.Contains(property.Name))
                continue;
            if (SchemaMaps.Contains(property.Name) && property.Value.ValueKind == JsonValueKind.Object)
            {
                foreach (var entry in property.Value.EnumerateObject())
                    if (CheckSubschema(entry.Value, $"{at}/{entry.Name}") is { } error)
                        return error;
                continue;
            }
            if (CheckSubschema(property.Value, at) is { } nested)
                return nested;
        }
        return null;
    }

    /// <summary>
    /// Validates a claims object against the schema. Returns null on success;
    /// returns an error message on failure.
    /// </summary>
    public static async Task<string?> ValidateClaimsAsync(string schemaJson, string claimsJson)
    {
        if (CheckSchema(schemaJson) is { } schemaError)
            return schemaError;

        try { using var _ = JsonDocument.Parse(claimsJson); }
        catch (JsonException ex) { return $"Claims parse error: {ex.Message}"; }

        JsonSchema schema;
        try { schema = await JsonSchema.FromJsonAsync(schemaJson); }
        catch (Exception ex) { return $"Schema parse error: {ex.Message}"; }

        var errors = new List<string>();
        CollectErrors(schema.Validate(claimsJson), errors);
        return errors.Count == 0 ? null : string.Join("; ", errors);
    }

    private static void CollectErrors(IEnumerable<ValidationError> results, List<string> sink)
    {
        foreach (var error in results)
        {
            sink.Add($"{error.Path}: {error.Kind}");
            if (error is ChildSchemaValidationError child)
                foreach (var nested in child.Errors.Values)
                    CollectErrors(nested, sink);
        }
    }
}
