# VAULT-X Code Documentation Standard

## Required Style

- Format all Python code with Black using `pyproject.toml`.
- Give every public module, class, and function a concise docstring.
- Document security assumptions, side effects, parameters, return values, and
  failure behavior where they are not obvious from the signature.
- Add comments before complex cryptographic, authentication, monitoring, and
  migration logic.
- Prefer descriptive names over comments that merely repeat an assignment.
- Do not add comments such as `# increment count` above `count += 1`; they add
  noise without explaining intent.
- Never suppress exceptions silently in security-sensitive paths. Catch known
  exceptions and document why recovery is safe.

## Formatting Command

```powershell
python -m black .
```

## Verification Command

```powershell
python -m compileall -q .
```

