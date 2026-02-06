# Shannon Passive - Production-Safe Security Scanner

**A passive fork of [Shannon](https://github.com/KeygraphHQ/shannon) designed for production environments.**

## What Changed?

This fork modifies Shannon to operate as a **passive scanner** instead of an active penetration testing tool:

### Original Shannon (Active)
- **Proof-by-Exploitation**: Actually exploits vulnerabilities to prove they're real
- **Production-Unsafe**: Creates users, modifies data, executes injections
- **Higher Accuracy**: Very low false positive rate (only reports proven exploits)
- **Use Case**: Staging/dev/test environments only

### Shannon Passive (This Fork)
- **Analysis Only**: Analyzes code and reports potential vulnerabilities
- **Production-Safe**: No active exploitation, purely observational
- **Lower Accuracy**: Higher false positive rate (reports potential issues without proof)
- **Use Case**: Production websites, live systems

## Key Modification

The exploitation phase (Phase 3) has been disabled. Instead of:
```typescript
// Original: Actually run the exploit
if (decision.shouldExploit) {
  exploitMetrics = await runExploitAgent(); // ACTIVE EXPLOITATION
}
```

Now:
```typescript
// Passive: Skip exploitation, just report potential
if (decision.shouldExploit) {
  // exploitMetrics = await runExploitAgent(); // DISABLED
  exploitMetrics = { costUsd: 0, numTurns: 0, durationMs: 0 };
}
```

## What You Get

✅ **Safe for Production**
- No data modification
- No user creation
- No injection attempts
- No authentication bypass attempts

✅ **Still Useful**
- White-box source code analysis
- Data flow analysis (identifies paths from user input to dangerous sinks)
- OWASP coverage (Injection, XSS, SSRF, Auth issues)
- Detailed reports with hypothesized attack vectors

❌ **Tradeoffs**
- **Higher False Positive Rate**: Reports potential issues that might not be exploitable
- **No Proof**: Can't confirm if vulnerabilities are actually exploitable
- **Less Confidence**: Security team must manually verify findings

## Installation & Usage

Same as original Shannon:

1. **Set up credentials**:
```bash
cat > .env << 'EOF'
ANTHROPIC_API_KEY=your-api-key
CLAUDE_CODE_MAX_OUTPUT_TOKENS=64000
EOF
```

2. **Run scanner**:
```bash
./shannon start URL=https://your-production-site.com REPO=/path/to/source
```

3. **Review results**:
```bash
# Results in ./audit-logs/{hostname}_{sessionId}/deliverables/
```

## When to Use Which Version

### Use Shannon Passive (This Fork) When:
- Scanning production websites
- Continuous monitoring in CI/CD for live services
- Initial security assessment of sensitive systems
- Company policy prohibits active exploitation

### Use Original Shannon When:
- Testing staging/dev environments
- Pre-release security validation
- You need proof-of-exploitability
- False positives are costly to triage

## Cost & Time

- **Cost**: ~$30-40 USD (cheaper than original since no exploitation phase)
- **Time**: ~45-60 minutes (faster than original)
- **Requirements**: Same as original (Docker, Anthropic API key, source code access)

## Important Notes

⚠️ **This is a Fork**
- Not officially supported by Keygraph
- Maintained by @moteboxai
- Based on Shannon's AGPL-3.0 licensed codebase

⚠️ **Security Implications**
- Reports are **hypotheses**, not proven vulnerabilities
- Manual verification required before considering findings actionable
- False positive rate expected to be 30-50% higher than original Shannon

⚠️ **Recommended Workflow**
1. Run Shannon Passive on production
2. Triage findings (prioritize high-confidence issues)
3. Reproduce high-priority findings in staging with original Shannon
4. Fix confirmed vulnerabilities

## Upstream

Original Shannon: https://github.com/KeygraphHQ/shannon

For the full active pentesting version (with proof-by-exploitation), use the original Shannon on non-production environments.

## License

AGPL-3.0 (same as upstream Shannon)

Modifications © 2026 moteboxai
Original © 2025 Keygraph, Inc.
