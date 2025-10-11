# Security Analysis Report

## Executive Summary
- Total findings: **3**
- Findings by type:
  - SQL Injection: 1
  - Unsafe Eval: 1
  - Timing Side-Channel: 1

## Detailed Findings
### SQL Injection — `C:\Users\Ashish Yadav\Downloads\vulnerable_node_context_nesting\vulnerable_node_context_nesting\routes\admin.js`
- **PoC(s):**
  - GET /admin/user?name=' OR '1'='1
- **Confidence:** 0.95
- **Edge cases:** Input sanitization
- **Suggested fixes:**
  - Use parameterized queries
- **Dataflow:** `{"source": "req.query.name", "sink": "db.query"}`

### Unsafe Eval — `C:\Users\Ashish Yadav\Downloads\vulnerable_node_context_nesting\vulnerable_node_context_nesting\routes\admin.js`
- **PoC(s):**
  - GET /admin/eval?expr=process.exit()
- **Confidence:** 0.95
- **Edge cases:** Input validation
- **Suggested fixes:**
  - Avoid using eval
- **Dataflow:** `{"source": "req.query.expr", "sink": "eval"}`

### Timing Side-Channel — `C:\Users\Ashish Yadav\Downloads\vulnerable_node_context_nesting\vulnerable_node_context_nesting\middleware\auth.js`
- **PoC(s):**
  - Measure response time for different tokens
- **Confidence:** 0.8
- **Edge cases:** Token length check
- **Suggested fixes:**
  - Use constant-time comparison
- **Dataflow:** `{"source": "req.headers['x-token']", "sink": "auth function"}`
