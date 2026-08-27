(function(){

  const EXAMPLES = {
    python:
`import sqlite3

def get_user(request):
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # vulnerable: f-string interpolation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    # safe: parameterized
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()`,

    js:
`const express = require("express");
const app = express();

app.get("/user", (req, res) => {
  const userId = req.query.id;

  // vulnerable: template literal interpolation
  const sql = \`SELECT * FROM users WHERE id = \${userId}\`;
  db.query(sql, (err, rows) => res.json(rows));

  // safe: parameterized
  db.query("SELECT * FROM users WHERE id = $1", [userId]);
});`,

    php:
`<?php
$id = $_GET['id'];

// vulnerable: concatenation with a superglobal
$sql = "SELECT * FROM users WHERE id = " . $id;
$result = mysqli_query($conn, $sql);

// safe: PDO prepared statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(["id" => $id]);
?>`
  };

  const patterns = [
    {
      id: 'format-interp',
      lang: 'Python',
      severity_base: 'high',
      test: /f["'][^"'\n]*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^"'\n]*\{[^}]+\}[^"'\n]*["']/i,
      label: 'f-string interpolation into a SQL string',
      fix: 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
    },
    {
      id: 'percent-format',
      lang: 'Python',
      severity_base: 'high',
      test: /["'][^"'\n]*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^"'\n]*["']\s*(%\s*\(|\.format\()/i,
      label: '%-formatting or .format() building a SQL string',
      fix: 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
    },
    {
      id: 'template-literal',
      lang: 'JavaScript / Node',
      severity_base: 'high',
      test: /`[^`\n]*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^`\n]*\$\{[^}]+\}[^`\n]*`/i,
      label: 'Template literal interpolation into a SQL string',
      fix: 'db.query("SELECT * FROM users WHERE id = $1", [userId])'
    },
    {
      id: 'php-superglobal-concat',
      lang: 'PHP',
      severity_base: 'high',
      test: /(\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\][^;\n]*\.\s*["'])|(["'][^"'\n]*\b(SELECT|WHERE|FROM)\b[^"'\n]*["']\s*\.\s*\$)/i,
      label: 'Concatenation of request data into a SQL string',
      fix: '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");\n$stmt->execute(["id" => $id]);'
    },
    {
      id: 'concat-plus',
      lang: 'Python / JS / Java / C#',
      severity_base: 'medium',
      test: /["'][^"'\n]*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^"'\n]*["']\s*\+|\+\s*["'][^"'\n]*\b(WHERE|FROM|SELECT)\b/i,
      label: 'String concatenation building a SQL string',
      fix: "Use a parameterized/prepared statement instead of + concatenation (e.g. PreparedStatement, SqlParameter, or a driver's placeholder syntax)."
    }
  ];

  const commentRegex = /^\s*(#|\/\/|\*|<!--)/;
  const safeMarkerRegex = /(execute\([^,()]*,\s*[\(\[])|(\.prepare\()|(bindParam\()|(bindValue\()|(PreparedStatement)|(setString\()|(setInt\()|(SqlParameter)|(Parameters\.Add)|(\$\d\s*,)/i;
  const userInputRegex = /\b(request\.(args|form|values)|req\.(query|body|params)|\$_(GET|POST|REQUEST|COOKIE)|input\(\)|sys\.argv)\b/i;

  function escapeHtml(str){
    return str.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function scan(text){
    const lines = text.split('\n');
    const findings = [];
    for(let i=0;i<lines.length;i++){
      const line = lines[i];
      if(commentRegex.test(line)) continue;
      for(const p of patterns){
        if(p.test.test(line)){
          const start = Math.max(0, i-3);
          const end = Math.min(lines.length, i+4);
          const window = lines.slice(start,end).join('\n');
          const safe = safeMarkerRegex.test(window);
          let severity = safe ? 'info' : p.severity_base;
          if(!safe && p.severity_base === 'medium' && userInputRegex.test(line)) severity = 'high';
          findings.push({
            lineNo: i+1,
            code: line.trim(),
            category: p.label,
            lang: p.lang,
            severity,
            fix: p.fix,
            safe
          });
          break; // one finding per line
        }
      }
    }
    return {findings, totalLines: lines.length};
  }

  function render(result){
    const {findings, totalLines} = result;
    const summaryEl = document.getElementById('summaryRow');
    const listEl = document.getElementById('findings');

    const counts = {high:0, medium:0, info:0};
    findings.forEach(f => counts[f.severity]++);

    summaryEl.innerHTML = `
      <span class="summary-pill"><span class="swatch" style="background:var(--red)"></span>${counts.high} high</span>
      <span class="summary-pill"><span class="swatch" style="background:var(--amber)"></span>${counts.medium} medium</span>
      <span class="summary-pill"><span class="swatch" style="background:var(--teal)"></span>${counts.info} parameterized nearby</span>
      <span class="summary-pill">${totalLines} lines scanned</span>
    `;

    listEl.innerHTML = '';
    if(findings.length === 0){
      const p = document.createElement('p');
      p.className = 'empty-state';
      p.textContent = 'No obvious query-building patterns detected in ' + totalLines + ' lines. Heuristic scan only — see "Known limitation" below.';
      listEl.appendChild(p);
      return;
    }

    findings.forEach((f, idx) => {
      const card = document.createElement('div');
      card.className = 'finding ' + f.severity;

      const top = document.createElement('div');
      top.className = 'finding-top';
      const idSpan = document.createElement('span');
      idSpan.className = 'finding-id';
      idSpan.textContent = 'FINDING-' + String(idx+1).padStart(3,'0') + '  ·  line ' + f.lineNo + '  ·  ' + f.lang;
      const sevBadge = document.createElement('span');
      sevBadge.className = 'sev-badge ' + f.severity;
      sevBadge.textContent = f.severity === 'info' ? 'parameterized nearby' : f.severity;
      top.appendChild(idSpan);
      top.appendChild(sevBadge);

      const cat = document.createElement('p');
      cat.className = 'finding-cat';
      cat.textContent = f.category;

      const pre = document.createElement('pre');
      pre.textContent = f.code;

      const fix = document.createElement('div');
      fix.className = 'fix';
      const b = document.createElement('b');
      b.textContent = f.safe ? 'Note' : 'Remediation';
      fix.appendChild(b);
      fix.appendChild(document.createTextNode(
        f.safe
          ? "A parameterization marker was found nearby — this is likely already safe. Verify the flagged value isn't reused elsewhere unparameterized."
          : f.fix
      ));

      card.appendChild(top);
      card.appendChild(cat);
      card.appendChild(pre);
      card.appendChild(fix);
      listEl.appendChild(card);
    });
  }

  function runScan(){
    const text = document.getElementById('codeInput').value;
    render(scan(text));
  }

  document.getElementById('runBtn').addEventListener('click', runScan);

  document.getElementById('clearBtn').addEventListener('click', () => {
    document.getElementById('codeInput').value = '';
    document.getElementById('summaryRow').innerHTML = '';
    document.getElementById('findings').innerHTML = '<p class="empty-state">Run a scan to see results here.</p>';
  });

  document.querySelectorAll('.chip[data-ex]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.getElementById('codeInput').value = EXAMPLES[btn.dataset.ex];
      runScan();
    });
  });

  document.getElementById('fileInput').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if(!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      document.getElementById('codeInput').value = reader.result;
      runScan();
    };
    reader.readAsText(file);
  });

  // initial state
  document.getElementById('codeInput').value = EXAMPLES.python;
  runScan();

})();