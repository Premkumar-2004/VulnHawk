const PENALTY_POINTS = {
  MISSING_HEADER: 5,
  SECURITY_ISSUE: 10, // missconfiguration issues
  SSL_TLS_ISSUE: 8,
  SQL_INJECTION: 25,
  XSS: 20,
  VULNERABLE_FORM: 15,
  OUTDATED_TECHNOLOGY: 5,
};

function calculateSecurityScore(result) {
  let score = 100;

  score -= Math.min(20, Object.keys(result.missing_headers).length * 5);
  score -= Math.min(20, Object.keys(result.security_issues).length * 5);

  if (result.ssl_tls) {
    if (result.ssl_tls.error) {
      score -= 15;
    } else {
      // Check for unsecure protocols
      if (
        result.ssl_tls.protocols &&
        (result.ssl_tls.protocols["TLS 1.0"] ||
          result.ssl_tls.protocols["TLS 1.1"])
      ) {
        score -= 10;
      }

      // Check for SSL/TLS issues
      if (result.ssl_tls.issues) {
        score -= Math.min(20, result.ssl_tls.issues.length * 5);
      }

      // Check certificate days remaining
      if (result.ssl_tls.certificate?.days_remaining < 30) {
        score -= 10;
      }
    }
  }

  if (result.vulnerabilities) {
    // SQL Injection
    if (result.vulnerabilities["SQL Injection"]) {
      const sqliDetails = result.vulnerabilities["SQL Injection"].details || [];
      score -= Math.min(30, sqliDetails.length * 10);
    }

    // XSS
    if (result.vulnerabilities["XSS"]) {
      const xssDetails = result.vulnerabilities["XSS"].details || [];
      score -= Math.min(30, xssDetails.length * 10);
    }

    // Form vulnerabilities
    const formVulns = result.vulnerabilities["Vulnerable_Forms"];
    if (formVulns?.forms?.length > 0) {
      let totalVulnerabilities = 0;
      for (let form of formVulns.forms) {
        totalVulnerabilities += form.vulnerabilities?.length || 0;
      }
      score -= Math.min(30, totalVulnerabilities * 8);
    }
  }

  // score based on vulnerabilities detected
  if (result.technologies) {
    // outdated WordPress version
    if (
      result.technologies.CMS === "WordPress" &&
      result.technologies.Generator &&
      result.technologies.Generator.includes("WordPress") &&
      /WordPress [1-4]\./.test(result.technologies.Generator)
    ) {
      score -= 10;
    }

    // potentially outdated backend technology
    if (
      result.technologies.Backend === "PHP" &&
      result.technologies["X-Powered-By"] &&
      /PHP\/[1-5]\./.test(result.technologies["X-Powered-By"])
    ) {
      score -= 8;
    }
  }

  // Ensure score is between 1 and 100
  return Math.max(1, Math.min(100, score));
}

function displayResults(result) {
  let output = "<div class='summary-results'>";
  let outputDownloadBtn = "";

  // SECTION 1: Security Headers Summary
  const missingHeadersCount = Object.keys(result.missing_headers).length;
  output += `<div class="summary-section">
    ${
      missingHeadersCount > 0
        ? `<p class="warning">⚠️ &nbsp; Missing ${missingHeadersCount} security headers</p>`
        : `<p class="success">✅ &nbsp; All security headers present</p>`
    }
  </div>`;

  // SECTION 2: Configuration Issues Summary
  const securityIssuesCount = Object.keys(result.security_issues).length;
  output += `<div class="summary-section">
    ${
      securityIssuesCount > 0
        ? `<p class="warning">⚠️ &nbsp; Found ${securityIssuesCount} security misconfigurations</p>`
        : `<p class="success">✅ &nbsp; No security misconfigurations detected</p>`
    }
  </div>`;

  // SECTION 3: SSL/TLS Summary
  output += `<div class="summary-section">`;
  if (result.ssl_tls) {
    if (result.ssl_tls.error) {
      output += `<p class="warning">⚠️ &nbsp; ${result.ssl_tls.error}</p>`;
    } else {
      const issuesCount = result.ssl_tls.issues
        ? result.ssl_tls.issues.length
        : 0;
      const certExpiring =
        result.ssl_tls.certificate &&
        result.ssl_tls.certificate.days_remaining < 30;

      if (issuesCount > 0 || certExpiring) {
        output += `<p class="warning">⚠️ &nbsp; ${issuesCount} SSL/TLS issues found</p>`;
        if (certExpiring) {
          output += `<p class="warning">⚠️ &nbsp; Certificate expires in ${result.ssl_tls.certificate.days_remaining} days</p>`;
        }
      } else {
        output += `<p class="success">✅ &nbsp; SSL/TLS configuration is secure</p>`;
      }
    }
  } else {
    output += `<p class="neutral">ℹ️ &nbsp; SSL/TLS not analyzed (non-HTTPS site)</p>`;
  }
  output += `</div>`;

  // SECTION 4: Vulnerabilities Summary
  output += `<div class="summary-section">`;
  if (result.vulnerabilities) {
    // SQL Injection
    const sqliCount =
      result.vulnerabilities["SQL Injection"]?.details?.length || 0;

    // XSS
    const xssCount = result.vulnerabilities["XSS"]?.details?.length || 0;

    // Form vulnerabilities
    const formVulns = result.vulnerabilities["Vulnerable_Forms"];
    const formCount = formVulns?.forms?.length || 0;

    if (sqliCount > 0) {
      output += `<p class="critical">🚨 &nbsp; Found ${sqliCount} SQL Injection vulnerabilities</p>`;
    }

    if (xssCount > 0) {
      output += `<p class="critical">🚨 &nbsp; Found ${xssCount} Cross-Site Scripting vulnerabilities</p>`;
    }

    if (formCount > 0) {
      output += `<p class="critical">🚨 &nbsp; Found ${formCount} vulnerable forms</p>`;
    }

    if (sqliCount === 0 && xssCount === 0 && formCount === 0) {
      output += `<p class="success">✅ &nbsp; No critical vulnerabilities detected</p>`;
    }
  } else {
    output += `<p class="success">✅ &nbsp; No vulnerabilities detected</p>`;
  }
  output += `</div>`;

  // SECTION 5: Detected Technologies
  if (result.technologies && Object.keys(result.technologies).length > 0) {
    output += `<div class="summary-section">
      <h3>Tehnologii detectate:</h3>
      <div class="technologies-list">`;

    // CMS
    if (result.technologies.CMS) {
      output += `<p class="tech-item">📊 &nbsp; <strong>CMS:</strong> ${result.technologies.CMS}</p>`;
    }

    // frontend
    if (result.technologies.Frontend) {
      output += `<p class="tech-item">🖥️ &nbsp; <strong>Frontend:</strong> ${result.technologies.Frontend}</p>`;
    }

    // backend
    if (result.technologies.Backend) {
      output += `<p class="tech-item">⚙️ &nbsp; <strong>Backend:</strong> ${result.technologies.Backend}</p>`;
    }

    // server
    if (result.technologies.Server) {
      output += `<p class="tech-item">🖧 &nbsp; <strong>Server:</strong> ${result.technologies.Server}</p>`;
    }

    if (result.technologies.Generator) {
      output += `<p class="tech-item">🔧 &nbsp; <strong>Generator:</strong> ${result.technologies.Generator}</p>`;
    }

    if (result.technologies.Type) {
      output += `<p class="tech-item">📄 &nbsp; <strong>Tip site:</strong> ${result.technologies.Type}</p>`;
    }

    output += `</div></div>`;
  }

  // add download report button
  outputDownloadBtn += `<div class="report-actions">
    <button id="downloadReportBtn" class="download-btn blue-btn" onclick="generateReport()">Download Full Report</button>
  </div>`;

  output += `</div>`;

  document.getElementById("result").innerHTML = output;
  document.getElementById("download-btn-container").innerHTML =
    outputDownloadBtn;

  // store the full result data for the PDF report
  window.fullScanResults = result;
}

function updateScoreIndicator(score) {
  score = Math.max(1, Math.min(100, score));

  // update score text
  document.getElementById("scoreValue").textContent = score;

  // update circle progress
  const progressCircle = document.getElementById("progressCircle");
  const circumference = 439.6;

  progressCircle.style.strokeDasharray = circumference;
  progressCircle.style.strokeDashoffset = circumference * (1 - score / 100);

  // set color based on score
  progressCircle.style.stroke =
    score < 30
      ? "#e63946" // red
      : score < 70
      ? "#ffb703" // yellow
      : "#52b788"; // green
}

function displayFinalScore(result) {
  const finalScore = calculateSecurityScore(result);

  document.getElementById("result").style.display = "block";
  document.getElementById("score-container").style.display = "block";
  document.getElementById("scan-to-ai").style.display = "block";

  updateScoreIndicator(finalScore);
}

async function scan() {
  const url = document.getElementById("url").value;
  if (!url) {
    alert("Enter a valid URL!");
    return;
  }

  document.getElementById("score-container").style.display = "none"; // show the score only after the scan is completed

  document.getElementById("loading").style.display = "block"; // load spinner till the scan is complete
  document.getElementById("result").innerHTML = "";

  try {
    // POST request to /scan endpoint
    const response = await fetch(
      "https://web-scanner-server.onrender.com/scan",
      // "http://localhost:5100/scan",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url }),
      }
    );

    const result = await response.json();

    document.getElementById("loading").style.display = "none";

    if (result.error) {
      document.getElementById(
        "result"
      ).innerHTML = `<p style="color: red;"><strong>Error:</strong> ${result.error}</p>`;
      return;
    }

    displayResults(result);
    displayFinalScore(result);
  } catch (error) {
    document.getElementById("loading").style.display = "none";
    document.getElementById(
      "result"
    ).innerHTML = `<p style="color: red;"><strong>Error:</strong> ${error.message}</p>`;
  }
}
