function generateReport() {
  // jsPDF instance
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();

  const result = window.fullScanResults;
  if (!result) {
    alert("No scan results available. Please run a scan first.");
    return;
  }

  // get the scanned URL
  const scannedUrl = document.getElementById("url").value;

  // title and date
  const currentDate = new Date().toLocaleString();
  doc.setFontSize(18);
  doc.text("Web Security Scan Report", 105, 15, { align: "center" });
  doc.setFontSize(12);
  doc.text(`URL: ${scannedUrl}`, 105, 25, { align: "center" });
  doc.text(`Date: ${currentDate}`, 105, 30, { align: "center" });

  doc.setLineWidth(0.5);
  doc.line(20, 35, 190, 35);

  let yPos = 45;

  // security Score
  const securityScore = document.getElementById("scoreValue").textContent;
  doc.setFontSize(14);
  doc.text(`Security Score: ${securityScore}/100`, 20, yPos);

  yPos += 10;

  // missing headers section
  doc.setFontSize(14);
  doc.text("Security Headers", 20, yPos);
  yPos += 8;

  if (Object.keys(result.missing_headers).length > 0) {
    doc.setFontSize(10);
    doc.text("Missing Headers:", 25, yPos);
    yPos += 5;

    for (let header in result.missing_headers) {
      doc.text(`- ${header}: ${result.missing_headers[header]}`, 30, yPos);
      yPos += 5;

      // check if we need a new page
      if (yPos > 270) {
        doc.addPage();
        yPos = 20;
      }
    }
  } else {
    doc.setFontSize(10);
    doc.text("All security headers are present.", 25, yPos);
    yPos += 8;
  }

  // security issues section
  yPos += 5;
  doc.setFontSize(14);
  doc.text("Security Misconfigurations", 20, yPos);
  yPos += 8;

  if (Object.keys(result.security_issues).length > 0) {
    doc.setFontSize(10);
    for (let issue in result.security_issues) {
      doc.text(`- ${issue}: ${result.security_issues[issue]}`, 25, yPos);
      yPos += 5;

      // check if we need a new page
      if (yPos > 270) {
        doc.addPage();
        yPos = 20;
      }
    }
  } else {
    doc.setFontSize(10);
    doc.text("No security misconfigurations detected.", 25, yPos);
    yPos += 8;
  }

  // SSL/TLS section
  yPos += 5;
  doc.setFontSize(14);
  doc.text("SSL/TLS Analysis", 20, yPos);
  yPos += 8;

  if (result.ssl_tls) {
    doc.setFontSize(10);
    if (result.ssl_tls.error) {
      doc.text(`${result.ssl_tls.error}`, 25, yPos);
      yPos += 8;
    } else {
      // certificate info
      if (result.ssl_tls.certificate) {
        const cert = result.ssl_tls.certificate;
        doc.text("Certificate Information:", 25, yPos);
        yPos += 5;
        doc.text(`- Issued to: ${cert.subject?.CN || "N/A"}`, 30, yPos);
        yPos += 5;
        doc.text(`- Issuer: ${cert.issuer?.CN || "N/A"}`, 30, yPos);
        yPos += 5;
        doc.text(`- Valid from: ${cert.valid_from}`, 30, yPos);
        yPos += 5;
        doc.text(`- Valid until: ${cert.valid_until}`, 30, yPos);
        yPos += 5;
        doc.text(`- Days remaining: ${cert.days_remaining}`, 30, yPos);
        yPos += 8;
      }

      // check if we need a new page
      if (yPos > 270) {
        doc.addPage();
        yPos = 20;
      }

      // Protocols
      if (result.ssl_tls.protocols) {
        doc.text("Supported Protocols:", 25, yPos);
        yPos += 5;

        for (let protocol in result.ssl_tls.protocols) {
          const supported = result.ssl_tls.protocols[protocol];
          doc.text(
            `- ${protocol}: ${supported ? "Supported" : "Not supported"}`,
            30,
            yPos
          );
          yPos += 5;
        }

        yPos += 3;
      }

      // Check if we need a new page
      if (yPos > 270) {
        doc.addPage();
        yPos = 20;
      }

      // SSL/TLS Issues
      if (result.ssl_tls.issues && result.ssl_tls.issues.length > 0) {
        doc.text("SSL/TLS Issues:", 25, yPos);
        yPos += 5;

        for (let issue of result.ssl_tls.issues) {
          doc.text(`- ${issue}`, 30, yPos);
          yPos += 5;

          // Check if we need a new page
          if (yPos > 270) {
            doc.addPage();
            yPos = 20;
          }
        }
      } else {
        doc.text("No SSL/TLS issues detected.", 25, yPos);
        yPos += 8;
      }
    }
  } else {
    doc.setFontSize(10);
    doc.text("SSL/TLS analysis only available for HTTPS URLs.", 25, yPos);
    yPos += 8;
  }

  // Add vulnerabilities section
  // Check if we need a new page
  if (yPos > 250) {
    doc.addPage();
    yPos = 20;
  }

  yPos += 5;
  doc.setFontSize(14);
  doc.text("Vulnerabilities", 20, yPos);
  yPos += 8;

  if (result.vulnerabilities) {
    doc.setFontSize(10);

    // SQL Injection - updated structure based on new Python functions
    if (result.vulnerabilities["SQL Injection"]) {
      const sqli = result.vulnerabilities["SQL Injection"];
      doc.text("SQL Injection:", 25, yPos);
      yPos += 5;
      doc.text(sqli.description, 30, yPos);
      yPos += 5;

      if (sqli.details && sqli.details.length > 0) {
        for (let detail of sqli.details) {
          doc.text(
            `- Parameter: ${detail.parameter}, Payload: ${detail.payload}, Type: ${detail.type}`,
            30,
            yPos
          );
          yPos += 5;

          // Check if we need a new page
          if (yPos > 270) {
            doc.addPage();
            yPos = 20;
          }
        }
      }

      yPos += 3;
    }

    // Check if we need a new page
    if (yPos > 270) {
      doc.addPage();
      yPos = 20;
    }

    // XSS
    if (result.vulnerabilities["XSS"]) {
      const xss = result.vulnerabilities["XSS"];
      doc.text("Cross-Site Scripting (XSS):", 25, yPos);
      yPos += 5;
      doc.text(xss.description, 30, yPos);
      yPos += 5;

      if (xss.details && xss.details.length > 0) {
        for (let detail of xss.details) {
          doc.text(
            `- Parameter: ${detail.parameter}, Payload: ${detail.payload}, Type: ${detail.type}`,
            30,
            yPos
          );
          yPos += 5;

          // Check if we need a new page
          if (yPos > 270) {
            doc.addPage();
            yPos = 20;
          }
        }
      }

      yPos += 3;
    }

    // Check if we need a new page
    if (yPos > 270) {
      doc.addPage();
      yPos = 20;
    }

    // Vulnerable Forms
    if (result.vulnerabilities["Vulnerable_Forms"]) {
      const formVulns = result.vulnerabilities["Vulnerable_Forms"];
      doc.text("Vulnerable Forms:", 25, yPos);
      yPos += 5;
      doc.text(formVulns.description, 30, yPos);
      yPos += 5;

      if (formVulns.forms && formVulns.forms.length > 0) {
        for (let form of formVulns.forms) {
          // Check if we need a new page
          if (yPos > 250) {
            doc.addPage();
            yPos = 20;
          }

          doc.text(`Form #${form.form_id}:`, 30, yPos);
          yPos += 5;
          doc.text(`- Action: ${form.action || "N/A"}`, 35, yPos);
          yPos += 5;
          doc.text(`- Method: ${form.method}`, 35, yPos);
          yPos += 5;

          const fieldsText = Array.isArray(form.fields)
            ? form.fields.join(", ")
            : form.fields || "No fields detected";
          doc.text(`- Fields: ${fieldsText}`, 35, yPos);
          yPos += 5;

          if (form.vulnerabilities && form.vulnerabilities.length > 0) {
            doc.text(`Detected Vulnerabilities:`, 35, yPos);
            yPos += 5;

            for (let vuln of form.vulnerabilities) {
              doc.text(
                `- ${vuln.type} in field '${vuln.field}' with payload: ${vuln.payload}`,
                40,
                yPos
              );
              yPos += 5;

              // Check if we need a new page
              if (yPos > 270) {
                doc.addPage();
                yPos = 20;
              }
            }
          }

          yPos += 3;
        }
      }
    }
  } else {
    doc.setFontSize(10);
    doc.text("No vulnerabilities detected.", 25, yPos);
  }

  // Technologies section
  if (yPos > 250) {
    doc.addPage();
    yPos = 20;
  }

  yPos += 5;
  doc.setFontSize(14);
  doc.text("Detected Technologies", 20, yPos);
  yPos += 8;

  if (result.technologies && Object.keys(result.technologies).length > 0) {
    doc.setFontSize(10);

    // CMS
    if (result.technologies.CMS) {
      doc.text(`CMS: ${result.technologies.CMS}`, 25, yPos);
      yPos += 5;
    }

    // frontend
    if (result.technologies.Frontend) {
      doc.text(`Frontend: ${result.technologies.Frontend}`, 25, yPos);
      yPos += 5;
    }

    // backend
    if (result.technologies.Backend) {
      doc.text(`Backend: ${result.technologies.Backend}`, 25, yPos);
      yPos += 5;
    }

    // server
    if (result.technologies.Server) {
      doc.text(`Server: ${result.technologies.Server}`, 25, yPos);
      yPos += 5;
    }

    // Powered-By
    if (result.technologies["X-Powered-By"]) {
      doc.text(
        `X-Powered-By: ${result.technologies["X-Powered-By"]}`,
        25,
        yPos
      );
      yPos += 5;
    }

    // type
    if (result.technologies.Type) {
      doc.text(`Site type: ${result.technologies.Type}`, 25, yPos);
      yPos += 5;
    }
  } else {
    doc.setFontSize(10);
    doc.text("No technologies detected.", 25, yPos);
    yPos += 5;
  }

  // Save the PDF
  const scanDate = new Date().toISOString().split("T")[0];
  const fileName = `security_scan_${encodeURIComponent(
    scannedUrl.replace(/^https?:\/\//, "").replace(/[\/\.]/g, "_")
  )}.pdf`;
  doc.save(fileName);
}

window.generateReport = generateReport;
