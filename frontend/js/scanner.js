/**
 * Scanner JavaScript for Cyber Threat Intelligence Dashboard
 * Handles all scanning functionality
 */

/**
 * Perform a security scan
 * @param {string} type - Type of scan (file, email, url, ip, etc.)
 */
async function scan(type) {
  const alertSound = document.getElementById('alertSound');
  let value = '';
  
  if (type === 'file') {
    const file = document.getElementById('fileUpload').files[0];
    value = file ? file.name : 'unknown.exe';
  } else if (type === 'device_users') {
    value = 'scan';
  } else {
    value = document.getElementById(type).value;
  }
  
  if (value === '' && type !== 'device_users') {
    showNotification('Input Required', 'Please enter a value to scan.', 'warning');
    return;
  }

  const output = document.getElementById(`result_${type}`);
  output.innerHTML = `
    <div style="display: flex; justify-content: center; align-items: center; height: 50px;">
      <div class="fa-3x">
        <i class="fas fa-circle-notch fa-spin" style="color: var(--accent);"></i>
      </div>
    </div>
  `;

  try {
    const res = await fetch(`${API_URL}/scan?type=${type}&value=${encodeURIComponent(value)}`);
    const data = await res.json();
    const result = data.result.toLowerCase();
    const detail = data.details || '';
    
    // Prepare the result HTML with an appropriate icon
    let iconClass = "";
    
    if (["safe", "valid", "clean", "strong"].includes(result)) {
      iconClass = "fas fa-shield-alt";
    } else if (["suspicious", "infected", "weak", "invalid"].includes(result)) {
      iconClass = "fas fa-exclamation-triangle";
    } else if (["medium", "unknown"].includes(result)) {
      iconClass = "fas fa-question-circle";
    } else {
      iconClass = "fas fa-info-circle";
    }
    
    output.innerHTML = `
      <strong class="${result}">
        <div class="result-icon" style="background: rgba(${getColorForResult(result)}, 0.2);">
          <i class="${iconClass}"></i>
        </div>
        ${result.toUpperCase()}
      </strong>
      <small>${detail}</small>
    `;
    
    // Update chart data
    summary[result] = (summary[result] || 0) + 1;
    scanChart.data.datasets[0].data = Object.values(summary);
    scanChart.update();

    // Play sound effects for critical results
    if (["suspicious", "infected", "weak", "invalid"].includes(result)) {
      alertSound.volume = 0.5;
      alertSound.play();
      // Show notification for critical results
      showNotification('Security Alert', `${type.charAt(0).toUpperCase() + type.slice(1)} scan detected an issue: ${result.toUpperCase()}`, 'error');
    } else if (["safe", "valid", "clean", "strong"].includes(result)) {
      document.getElementById('successSound').volume = 0.3;
      document.getElementById('successSound').play();
    }
    
    // If this is the first scan, show a tutorial notification
    if (Object.values(summary).reduce((a, b) => a + b, 0) === 1) {
      setTimeout(() => {
        showNotification('Scan Results', 'Results are color coded: green for secure, orange for medium risk, and red for high risk. Results are also added to the chart below.', 'info');
      }, 3000);
    }
    
    // Save scan results to backend
    saveScanResult(type, value, result);
    
  } catch (err) {
    output.innerHTML = `
      <strong class="suspicious">
        <div class="result-icon" style="background: rgba(255, 82, 82, 0.2);">
          <i class="fas fa-times-circle"></i>
        </div>
        ERROR
      </strong>
      <small>Could not connect to backend. Server may not be running.</small>
    `;
    
    showNotification('Connection Error', 'Could not connect to the backend server. Is the server running?', 'error');
  }
}

/**
 * Save scan result to be included in the CSV export
 * @param {string} type - Type of scan
 * @param {string} value - Scanned value
 * @param {string} result - Scan result
 */
async function saveScanResult(type, value, result) {
  try {
    await fetch(`${API_URL}/save_scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        userId: userId,
        type: type,
        value: value,
        result: result
      }),
    });
  } catch (error) {
    console.error('Error saving scan result:', error);
  }
}