/**
 * Dashboard JavaScript for Cyber Threat Intelligence Dashboard
 * Handles dashboard display and threat assessment
 */

/**
 * Show dashboard interface
 */
function showDashboard() {
  // Hide chatbot, show dashboard
  document.getElementById('chatbot-container').style.display = 'none';
  const dashboard = document.getElementById('dashboard-container');
  dashboard.style.display = 'block';
  
  // Animate in
  setTimeout(() => {
    dashboard.style.opacity = '1';
    dashboard.style.transform = 'translateY(0)';
    
    // Get threat levels from backend
    getThreatLevels();
  }, 100);
  
  // Show welcome notification
  setTimeout(() => {
    showNotification('Welcome to your Security Dashboard', 'Your threat assessment has been completed based on your profile.');
  }, 1000);
}

/**
 * Get threat levels from backend
 */
async function getThreatLevels() {
  try {
    const response = await fetch(`${API_URL}/threat_assessment?userId=${userId}`);
    const data = await response.json();
    
    // Set threat levels on dashboard
    setThreatLevels(data);
  } catch (error) {
    console.error('Error getting threat assessment:', error);
    showNotification('Error', 'Could not retrieve threat assessment from the backend.', 'error');
  }
}

/**
 * Set threat levels on dashboard
 * @param {Object} threatData - Threat assessment data
 */
function setThreatLevels(threatData) {
  const overallEl = document.getElementById('overallThreatLevel');
  const networkEl = document.getElementById('networkThreatLevel');
  const deviceEl = document.getElementById('deviceThreatLevel');
  const accessEl = document.getElementById('accessThreatLevel');
  
  // Set values and colors
  overallEl.textContent = threatData.overall;
  overallEl.className = `threat-category-value threat-${threatData.overall.toLowerCase()}`;
  
  networkEl.textContent = threatData.network;
  networkEl.className = `threat-category-value threat-${threatData.network.toLowerCase()}`;
  
  deviceEl.textContent = threatData.device;
  deviceEl.className = `threat-category-value threat-${threatData.device.toLowerCase()}`;
  
  accessEl.textContent = threatData.access;
  accessEl.className = `threat-category-value threat-${threatData.access.toLowerCase()}`;
  
  // Highlight high-risk areas with pulse animation
  const highRiskElements = document.querySelectorAll('.threat-high');
  highRiskElements.forEach(el => {
    el.classList.add('pulse');
  });
  
  // Update card visibility based on threat levels
  adjustDashboardBasedOnThreat(threatData);
}

/**
 * Adjust dashboard display based on threat levels
 * @param {Object} threatData - Threat assessment data
 */
function adjustDashboardBasedOnThreat(threatData) {
  // Example: If network threat is high, highlight IP scanner
  if (threatData.network === 'High') {
    const ipCard = document.querySelector('.card:has(#result_ip)');
    if (ipCard) {
      ipCard.classList.add('pulse');
      ipCard.style.order = '-1'; // Move to top of grid
    }
  }
  
  // Example: If access threat is high, highlight password scanner
  if (threatData.access === 'High') {
    const passwordCard = document.querySelector('.card:has(#result_password)');
    if (passwordCard) {
      passwordCard.classList.add('pulse');
      passwordCard.style.order = '-1'; // Move to top of grid
    }
  }
}