/**
 * Main JavaScript file for Cyber Threat Intelligence Dashboard
 * Handles global variables, initialization, and utility functions
 */

// Global variables
const API_URL = 'http://localhost:8080';
const userId = generateUserId();
let isDarkTheme = true;
let chatState = 0;

// Initialize scan results summary
const summary = { 
  safe: 0, 
  suspicious: 0, 
  valid: 0, 
  invalid: 0, 
  weak: 0, 
  medium: 0, 
  strong: 0, 
  unknown: 0, 
  infected: 0, 
  clean: 0, 
  private: 0, 
  public: 0 
};

// User profile to be sent to backend
let userProfile = {
  userId: userId,
  organizationType: '',
  securityConcerns: [],
  previousIncidents: false,
  networkType: '',
  sensitiveData: false
};

// Chart object
let scanChart;

// Initialize on document load
document.addEventListener('DOMContentLoaded', function() {
  // Start conversation with Prolog backend
  startConversation();
  
  // Initialize chart
  const ctx = document.getElementById('scanChart').getContext('2d');
  scanChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Safe', 'Suspicious', 'Valid', 'Invalid', 'Weak', 'Medium', 'Strong', 'Unknown', 'Infected', 'Clean', 'Private', 'Public'],
      datasets: [{
        label: 'Scan Results Summary',
        data: Object.values(summary),
        backgroundColor: [
          '#00e676', // safe
          '#ff5252', // suspicious
          '#00e676', // valid
          '#ff5252', // invalid
          '#ff5252', // weak
          '#ffab40', // medium
          '#00e676', // strong
          '#ffab40', // unknown
          '#ff5252', // infected
          '#00e676', // clean
          '#2196f3', // private
          '#2196f3'  // public
        ],
        borderWidth: 0,
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: function(context) {
              return `${context.label}: ${context.raw}`;
            }
          }
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          grid: {
            color: 'rgba(255, 255, 255, 0.1)'
          },
          ticks: {
            color: '#9e9e9e'
          }
        },
        x: {
          grid: {
            display: false
          },
          ticks: {
            color: '#9e9e9e'
          }
        }
      }
    }
  });
});

/**
 * Generate a unique user ID
 * @returns {string} A unique identifier
 */
function generateUserId() {
  return 'user_' + Math.random().toString(36).substr(2, 9);
}

/**
 * Toggle between light and dark themes
 */
function toggleTheme() {
  const body = document.body;
  const themeIcon = document.querySelector('.theme-toggle i');
  
  if (isDarkTheme) {
    body.classList.add('light-theme');
    themeIcon.className = 'fas fa-sun';
  } else {
    body.classList.remove('light-theme');
    themeIcon.className = 'fas fa-moon';
  }
  
  isDarkTheme = !isDarkTheme;
}

/**
 * Display notification
 * @param {string} title - Notification title
 * @param {string} message - Notification message
 * @param {string} type - Notification type (info, warning, error)
 */
function showNotification(title, message, type = 'info') {
  const notification = document.getElementById('notification');
  const notificationTitle = notification.querySelector('.notification-title');
  const notificationMessage = notification.querySelector('.notification-message');
  const notificationIcon = notification.querySelector('.notification-icon i');
  
  // Set icon based on notification type
  if (type === 'error') {
    notificationIcon.className = 'fas fa-exclamation-circle';
    notificationIcon.style.color = 'var(--danger)';
  } else if (type === 'warning') {
    notificationIcon.className = 'fas fa-exclamation-triangle';
    notificationIcon.style.color = 'var(--warning)';
  } else {
    notificationIcon.className = 'fas fa-info-circle';
    notificationIcon.style.color = 'var(--accent)';
  }
  
  // Set notification content
  notificationTitle.textContent = title;
  notificationMessage.textContent = message;
  
  // Show notification
  notification.classList.add('show');
  
  // Hide notification after 5 seconds
  setTimeout(() => {
    closeNotification();
  }, 5000);
}

/**
 * Close notification
 */
function closeNotification() {
  const notification = document.getElementById('notification');
  notification.classList.remove('show');
}

/**
 * Handle key press events
 * @param {Event} event - Key press event
 */
function handleKeyPress(event) {
  if (event.key === 'Enter') {
    sendMessage();
  }
}

/**
 * Get color value for scan result
 * @param {string} result - Scan result type
 * @returns {string} RGBA color value
 */
function getColorForResult(result) {
  if (["safe", "valid", "clean", "strong"].includes(result)) {
    return "0, 230, 118, 1"; // Green
  } else if (["suspicious", "infected", "weak", "invalid"].includes(result)) {
    return "255, 82, 82, 1"; // Red
  } else if (["medium", "unknown"].includes(result)) {
    return "255, 171, 64, 1"; // Orange
  } else {
    return "33, 150, 243, 1"; // Blue
  }
}