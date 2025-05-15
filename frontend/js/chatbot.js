/**
 * Chatbot JavaScript for Cyber Threat Intelligence Dashboard
 * Handles chatbot interactions with the Prolog DSS backend
 */

/**
 * Start the conversation with the chatbot
 */
async function startConversation() {
  // Initial welcome message from the DSS backend
  await getChatResponse("start_assessment", true);
}

/**
 * Get response from Prolog DSS backend
 * @param {string} message - User message
 * @param {boolean} isFirstMessage - Whether this is the first message
 */
async function getChatResponse(message, isFirstMessage = false) {
  try {
    const chatArea = document.getElementById('chatArea');
    
    // Show typing indicator
    const typingIndicator = document.createElement('div');
    typingIndicator.className = 'typing-indicator bot-message';
    typingIndicator.innerHTML = `
      <div class="typing-dot"></div>
      <div class="typing-dot"></div>
      <div class="typing-dot"></div>
    `;
    chatArea.appendChild(typingIndicator);
    chatArea.scrollTop = chatArea.scrollHeight;
    
    // Make API call to Prolog backend
    const response = await fetch(`${API_URL}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        message: message,
        userId: userId,
        chatState: chatState,
        isFirstMessage: isFirstMessage
      }),
    });
    
    const data = await response.json();
    
    // Remove typing indicator
    typingIndicator.remove();
    
    // Create bot message element
    const messageDiv = document.createElement('div');
    messageDiv.className = 'chat-message bot-message fade-in';
    messageDiv.textContent = data.message;
    
    // Add quick options if provided
    if (data.options && data.options.length > 0) {
      const optionsDiv = document.createElement('div');
      optionsDiv.className = 'quick-options';
      
      data.options.forEach(option => {
        const optionButton = document.createElement('button');
        optionButton.className = 'quick-option';
        optionButton.textContent = option;
        optionButton.onclick = () => sendUserResponse(option);
        optionsDiv.appendChild(optionButton);
      });
      
      messageDiv.appendChild(optionsDiv);
    }
    
    chatArea.appendChild(messageDiv);
    chatArea.scrollTop = chatArea.scrollHeight;
    
    // Play message tone
    document.getElementById('messageTone').volume = 0.3;
    document.getElementById('messageTone').play();
    
    // Update chat state if provided
    if (data.chatState !== undefined) {
      chatState = data.chatState;
    }
    
    // Update profile if provided
    if (data.profileUpdate) {
      updateUserProfile(data.profileUpdate);
    }
    
    // Check if we should move to dashboard
    if (data.showDashboard) {
      showDashboard();
    }
  } catch (error) {
    console.error('Error communicating with DSS backend:', error);
    showNotification('Connection Error', 'Could not communicate with the DSS backend. Is the server running?', 'error');
  }
}

/**
 * Send user response to backend
 * @param {string} message - User message
 */
function sendUserResponse(message) {
  // Display user's message in chat
  addUserMessage(message);
  
  // Get response from DSS backend
  getChatResponse(message);
  
  // Update profile based on the response
  updateProfileBasedOnAnswer(message);
}

/**
 * Update user profile based on current question and answer
 * @param {string} answer - User's answer
 */
function updateProfileBasedOnAnswer(answer) {
  switch (chatState) {
    case 0: // Organization type
      userProfile.organizationType = answer;
      break;
    case 1: // Security concerns
      if (!userProfile.securityConcerns.includes(answer)) {
        userProfile.securityConcerns.push(answer);
      }
      break;
    case 2: // Previous incidents
      userProfile.previousIncidents = (answer === "Yes");
      break;
    case 3: // Network type
      userProfile.networkType = answer;
      break;
    case 4: // Sensitive data
      userProfile.sensitiveData = (answer === "Yes");
      break;
  }
  
  // Send updated profile to backend
  sendProfileToBackend();
}

/**
 * Update user profile with data from backend
 * @param {Object} profileUpdate - Profile update data
 */
function updateUserProfile(profileUpdate) {
  for (const key in profileUpdate) {
    userProfile[key] = profileUpdate[key];
  }
}

/**
 * Send profile to backend
 */
async function sendProfileToBackend() {
  try {
    await fetch(`${API_URL}/profile`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(userProfile),
    });
  } catch (error) {
    console.error('Error updating profile on backend:', error);
  }
}

/**
 * Display user message in chat
 * @param {string} message - User message
 */
function addUserMessage(message) {
  const chatArea = document.getElementById('chatArea');
  const messageDiv = document.createElement('div');
  messageDiv.className = 'chat-message user-message fade-in';
  messageDiv.textContent = message;
  chatArea.appendChild(messageDiv);
  chatArea.scrollTop = chatArea.scrollHeight;
  
  // Clear input
  document.getElementById('userInput').value = '';
}

/**
 * Handle sending message via input field
 */
function sendMessage() {
  const userInput = document.getElementById('userInput');
  const message = userInput.value.trim();
  
  if (message === '') return;
  
  sendUserResponse(message);
}