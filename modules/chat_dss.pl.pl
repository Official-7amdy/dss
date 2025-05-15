:- module(chat_dss, [
    get_welcome_message/2,
    process_chat_message/8,
    process_org_type/4,
    process_security_concerns/4,
    process_previous_incidents/4,
    process_network_type/4,
    process_sensitive_data/4,
    process_final_step/4,
    process_general_question/2
]).

/**
 * Chatbot Decision Support System Module
 * 
 * This module implements the chatbot decision support system logic.
 * It handles the conversation flow and provides security recommendations.
 */

/**
 * Initial welcome message
 * @param Response - Welcome message text
 * @param Options - List of available options for the user
 */
get_welcome_message(
    "Hello! I'm CyberSentinel, your cybersecurity assistant. I'll help assess your security needs and guide you to the right tools. First, what type of organization are you securing?",
    ["Personal", "Small Business", "Enterprise", "Government"]
).

/**
 * Process chat message based on state
 * @param UserId - User identifier
 * @param Message - User message
 * @param State - Current chat state
 * @param Response - Response message to send back
 * @param Options - Available options for the user
 * @param NextState - Next chat state
 * @param ShowDashboard - Whether to show the dashboard
 * @param ProfileUpdate - Profile updates to apply
 */
process_chat_message(UserId, Message, State, Response, Options, NextState, ShowDashboard, ProfileUpdate) :-
    % Based on current state, process the message and determine the next state
    (
        State =:= 0 -> % Organization type
            process_org_type(Message, Response, Options, ProfileUpdate),
            NextState is 1,
            ShowDashboard = false
    ;
        State =:= 1 -> % Security concerns
            process_security_concerns(Message, Response, Options, ProfileUpdate),
            NextState is 2,
            ShowDashboard = false
    ;
        State =:= 2 -> % Previous incidents
            process_previous_incidents(Message, Response, Options, ProfileUpdate),
            NextState is 3,
            ShowDashboard = false
    ;
        State =:= 3 -> % Network type
            process_network_type(Message, Response, Options, ProfileUpdate),
            NextState is 4,
            ShowDashboard = false
    ;
        State =:= 4 -> % Sensitive data
            process_sensitive_data(Message, Response, Options, ProfileUpdate),
            NextState is 5,
            ShowDashboard = false
    ;
        State =:= 5 -> % Proceed to dashboard or more questions
            process_final_step(Message, Response, Options, ShowDashboard1),
            (ShowDashboard1 = true -> 
                NextState is 6,  % Move to post-dashboard state
                ShowDashboard = true,
                ProfileUpdate = json([])
            ; 
                NextState is 5,  % Stay in current state for more questions
                ShowDashboard = false,
                ProfileUpdate = json([])
            )
    ;
        State >= 6 -> % Post-dashboard questions or general chat
            process_general_question(Message, Response),
            Options = [],
            NextState is State,  % Keep the same state
            ShowDashboard = false,
            ProfileUpdate = json([])
    ).

/**
 * Process organization type (State 0)
 */
process_org_type(OrgType, Response, Options, ProfileUpdate) :-
    % Create profile update object
    ProfileUpdate = json([organizationType=OrgType]),
    
    % Generate next response and options
    Response = "Thank you. What are your primary security concerns?",
    Options = ["Data Breaches", "Malware", "Phishing", "Insider Threats", "Network Vulnerabilities"].

/**
 * Process security concerns (State 1)
 */
process_security_concerns(Concern, Response, Options, ProfileUpdate) :-
    % Create profile update object
    ProfileUpdate = json([securityConcerns=[Concern]]),
    
    % Generate next response and options
    Response = "Have you experienced any security incidents in the past 6 months?",
    Options = ["Yes", "No", "Not Sure"].

/**
 * Process previous incidents (State 2)
 */
process_previous_incidents(Answer, Response, Options, ProfileUpdate) :-
    % Determine boolean value based on answer
    (Answer = "Yes" -> HasIncidents = true ; HasIncidents = false),
    
    % Create profile update object
    ProfileUpdate = json([previousIncidents=HasIncidents]),
    
    % Generate next response and options
    Response = "What type of network environment are you using?",
    Options = ["Home Network", "Small Office", "Enterprise Network", "Cloud-Based", "Hybrid"].

/**
 * Process network type (State 3)
 */
process_network_type(NetworkType, Response, Options, ProfileUpdate) :-
    % Create profile update object
    ProfileUpdate = json([networkType=NetworkType]),
    
    % Generate next response and options
    Response = "Do you handle sensitive data like personal information, financial records, or intellectual property?",
    Options = ["Yes", "No", "Not Sure"].

/**
 * Process sensitive data (State 4)
 */
process_sensitive_data(Answer, Response, Options, ProfileUpdate) :-
    % Determine boolean value based on answer
    (Answer = "Yes" -> HasSensitiveData = true ; HasSensitiveData = false),
    
    % Create profile update object
    ProfileUpdate = json([sensitiveData=HasSensitiveData]),
    
    % Generate next response and options based on security profile
    Response = "Based on your responses, I've prepared a customized security dashboard for you. Your current threat assessment is displayed at the top of the dashboard. Would you like to proceed to the dashboard now?",
    Options = ["Yes, show me the dashboard", "I have more questions"].

/**
 * Process final step (State 5)
 */
process_final_step(Answer, Response, Options, ShowDashboard) :-
    % Determine if we should show dashboard or not
    (Answer = "Yes, show me the dashboard" -> 
        ShowDashboard = true,
        Response = "Great! Here's your security dashboard. You can scan files, emails, URLs, and more to detect potential threats.",
        Options = []
    ; 
        ShowDashboard = false,
        Response = "What specific questions do you have about cybersecurity? I can provide insights on passwords, malware, phishing, network security, or other topics.",
        Options = ["Password Security", "Malware Protection", "Phishing Defense", "Network Security", "Move to Dashboard"]
    ).

/**
 * Process general question (State 6+)
 */
process_general_question(Question, Response) :-
    % Convert question to lowercase for easier matching
    string_lower(Question, LowerQuestion),
    
    % Try to match question with predefined topics
    (
        (sub_string(LowerQuestion, _, _, _, "password") ; Question = "Password Security") -> 
            Response = "Strong passwords are critical for security. They should be at least 12 characters long, include a mix of upper and lowercase letters, numbers and symbols. You can use our Password Strength checker in the dashboard to test your passwords. For maximum security, consider using a password manager to generate and store unique passwords for each account."
    ;
        (sub_string(LowerQuestion, _, _, _, "malware") ; Question = "Malware Protection") -> 
            Response = "Malware is a serious threat to all organizations. Our File Scanner can help detect suspicious files. For comprehensive protection: 1) Keep all software updated, 2) Use reputable antivirus software with real-time protection, 3) Be cautious with email attachments and downloads, 4) Use application whitelisting when possible, 5) Regular system backups are essential to recover from ransomware."
    ;
        (sub_string(LowerQuestion, _, _, _, "phish") ; Question = "Phishing Defense") -> 
            Response = "Phishing attacks are increasingly sophisticated. You can use our Email Scanner to check suspicious emails. Best practices include: 1) Verify sender emails carefully, 2) Don't click unexpected links, 3) Be wary of urgency or threats, 4) Check for spelling/grammar errors, 5) Hover over links before clicking, 6) Never provide sensitive information via email, 7) Implement DMARC, SPF, and DKIM for your domain."
    ;
        (sub_string(LowerQuestion, _, _, _, "network") ; Question = "Network Security") -> 
            Response = "Network security is essential. You can use our IP Scanner to check for private vs public IPs. Key recommendations: 1) Use a hardware firewall, 2) Implement network segmentation, 3) Use VPNs for remote access, 4) Enable encryption for wireless networks, 5) Conduct regular vulnerability scanning, 6) Monitor network traffic for suspicious patterns, 7) Use intrusion detection/prevention systems."
    ;
        (sub_string(LowerQuestion, _, _, _, "data breach") ; sub_string(LowerQuestion, _, _, _, "breach")) -> 
            Response = "Data breaches can be devastating. To protect against them: 1) Encrypt sensitive data both at rest and in transit, 2) Implement strong access controls using least privilege principles, 3) Use multi-factor authentication, 4) Regular security awareness training, 5) Have an incident response plan ready, 6) Conduct regular security assessments, 7) Monitor for unauthorized access or data exfiltration."
    ;
        (sub_string(LowerQuestion, _, _, _, "vulnerability") ; sub_string(LowerQuestion, _, _, _, "vulnerab")) -> 
            Response = "Vulnerability management is crucial. Best practices include: 1) Maintain a complete inventory of all assets, 2) Implement a patch management system, 3) Conduct regular vulnerability scans, 4) Prioritize vulnerabilities based on risk, 5) Test patches before full deployment, 6) Consider penetration testing to identify weaknesses proactively, 7) Track remediation progress with clear metrics."
    ;
        (sub_string(LowerQuestion, _, _, _, "insider") ; sub_string(LowerQuestion, _, _, _, "employee")) -> 
            Response = "Insider threats are particularly challenging. Key controls include: 1) Principle of least privilege access, 2) Separation of duties for critical functions, 3) Monitor user activities, especially for sensitive data, 4) Conduct background checks for employees with privileged access, 5) Revoke access immediately after termination, 6) Implement data loss prevention tools, 7) Create a security-aware culture."
    ;
        (sub_string(LowerQuestion, _, _, _, "encrypt") ; sub_string(LowerQuestion, _, _, _, "encryption")) -> 
            Response = "Encryption is a fundamental security control. Important considerations: 1) Use strong, industry-standard encryption protocols (AES-256, RSA-2048), 2) Encrypt sensitive data both at rest and in transit, 3) Implement HTTPS across all web properties, 4) Secure key management is critical - protect encryption keys carefully, 5) Consider full-disk encryption for mobile devices, 6) Email encryption for sensitive communications."
    ;
        (sub_string(LowerQuestion, _, _, _, "backup") ; sub_string(LowerQuestion, _, _, _, "recovery")) -> 
            Response = "Data backup and recovery is essential, especially against ransomware. Follow the 3-2-1 rule: 3 copies of your data, on 2 different media types, with 1 copy stored offsite. Other best practices: 1) Regular automated backups, 2) Encrypt backup data, 3) Test restoration processes regularly, 4) Keep some backups offline and disconnected, 5) Document your backup and recovery procedures, 6) Consider cloud backup solutions for redundancy."
    ;
        (sub_string(LowerQuestion, _, _, _, "compliance") ; sub_string(LowerQuestion, _, _, _, "regulation")) -> 
            Response = "Compliance with regulations like GDPR, HIPAA, PCI DSS, etc. requires: 1) Identify which regulations apply to your organization, 2) Conduct gap analysis against requirements, 3) Implement necessary controls and policies, 4) Regular staff training on compliance requirements, 5) Document everything - policies, processes, incidents, 6) Regular audits and assessments, 7) Stay updated on regulatory changes."
    ;
        (sub_string(LowerQuestion, _, _, _, "incident") ; sub_string(LowerQuestion, _, _, _, "response")) -> 
            Response = "An effective incident response plan includes: 1) Clearly defined roles and responsibilities, 2) Step-by-step procedures for different incident types, 3) Communication protocols (internal and external), 4) Tools and resources needed for response, 5) Regular testing through tabletop exercises, 6) Post-incident analysis process, 7) Integration with business continuity plans, 8) Contact information for all stakeholders and authorities."
    ;
        sub_string(LowerQuestion, _, _, _, "dashboard") -> 
            Response = "Ready to proceed to the dashboard? It contains all the security tools you need based on your profile. Select 'Move to Dashboard' when you're ready."
    ;
        Question = "Move to Dashboard" ->
            Response = "Great! I'll show you the security dashboard now. You can scan files, emails, URLs, and more to detect potential threats."
    ;
        % Default response for unmatched questions
        Response = "That's an interesting question about cybersecurity. Based on your security profile, I recommend using the tools in our dashboard to conduct a full security assessment. The dashboard has specialized tools for file scanning, email validation, and password strength testing. Would you like me to explain any specific security topic in more detail?"
    ).