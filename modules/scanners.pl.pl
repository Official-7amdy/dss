::- use_module(library(http/thread_httpd)).
:- use_module(library(http/http_dispatch)).
:- use_module(library(http/http_parameters)).
:- use_module(library(http/http_json)).
:- use_module(library(http/http_files)).
:- use_module(library(http/http_cors)).
:- use_module(library(readutil)).
:- dynamic scan_log/3.
:- dynamic user_profile/6.
:- dynamic chat_history/2.
:- dynamic chat_state/2.

:- initialization(server).

% Start the server with CORS enabled
server :- 
    http_server(http_dispatch, [port(8080)]),
    format('Server started on port 8080~n').

% Set up CORS for all handlers
:- http_handler(root(.), 
    http_cors_enable([methods([get,post,put,delete,options]),
                     allow_headers(['Authorization', 'Content-Type']),
                     allow_origin([*])], serve_frontend), 
    [prefix]).

:- http_handler(root(scan), 
    http_cors_enable([methods([get,post]), allow_origin([*])], handle_scan), 
    []).

:- http_handler(root(export_csv), 
    http_cors_enable([methods([get]), allow_origin([*])], export_csv), 
    []).

:- http_handler(root(chat), 
    http_cors_enable([methods([post]), allow_origin([*])], handle_chat), 
    []).

:- http_handler(root(profile), 
    http_cors_enable([methods([post,get]), allow_origin([*])], handle_profile), 
    []).

:- http_handler(root(threat_assessment), 
    http_cors_enable([methods([get]), allow_origin([*])], get_threat_assessment), 
    []).

serve_frontend(Request) :-
    http_reply_from_files('frontend', [index('index.html')], Request).

% Handle scan requests
handle_scan(Request) :-
    http_parameters(Request, [ type(Type, []), value(Value, []) ]),
    scan(Type, Value, Result),
    details(Type, Value, Detail),
    assertz(scan_log(Type, Value, Result)),
    reply_json(json([result=Result, details=Detail])).

% Handle chat requests
handle_chat(Request) :-
    http_read_json_dict(Request, Data),
    get_dict(message, Data, Message),
    get_dict(userId, Data, UserId),
    
    % Get chat state or use default 0
    (get_dict(chatState, Data, ChatState) -> true ; ChatState = 0),
    
    % Check if this is the first message
    (get_dict(isFirstMessage, Data, true) -> 
        retractall(chat_state(UserId, _)),  % Clear any existing chat state
        assertz(chat_state(UserId, 0)),     % Set initial state
        get_welcome_message(Response, Options)
    ;
        % Process user message and get next response
        assertz(chat_history(UserId, Message)),
        process_chat_message(UserId, Message, ChatState, Response, Options, NextState, ShowDashboard, ProfileUpdate)
    ),
    
    % Update chat state
    retractall(chat_state(UserId, _)),
    assertz(chat_state(UserId, NextState)),
    
    % Prepare response
    reply_json(json([
        message=Response,
        options=Options,
        chatState=NextState,
        showDashboard=ShowDashboard,
        profileUpdate=ProfileUpdate
    ])).

% Handle profile updates
handle_profile(Request) :-
    (http_method(Request, post) ->
        http_read_json_dict(Request, Data),
        get_dict(userId, Data, UserId),
        get_dict(organizationType, Data, OrgType),
        get_dict(securityConcerns, Data, Concerns),
        get_dict(previousIncidents, Data, Incidents),
        get_dict(networkType, Data, Network),
        get_dict(sensitiveData, Data, Sensitive),
        
        % Delete old profile if exists
        retractall(user_profile(UserId, _, _, _, _, _)),
        
        % Save new profile
        assertz(user_profile(UserId, OrgType, Concerns, Incidents, Network, Sensitive)),
        
        reply_json(json([status="Profile updated"]))
    ;
        % GET request
        http_parameters(Request, [ userId(UserId, []) ]),
        (user_profile(UserId, OrgType, Concerns, Incidents, Network, Sensitive) ->
            reply_json(json([
                userId=UserId,
                organizationType=OrgType,
                securityConcerns=Concerns,
                previousIncidents=Incidents,
                networkType=Network,
                sensitiveData=Sensitive
            ]))
        ;
            reply_json(json([error="Profile not found"]))
        )
    ).

% Get threat assessment based on profile
get_threat_assessment(Request) :-
    http_parameters(Request, [ userId(UserId, []) ]),
    (user_profile(UserId, OrgType, Concerns, Incidents, Network, Sensitive) ->
        calculate_threat_level(OrgType, Concerns, Incidents, Network, Sensitive, OverallThreat),
        calculate_network_threat(Network, Incidents, NetworkThreat),
        calculate_device_threat(OrgType, DeviceThreat),
        calculate_access_threat(Sensitive, AccessThreat),
        
        reply_json(json([
            overall=OverallThreat,
            network=NetworkThreat,
            device=DeviceThreat,
            access=AccessThreat
        ]))
    ;
        reply_json(json([error="Profile not found"]))
    ).

% Export scan logs as CSV
export_csv(_) :-
    format('Content-type: text/csv~n'),
    format('Content-Disposition: attachment; filename=\"scan_report.csv\"~n~n'),
    format("Type,Value,Result~n"),
    forall(scan_log(Type, Value, Result),
           format("~w,~w,~w~n", [Type, Value, Result])).

% ========================== CHATBOT DSS LOGIC ==========================

% Initial welcome message
get_welcome_message(
    "Hello! I'm CyberSentinel, your cybersecurity assistant. I'll help assess your security needs and guide you to the right tools. First, what type of organization are you securing?",
    ["Personal", "Small Business", "Enterprise", "Government"]
).

% Process chat message based on state
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
            process_final_step(Message, Response, Options, ShowDashboard1, ProfileUpdate),
            (ShowDashboard1 = true -> 
                NextState is 6,  % Move to post-dashboard state
                ShowDashboard = true
            ; 
                NextState is 5,  % Stay in current state for more questions
                ShowDashboard = false
            )
    ;
        State >= 6 -> % Post-dashboard questions or general chat
            process_general_question(Message, Response),
            Options = [],
            NextState is State,  % Keep the same state
            ShowDashboard = false,
            ProfileUpdate = json([])
    ).

% Process organization type (State 0)
process_org_type(OrgType, Response, Options, ProfileUpdate) :-
    % Create profile update object
    ProfileUpdate = json([organizationType=OrgType]),
    
    % Generate next response and options
    Response = "Thank you. What are your primary security concerns?",
    Options = ["Data Breaches", "Malware", "Phishing", "Insider Threats", "Network Vulnerabilities"].

% Process security concerns (State 1)
process_security_concerns(Concern, Response, Options, ProfileUpdate) :-
    % Create profile update object
    ProfileUpdate = json([securityConcerns=[Concern]]),
    
    % Generate next response and options
    Response = "Have you experienced any security incidents in the past 6 months?",
    Options = ["Yes", "No", "Not Sure"].

% Process previous incidents (State 2)
process_previous_incidents(Answer, Response, Options, ProfileUpdate) :-
    % Determine boolean value based on answer
    (Answer = "Yes" -> HasIncidents = true ; HasIncidents = false),
    
    % Create profile update object
    ProfileUpdate = json([previousIncidents=HasIncidents]),
    
    % Generate next response and options
    Response = "What type of network environment are you using?",
    Options = ["Home Network", "Small Office", "Enterprise Network", "Cloud-Based", "Hybrid"].

% Process network type (State 3)
process_network_type(NetworkType, Response, Options, ProfileUpdate) :-
    % Create profile update object
    ProfileUpdate = json([networkType=NetworkType]),
    
    % Generate next response and options
    Response = "Do you handle sensitive data like personal information, financial records, or intellectual property?",
    Options = ["Yes", "No", "Not Sure"].

% Process sensitive data (State 4)
process_sensitive_data(Answer, Response, Options, ProfileUpdate) :-
    % Determine boolean value based on answer
    (Answer = "Yes" -> HasSensitiveData = true ; HasSensitiveData = false),
    
    % Create profile update object
    ProfileUpdate = json([sensitiveData=HasSensitiveData]),
    
    % Generate next response and options based on security profile
    Response = "Based on your responses, I've prepared a customized security dashboard for you. Your current threat assessment is displayed at the top of the dashboard. Would you like to proceed to the dashboard now?",
    Options = ["Yes, show me the dashboard", "I have more questions"].

% Process final step (State 5)
process_final_step(Answer, Response, Options, ShowDashboard, ProfileUpdate) :-
    % Empty profile update
    ProfileUpdate = json([]),
    
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

% Process general question (State 6+)
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

% ========================== THREAT ASSESSMENT LOGIC ==========================

% Calculate overall threat level
calculate_threat_level(OrgType, Concerns, Incidents, Network, Sensitive, Threat) :-
    % Start with base threat level
    (
        (OrgType = "Enterprise" ; OrgType = "Government") -> 
            BaseLevel = "Medium"
        ;
            BaseLevel = "Low"
    ),
    
    % Check serious concerns (Data Breaches, Insider Threats)
    (
        (member("Data Breaches", Concerns) ; member("Insider Threats", Concerns)) ->
            (
                BaseLevel = "Low" -> Level1 = "Medium";
                BaseLevel = "Medium" -> Level1 = "High";
                Level1 = BaseLevel
            )
        ;
            Level1 = BaseLevel
    ),
    
    % Check previous incidents
    (
        Incidents = true ->
            (
                Level1 = "Low" -> Level2 = "Medium";
                Level1 = "Medium" -> Level2 = "High";
                Level2 = Level1
            )
        ;
            Level2 = Level1
    ),
    
    % Check network complexity
    (
        (Network = "Enterprise Network" ; Network = "Hybrid") ->
            (
                Level2 = "Low" -> Level3 = "Medium";
                Level3 = Level2
            )
        ;
            Level3 = Level2
    ),
    
    % Check sensitive data
    (
        Sensitive = true ->
            (
                Level3 = "Low" -> Threat = "Medium";
                Level3 = "Medium" -> Threat = "High";
                Threat = Level3
            )
        ;
            Threat = Level3
    ).

% Calculate network threat level
calculate_network_threat(Network, Incidents, Threat) :-
    % Base network threat on network type
    (
        (Network = "Enterprise Network" ; Network = "Hybrid") -> 
            BaseLevel = "Medium"
        ;
            BaseLevel = "Low"
    ),
    
    % Adjust for previous incidents
    (
        Incidents = true ->
            Threat = "High"
        ;
            Threat = BaseLevel
    ).

% Calculate device threat level based on organization type
calculate_device_threat(OrgType, Threat) :-
    (
        (OrgType = "Enterprise" ; OrgType = "Government") -> 
            Threat = "Medium"
        ;
            Threat = "Low"
    ).

% Calculate access threat level based on sensitive data
calculate_access_threat(Sensitive, Threat) :-
    (
        Sensitive = true ->
            Threat = "High"
        ;
            Threat = "Medium"
    ).:- use_module(library(http/thread_httpd)).
:- use_module(library(http/http_dispatch)).
:- use_module(library(http/http_parameters)).
:- use_module(library(http/http_json)).
:- use_module(library(http/http_files)).
:- use_module(library(http/http_cors)).
:- use_module(library(readutil)).
:- dynamic scan_log/3.
:- dynamic user_profile/6.
:- dynamic chat_history/2.

:- initialization(server).

% Start the server with CORS enabled
server :- 
    http_server(http_dispatch, [port(8080)]),
    format('Server started on port 8080~n').

% Set up CORS for all handlers
:- http_handler(root(.), 
    http_cors_enable([methods([get,post,put,delete,options]),
                     allow_headers(['Authorization', 'Content-Type']),
                     allow_origin([*])], serve_frontend), 
    [prefix]).

:- http_handler(root(scan), 
    http_cors_enable([methods([get,post]), allow_origin([*])], handle_scan), 
    []).

:- http_handler(root(export_csv), 
    http_cors_enable([methods([get]), allow_origin([*])], export_csv), 
    []).

:- http_handler(root(chat), 
    http_cors_enable([methods([post]), allow_origin([*])], handle_chat), 
    []).

:- http_handler(root(profile), 
    http_cors_enable([methods([post,get]), allow_origin([*])], handle_profile), 
    []).

:- http_handler(root(threat_assessment), 
    http_cors_enable([methods([get]), allow_origin([*])], get_threat_assessment), 
    []).

serve_frontend(Request) :-
    http_reply_from_files('frontend', [index('index.html')], Request).

% Handle scan requests
handle_scan(Request) :-
    http_parameters(Request, [ type(Type, []), value(Value, []) ]),
    scan(Type, Value, Result),
    details(Type, Value, Detail),
    assertz(scan_log(Type, Value, Result)),
    reply_json(json([result=Result, details=Detail])).

% Handle chat requests
handle_chat(Request) :-
    http_read_json_dict(Request, Data),
    get_dict(message, Data, Message),
    get_dict(userId, Data, UserId),
    assertz(chat_history(UserId, Message)),
    chatbot_response(Message, Response),
    reply_json(json([response=Response])).

% Handle profile updates
handle_profile(Request) :-
    (http_method(Request, post) ->
        http_read_json_dict(Request, Data),
        get_dict(userId, Data, UserId),
        get_dict(organizationType, Data, OrgType),
        get_dict(securityConcerns, Data, Concerns),
        get_dict(previousIncidents, Data, Incidents),
        get_dict(networkType, Data, Network),
        get_dict(sensitiveData, Data, Sensitive),
        
        % Delete old profile if exists
        retractall(user_profile(UserId, _, _, _, _, _)),
        
        % Save new profile
        assertz(user_profile(UserId, OrgType, Concerns, Incidents, Network, Sensitive)),
        
        reply_json(json([status="Profile updated"]))
    ;
        % GET request
        http_parameters(Request, [ userId(UserId, []) ]),
        (user_profile(UserId, OrgType, Concerns, Incidents, Network, Sensitive) ->
            reply_json(json([
                userId=UserId,
                organizationType=OrgType,
                securityConcerns=Concerns,
                previousIncidents=Incidents,
                networkType=Network,
                sensitiveData=Sensitive
            ]))
        ;
            reply_json(json([error="Profile not found"]))
        )
    ).

% Get threat assessment based on profile
get_threat_assessment(Request) :-
    http_parameters(Request, [ userId(UserId, []) ]),
    (user_profile(UserId, OrgType, Concerns, Incidents, Network, Sensitive) ->
        calculate_threat_level(OrgType, Concerns, Incidents, Network, Sensitive, OverallThreat),
        calculate_network_threat(Network, Incidents, NetworkThreat),
        calculate_device_threat(OrgType, DeviceThreat),
        calculate_access_threat(Sensitive, AccessThreat),
        
        reply_json(json([
            overall=OverallThreat,
            network=NetworkThreat,
            device=DeviceThreat,
            access=AccessThreat
        ]))
    ;
        reply_json(json([error="Profile not found"]))
    ).

% Export scan logs as CSV
export_csv(_) :-
    format('Content-type: text/csv~n'),
    format('Content-Disposition: attachment; filename=\"scan_report.csv\"~n~n'),
    format("Type,Value,Result~n"),
    forall(scan_log(Type, Value, Result),
           format("~w,~w,~w~n", [Type, Value, Result])).

% ========================== CHATBOT DSS LOGIC ==========================

% Chatbot response generation
chatbot_response(Message, Response) :-
    string_lower(Message, LowerMessage),
    (
        sub_string(LowerMessage, _, _, _, "password") -> 
            Response = "Strong passwords are critical for security. They should be at least 12 characters long, include a mix of upper and lowercase letters, numbers and symbols. You can use our Password Strength checker in the dashboard to test your passwords."
    ;
        sub_string(LowerMessage, _, _, _, "malware") -> 
            Response = "Malware is a serious threat to all organizations. Our File Scanner can help detect suspicious files. I also recommend regular system updates, using reputable antivirus software, and educating users about not opening suspicious attachments."
    ;
        sub_string(LowerMessage, _, _, _, "phishing") -> 
            Response = "Phishing attacks are increasingly sophisticated. You can use our Email Scanner to check suspicious emails. Always verify unexpected emails, especially those requesting sensitive information or containing links."
    ;
        sub_string(LowerMessage, _, _, _, "network") -> 
            Response = "Network security is essential. You can use our IP Scanner to check for private vs public IPs. I recommend implementing firewalls, VPNs for remote access, regular network monitoring, and segmentation for sensitive systems."
    ;
        sub_string(LowerMessage, _, _, _, "data breach") -> 
            Response = "Data breaches can be devastating. To protect against them, ensure you're encrypting sensitive data, implementing access controls, using strong authentication, and training employees on security awareness."
    ;
        sub_string(LowerMessage, _, _, _, "vulnerability") -> 
            Response = "Vulnerability management is crucial. Make sure to keep all systems updated, run regular security scans, implement proper patch management, and consider penetration testing to identify weaknesses before attackers do."
    ;
        sub_string(LowerMessage, _, _, _, "insider threat") -> 
            Response = "Insider threats are particularly challenging. Implement the principle of least privilege, use strong access controls, monitor user activities, and establish clear security policies and training for employees."
    ;
        sub_string(LowerMessage, _, _, _, "encrypt") -> 
            Response = "Encryption is a fundamental security control. Ensure that sensitive data is encrypted both at rest and in transit. Use industry-standard encryption protocols and manage encryption keys securely."
    ;
        sub_string(LowerMessage, _, _, _, "dashboard") -> 
            Response = "Ready to proceed to the dashboard? It contains all the security tools you need based on your profile. Click 'Yes, show me the dashboard' when you're ready."
    ;
        Response = "Based on your security profile, I recommend starting with a full system assessment. The dashboard has tools for file scanning, email validation, and password strength testing. Would you like to proceed to the dashboard now?"
    ).

% ========================== THREAT ASSESSMENT LOGIC ==========================

% Calculate overall threat level
calculate_threat_level(OrgType, Concerns, Incidents, Network, Sensitive, Threat) :-
    % Start with base threat level
    (
        (OrgType = "Enterprise" ; OrgType = "Government") -> 
            BaseLevel = "Medium"
        ;
            BaseLevel = "Low"
    ),
    
    % Check serious concerns (Data Breaches, Insider Threats)
    (
        (member("Data Breaches", Concerns) ; member("Insider Threats", Concerns)) ->
            (
                BaseLevel = "Low" -> Level1 = "Medium";
                BaseLevel = "Medium" -> Level1 = "High";
                Level1 = BaseLevel
            )
        ;
            Level1 = BaseLevel
    ),
    
    % Check previous incidents
    (
        Incidents = true ->
            (
                Level1 = "Low" -> Level2 = "Medium";
                Level1 = "Medium" -> Level2 = "High";
                Level2 = Level1
            )
        ;
            Level2 = Level1
    ),
    
    % Check network complexity
    (
        (Network = "Enterprise Network" ; Network = "Hybrid") ->
            (
                Level2 = "Low" -> Level3 = "Medium";
                Level3 = Level2
            )
        ;
            Level3 = Level2
    ),
    
    % Check sensitive data
    (
        Sensitive = true ->
            (
                Level3 = "Low" -> Threat = "Medium";
                Level3 = "Medium" -> Threat = "High";
                Threat = Level3
            )
        ;
            Threat = Level3
    ).

% Calculate network threat level
calculate_network_threat(Network, Incidents, Threat) :-
    % Base network threat on network type
    (
        (Network = "Enterprise Network" ; Network = "Hybrid") -> 
            BaseLevel = "Medium"
        ;
            BaseLevel = "Low"
    ),
    
    % Adjust for previous incidents
    (
        Incidents = true ->
            Threat = "High"
        ;
            Threat = BaseLevel
    ).

% Calculate device threat level based on organization type
calculate_device_threat(OrgType, Threat) :-
    (
        (OrgType = "Enterprise" ; OrgType = "Government") -> 
            Threat = "Medium"
        ;
            Threat = "Low"
    ).

% Calculate access threat level based on sensitive data
calculate_access_threat(Sensitive, Threat) :-
    (
        Sensitive = true ->
            Threat = "High"
        ;
            Threat = "Medium"
    ).

% ========================== SCAN LOGIC ==========================

% File extension risk assessment
suspicious_file_extension('.exe').
suspicious_file_extension('.bat').
suspicious_file_extension('.js').
suspicious_file_extension('.vbs').
suspicious_file_extension('.scr').
suspicious_file_extension('.dll').
suspicious_file_extension('.com').
suspicious_file_extension('.ps1').  % PowerShell scripts
suspicious_file_extension('.jar').  % Java archives
suspicious_file_extension('.hta').  % HTML applications
suspicious_file_extension('.msi').  % Windows installers
suspicious_file_extension('.reg').  % Registry files

% Known malicious file hashes (MD5)
malicious_hash('d41d8cd98f00b204e9800998ecf8427e').    % Example hash
malicious_hash('e55a57a422b92c5a04da2aa4842e4f35').    % Example hash
malicious_hash('7f141035cef5a74a97f45a4fd50d61c4').    % Example hash
malicious_hash('f5bc7fcc7f5b4679dfb6176f64476078').    % Example hash

% Known malicious domains
malicious_domain('badexample.com').
malicious_domain('malware-host.net').
malicious_domain('phishing-site.org').
malicious_domain('trojan-delivery.com').
malicious_domain('ransomware.io').

% Known malicious devices
malicious_device('device-malware-node').
malicious_device('compromised-server-1').
malicious_device('infected-laptop-23').
malicious_device('suspicious-iot-device').

% URL safety check
url_safe(URL) :-
    sub_string(URL, 0, _, _, "https"),
    \+ sub_string(URL, _, _, _, " "),
    \+ sub_string(URL, _, _, _, ".."),
    \+ sub_string(URL, _, _, _, "data:"),
    \+ sub_string(URL, _, _, _, "javascript:"),
    \+ contains_malicious_domain(URL).

% Check if URL contains a malicious domain
contains_malicious_domain(URL) :-
    malicious_domain(Domain),
    sub_string(URL, _, _, _, Domain).

% Email validation
email_valid(Email) :-
    split_string(Email, "@", "", Parts),
    length(Parts, 2),
    Parts = [Local, Domain],
    Local \= "",
    Domain \= "",
    sub_string(Domain, _, _, _, "."),
    \+ sub_string(Email, _, _, _, ".."),
    \+ sub_string(Local, 0, _, _, "."),
    \+ sub_string(Domain, _, _, 0, "."),
    string_length(Local, LocalLen),
    LocalLen =< 64,
    string_length(Domain, DomainLen),
    DomainLen =< 255.

% IP address classification
private_ip(IP) :-
    sub_string(IP, 0, _, _, "192.168.") ;
    sub_string(IP, 0, _, _, "10.") ;
    sub_string(IP, 0, _, _, "172.16.") ;
    sub_string(IP, 0, _, _, "172.17.") ;
    sub_string(IP, 0, _, _, "172.18.") ;
    sub_string(IP, 0, _, _, "172.19.") ;
    sub_string(IP, 0, _, _, "172.20.") ;
    sub_string(IP, 0, _, _, "172.21.") ;
    sub_string(IP, 0, _, _, "172.22.") ;
    sub_string(IP, 0, _, _, "172.23.") ;
    sub_string(IP, 0, _, _, "172.24.") ;
    sub_string(IP, 0, _, _, "172.25.") ;
    sub_string(IP, 0, _, _, "172.26.") ;
    sub_string(IP, 0, _, _, "172.27.") ;
    sub_string(IP, 0, _, _, "172.28.") ;
    sub_string(IP, 0, _, _, "172.29.") ;
    sub_string(IP, 0, _, _, "172.30.") ;
    sub_string(IP, 0, _, _, "172.31.") ;
    sub_string(IP, 0, _, _, "127.0.0.") ;  % Localhost
    sub_string(IP, 0, _, _, "169.254.").   % Link-local

% Enhanced scan logic
scan(file, Name, suspicious) :- file_name_extension(_, Ext, Name), suspicious_file_extension(Ext), !.
scan(file, _, clean).

scan(email, Email, valid) :- email_valid(Email), !.
scan(email, _, invalid).

scan(ip, IP, private) :- private_ip(IP), !.
scan(ip, _, public).

scan(url, URL, suspicious) :- \+ url_safe(URL), !.
scan(url, _, safe).

scan(password, Pwd, weak) :- 
    string_length(Pwd, L), 
    L < 8, !.
scan(password, Pwd, medium) :- 
    string_length(Pwd, L), 
    L >= 8, L < 12,
    (\+ contains_lowercase(Pwd) ; \+ contains_uppercase(Pwd) ; \+ contains_digit(Pwd)), !.
scan(password, Pwd, medium) :- 
    string_length(Pwd, L), 
    L >= 8, L < 12, 
    contains_lowercase(Pwd),
    contains_uppercase(Pwd),
    contains_digit(Pwd), !.
scan(password, Pwd, strong) :- 
    string_length(Pwd, L), 
    L >= 12, 
    contains_lowercase(Pwd),
    contains_uppercase(Pwd),
    contains_digit(Pwd),
    contains_special(Pwd), !.
scan(password, Pwd, medium) :- 
    string_length(Pwd, L), 
    L >= 12, !.

scan(hash, Hash, suspicious) :- malicious_hash(Hash), !.
scan(hash, Hash, safe) :- atom_length(Hash, L), L < 16, !.
scan(hash, _, unknown).

scan(device, Name, infected) :- malicious_device(Name), !.
scan(device, _, clean).

scan(device_users, _, Result) :-
    setup_call_cleanup(
        open(pipe('net user'), read, Stream),
        read_string(Stream, _, Output),
        close(Stream)
    ),
    split_string(Output, "\n", " ", Lines),
    drop_until_user_lines(Lines, UserLines),
    extract_usernames(UserLines, Users),
    length(Users, Count),
    ( Count > 3 -> Result = suspicious ; Result = safe ).

% Helper predicates for password strength
contains_lowercase(Str) :-
    sub_string(Str, _, 1, _, Char),
    char_code(Char, Code),
    Code >= 97, Code =< 122.

contains_uppercase(Str) :-
    sub_string(Str, _, 1, _, Char),
    char_code(Char, Code),
    Code >= 65, Code =< 90.

contains_digit(Str) :-
    sub_string(Str, _, 1, _, Char),
    char_code(Char, Code),
    Code >= 48, Code =< 57.

contains_special(Str) :-
    sub_string(Str, _, 1, _, Char),
    special_char(Char).

special_char("!").
special_char("@").
special_char("#").
special_char("$").
special_char("%").
special_char("^").
special_char("&").
special_char("*").
special_char("(").
special_char(")").
special_char("-").
special_char("_").
special_char("+").
special_char("=").
special_char("[").
special_char("]").
special_char("{").
special_char("}").
special_char("|").
special_char("\\").
special_char(":").
special_char(";").
special_char("\"").
special_char("'").
special_char("<").
special_char(">").
special_char(",").
special_char(".").
special_char("?").
special_char("/").
special_char("`").
special_char("~").

% Details for scan results
details(file, Name, Detail) :- 
    file_name_extension(_, Ext, Name), 
    (suspicious_file_extension(Ext) -> 
        format(atom(Detail), 'Extension: ~w - Files with this extension may execute code', [Ext])
    ;
        format(atom(Detail), 'Extension: ~w', [Ext])
    ).

details(email, Email, Detail) :- 
    (email_valid(Email) -> 
        Detail = 'Valid email structure, but verify the domain existence' 
    ; 
        Detail = 'Invalid format - does not conform to email standards'
    ).

details(ip, IP, Detail) :- 
    (private_ip(IP) -> 
        Detail = 'Private IP address - for internal network use only' 
    ; 
        Detail = 'Public IP address - visible on the internet'
    ).

details(url, URL, Detail) :- 
    (url_safe(URL) -> 
        Detail = 'Secure URL (https) with no suspicious patterns' 
    ; 
        (
            sub_string(URL, 0, 5, _, "https") -> Part1 = "Not secure: missing HTTPS"
            ; Part1 = "Not secure: using HTTP instead of HTTPS"
        ),
        (
            sub_string(URL, _, _, _, " ") -> Part2 = ", contains spaces"
            ; Part2 = ""
        ),
        (
            sub_string(URL, _, _, _, "..") -> Part3 = ", contains directory traversal pattern"
            ; Part3 = ""
        ),
        (
            contains_malicious_domain(URL) -> Part4 = ", contains known malicious domain"
            ; Part4 = ""
        ),
        (
            sub_string(URL, _, _, _, "javascript:") -> Part5 = ", contains JavaScript protocol"
            ; Part5 = ""
        ),
        (
            sub_string(URL, _, _, _, "data:") -> Part6 = ", contains data URI scheme"
            ; Part6 = ""
        ),
        string_concat(string_concat(string_concat(string_concat(string_concat(Part1, Part2), Part3), Part4), Part5), Part6, Detail)
    ).

details(hash, Hash, Detail) :-
    ( malicious_hash(Hash) -> Detail = 'Known malicious hash - associated with malware'
    ; atom_length(Hash, L), L < 32 -> Detail = 'Hash length insufficient - might be truncated or weak hash algorithm'
    ; atom_length(Hash, L), L =:= 32 -> Detail = 'MD5 hash (128 bits) - considered cryptographically weak'
    ; atom_length(Hash, L), L =:= 40 -> Detail = 'SHA1 hash (160 bits) - vulnerable to collision attacks'
    ; atom_length(Hash, L), L =:= 64 -> Detail = 'SHA256 hash (256 bits) - currently secure'
    ; atom_length(Hash, L), L =:= 128 -> Detail = 'SHA512 hash (512 bits) - very secure'
    ; Detail = 'Unknown hash format or length' ).

details(password, Pwd, Detail) :-
    string_length(Pwd, L),
    contains_lowercase(Pwd, LC),
    contains_uppercase(Pwd, UC),
    contains_digit(Pwd, D),
    contains_special(Pwd, S),
    
    (L < 8 -> Strength = "Very weak: " ; L < 12 -> Strength = "Medium: " ; Strength = "Strong: "),
    
    atomic_list_concat([
        Strength,
        "Length: ", L, " chars",
        LC, UC, D, S
    ], ' ', Detail).

% Helper for password details
contains_lowercase(Str, Result) :-
    (contains_lowercase(Str) -> Result = "✓ lowercase" ; Result = "✗ no lowercase").
contains_uppercase(Str, Result) :-
    (contains_uppercase(Str) -> Result = "✓ uppercase" ; Result = "✗ no uppercase").
contains_digit(Str, Result) :-
    (contains_digit(Str) -> Result = "✓ digits" ; Result = "✗ no digits").
contains_special(Str, Result) :-
    (contains_special(Str) -> Result = "✓ special chars" ; Result = "✗ no special chars").

details(device, Name, Detail) :- 
    (malicious_device(Name) -> 
        Detail = 'Known infected device - isolated immediately' 
    ; 
        Detail = 'Device not flagged in malicious device database'
    ).

details(device_users, _, Detail) :-
    setup_call_cleanup(
        open(pipe('net user'), read, Stream),
        read_string(Stream, _, Output),
        close(Stream)
    ),
    split_string(Output, "\n", " ", Lines),
    drop_until_user_lines(Lines, UserLines),
    extract_usernames(UserLines, Users),
    atomic_list_concat(Users, ", ", UserList),
    length(Users, Count),
    (Count > 3 ->
        format(atom(Detail), 'Suspicious number of user accounts (~w): ~w', [Count, UserList])
    ;
        format(atom(Detail), 'Normal number of user accounts (~w): ~w', [Count, UserList])
    ).

% Helper functions for device_users scan
drop_until_user_lines([Line|Rest], Output) :-
    ( sub_string(Line, _, _, _, "---") -> Output = Rest ; drop_until_user_lines(Rest, Output) ).

extract_usernames([], []).
extract_usernames([Line|Rest], AllUsers) :-
    ( sub_string(Line, _, _, _, "command completed") -> AllUsers = []
    ; split_string(Line, " ", " ", Parts),
      exclude(=(""), Parts, Cleaned),
      extract_usernames(Rest, Others),
      append(Cleaned, Others, AllUsers)
    ).