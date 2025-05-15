
:- module(routes, [register_routes/0]).

/**
 * Routes Module - HTTP Route Handlers
 * 
 * This module defines all the HTTP routes and handlers for the API endpoints.
 */

% Load required libraries
:- use_module(library(http/http_dispatch)).
:- use_module(library(http/http_parameters)).
:- use_module(library(http/http_json)).
:- use_module(library(http/http_files)).
:- use_module(library(http/http_cors)).

% Import other application modules - use full file paths with extensions
:- use_module('chat_dss.pl').
:- use_module('threat_assessment.pl').
:- use_module('scanners.pl').
:- use_module('utils.pl').

/**
 * Register all HTTP routes
 */
register_routes :-
    % Set up CORS for all handlers
    http_handler(root(.), 
        http_cors_enable([methods([get,post,put,delete,options]),
                         allow_headers(['Authorization', 'Content-Type']),
                         allow_origin([*])], serve_frontend), 
        [prefix]),

    http_handler(root(scan), 
        http_cors_enable([methods([get,post]), allow_origin([*])], handle_scan), 
        []),

    http_handler(root(export_csv), 
        http_cors_enable([methods([get]), allow_origin([*])], export_csv), 
        []),

    http_handler(root(chat), 
        http_cors_enable([methods([post]), allow_origin([*])], handle_chat), 
        []),

    http_handler(root(profile), 
        http_cors_enable([methods([post,get]), allow_origin([*])], handle_profile), 
        []),

    http_handler(root(threat_assessment), 
        http_cors_enable([methods([get]), allow_origin([*])], get_threat_assessment), 
        []),

    http_handler(root(save_scan), 
        http_cors_enable([methods([post]), allow_origin([*])], save_scan_result), 
        []).

/**
 * Serve static frontend files
 */
serve_frontend(Request) :-
    http_reply_from_files('frontend', [index('index.html')], Request).

/**
 * Handle scan requests
 */
handle_scan(Request) :-
    http_parameters(Request, [ 
        type(Type, []), 
        value(Value, [])
    ]),
    
    % Get userId from query parameters or default to 'anonymous'
    (http_parameters(Request, [userId(UserId, [])], [form_data(no)]) -> true ; UserId = 'anonymous'),
    
    % Perform the scan
    scanners:scan(Type, Value, Result),
    scanners:details(Type, Value, Detail),
    
    % Log the scan if userId is provided
    assertz(scan_log(UserId, Type, Value, Result)),
    
    % Return JSON response
    reply_json(json([result=Result, details=Detail])).

/**
 * Save a scan result
 */
save_scan_result(Request) :-
    http_read_json_dict(Request, Data),
    get_dict(userId, Data, UserId),
    get_dict(type, Data, Type),
    get_dict(value, Data, Value),
    get_dict(result, Data, Result),
    
    % Save to scan log
    assertz(scan_log(UserId, Type, Value, Result)),
    
    % Return success response
    reply_json(json([status="Scan saved"])).

/**
 * Handle chat requests
 */
handle_chat(Request) :-
    http_read_json_dict(Request, Data),
    get_dict(message, Data, Message),
    get_dict(userId, Data, UserId),
    
    % Get current time
    get_time(Timestamp),
    
    % Get chat state or use default 0
    (get_dict(chatState, Data, ChatState) -> true ; ChatState = 0),
    
    % Record message in chat history
    assertz(chat_history(UserId, Timestamp, Message)),
    
    % Check if this is the first message
    (get_dict(isFirstMessage, Data, true) -> 
        retractall(chat_state(UserId, _)),  % Clear any existing chat state
        assertz(chat_state(UserId, 0)),     % Set initial state
        chat_dss:get_welcome_message(Response, Options)
    ;
        % Process user message and get next response
        chat_dss:process_chat_message(UserId, Message, ChatState, Response, Options, NextState, ShowDashboard, ProfileUpdate)
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

/**
 * Handle profile updates and retrievals
 */
handle_profile(Request) :-
    (http_method(Request, post) ->
        % POST request - Update profile
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
        % GET request - Get profile
        http_parameters(Request, [userId(UserId, [])], [form_data(no)]),
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

/**
 * Get threat assessment based on profile
 */
get_threat_assessment(Request) :-
    http_parameters(Request, [userId(UserId, [])], [form_data(no)]),
    (user_profile(UserId, OrgType, Concerns, Incidents, Network, Sensitive) ->
        threat_assessment:calculate_threat_level(OrgType, Concerns, Incidents, Network, Sensitive, OverallThreat),
        threat_assessment:calculate_network_threat(Network, Incidents, NetworkThreat),
        threat_assessment:calculate_device_threat(OrgType, DeviceThreat),
        threat_assessment:calculate_access_threat(Sensitive, AccessThreat),
        
        reply_json(json([
            overall=OverallThreat,
            network=NetworkThreat,
            device=DeviceThreat,
            access=AccessThreat
        ]))
    ;
        reply_json(json([error="Profile not found"]))
    ).

/**
 * Export scan logs as CSV
 */
export_csv(Request) :-
    % Get userId from query parameters or default to all users
    (http_parameters(Request, [userId(RequestUserId, [])], [form_data(no)]) -> 
        ExportPredicate =.. [scan_log, RequestUserId, Type, Value, Result]
    ; 
        ExportPredicate =.. [scan_log, _, Type, Value, Result]
    ),
    
    % Set CSV headers
    format('Content-type: text/csv~n'),
    format('Content-Disposition: attachment; filename=\"scan_report.csv\"~n~n'),
    
    % Write CSV header
    format("Type,Value,Result~n"),
    
    % Write CSV data
    forall(
        call(ExportPredicate),
        format("~w,~w,~w~n", [Type, Value, Result])
    ).