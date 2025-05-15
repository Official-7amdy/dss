:- module(server, [start_server/0]).

/**
 * Cyber Threat Intelligence Dashboard - Main Server Module
 * 
 * This is the main entry point for the Cyber Threat Intelligence Dashboard backend.
 * It loads all required modules and starts the HTTP server.
 */

% Load required libraries
:- use_module(library(http/thread_httpd)).
:- use_module(library(http/http_dispatch)).

% Load application modules - use full file paths with extensions
:- use_module('modules/routes.pl').
:- use_module('modules/chat_dss.pl').
:- use_module('modules/threat_assessment.pl').
:- use_module('modules/scanners.pl').
:- use_module('modules/utils.pl').

% Dynamic predicates for storing data
:- dynamic scan_log/4.         % userId, type, value, result
:- dynamic user_profile/6.     % userId, orgType, concerns, incidents, network, sensitive
:- dynamic chat_history/3.     % userId, timestamp, message
:- dynamic chat_state/2.       % userId, stateNumber
:- dynamic session_data/2.     % userId, jsonData

% Initialize server on startup
:- initialization(start_server).

/**
 * Start the HTTP server
 */
start_server :- 
    % Ensure modules are initialized
    routes:register_routes,
    
    % Start the server
    http_server(http_dispatch, [port(8080)]),
    
    % Log startup message
    format('Cyber Threat Intelligence Server started on port 8080~n'),
    format('Access the dashboard at http://localhost:8080~n').