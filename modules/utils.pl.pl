:- module(utils, [
    http_method/2,
    string_concat/3,
    exclude/3,
    drop_until_user_lines/2,
    extract_usernames/2
]).

/**
 * Utils Module
 * 
 * This module provides utility functions used across the application.
 */

% Load required libraries
:- use_module(library(http/http_client)).

/**
 * Get HTTP method from request
 * @param Request - HTTP request
 * @param Method - HTTP method (get, post, etc.)
 */
http_method(Request, Method) :-
    memberchk(method(Method), Request).

/**
 * Concatenate multiple strings
 * @param StringList - List of strings to concatenate
 * @param Result - Resulting concatenated string
 */
string_concat([], "").
string_concat([H|T], Result) :-
    string_concat(T, TempResult),
    string_concat(H, TempResult, Result).

/**
 * Exclude elements from a list based on a predicate
 * @param Pred - Predicate to test
 * @param List - Input list
 * @param Result - Filtered list
 */
exclude(_, [], []).
exclude(Pred, [H|T], Result) :-
    call(Pred, H), !,
    exclude(Pred, T, Result).
exclude(Pred, [H|T], [H|Result]) :-
    exclude(Pred, T, Result).

/**
 * Drop lines until finding user lines section
 * @param Lines - Input lines
 * @param Output - Lines after the marker
 */
drop_until_user_lines([], []).
drop_until_user_lines([Line|Rest], Output) :-
    (sub_string(Line, _, _, _, "---") -> Output = Rest ; drop_until_user_lines(Rest, Output)).

/**
 * Extract usernames from user lines
 * @param Lines - Input lines
 * @param AllUsers - Extracted usernames
 */
extract_usernames([], []).
extract_usernames([Line|Rest], AllUsers) :-
    (sub_string(Line, _, _, _, "command completed") -> AllUsers = [] ;
        split_string(Line, " ", " ", Parts),
        exclude(=(""), Parts, Cleaned),
        extract_usernames(Rest, Others),
        append(Cleaned, Others, AllUsers)
    ).