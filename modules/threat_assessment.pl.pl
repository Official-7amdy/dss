:- module(threat_assessment, [
    calculate_threat_level/6,
    calculate_network_threat/3,
    calculate_device_threat/2,
    calculate_access_threat/2
]).

/**
 * Threat Assessment Module
 * 
 * This module handles the threat assessment calculations based on user profile.
 */

/**
 * Calculate overall threat level
 * @param OrgType - Organization type
 * @param Concerns - Security concerns
 * @param Incidents - Previous incidents flag
 * @param Network - Network type
 * @param Sensitive - Sensitive data flag
 * @param Threat - Calculated threat level (output)
 */
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

/**
 * Calculate network threat level
 * @param Network - Network type
 * @param Incidents - Previous incidents flag
 * @param Threat - Calculated network threat level (output)
 */
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

/**
 * Calculate device threat level based on organization type
 * @param OrgType - Organization type
 * @param Threat - Calculated device threat level (output)
 */
calculate_device_threat(OrgType, Threat) :-
    (
        (OrgType = "Enterprise" ; OrgType = "Government") -> 
            Threat = "Medium"
        ;
            Threat = "Low"
    ).

/**
 * Calculate access threat level based on sensitive data
 * @param Sensitive - Sensitive data flag
 * @param Threat - Calculated access threat level (output)
 */
calculate_access_threat(Sensitive, Threat) :-
    (
        Sensitive = true ->
            Threat = "High"
        ;
            Threat = "Medium"
    ).