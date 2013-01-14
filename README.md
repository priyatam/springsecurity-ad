# Spring Security Active Directory Integration

## Goals 
Authenticate a Spring web application deployed on Windows NTLM network using ActiveDirectory, manage Roles in web application (custom authorization), 
and simulate a single-sign-on environment. When a (windows) authenticated user accesses the app's url, he would be redirected to the home page. 

## Overview
* Get Kerberos + NTLM using [Waffle](http://waffle.codeplex.com/) Filter and Spring Security
* Integrates well with Spring Security
* IIS Server is not required as a pass through authentication mechanism for Active Directory
* Reference [guide](http://code.dblock.org/single-sign-on-spring-security-negotiate-filter-kerberos-ntlm-wwaffle)
* Switch between "ldap-local-security" (dev) and "waffle-security-filter" (prod) strategies 
* A change of strategy will only require a new authentication strategy (few classes) as the spring authorization piece is generic.

## What about Spring Security LDAP?å
* [Spring LDAP Security Reference](http://static.springsource.org/spring-security/site/docs/3.1.x/reference/springsecurity-single.html#ldap)
* Spring uses ActiveDirectoryLdapAuthenticationProvider, which delegates the work to LdapAuthenticator and LdapAuthoritiesPopulator for authenticating
  user and retrieving GrantedAuthoritys. UserDetails can be populated using DefaultLdapAuthoritiesPopulator.
* With the correct users.ldif (sample ldap user info) app works for authentication/authorization. However single-sign on in 
  prod env needs additional filters and customization.

## What about Spring Security Kerberos/SPNEGO Extension?
* Spring's reference [example](http://blog.springsource.com/2009/09/28/spring-security-kerberos/) extension needs server side 
  configuration (setup kerberos etc.,) -- not be "out of the box"

