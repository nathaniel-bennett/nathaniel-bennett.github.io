---
layout: framework
title: SQLFortify
banner: "/assets/images/banners/code-blurred-banner-short2.jpeg"
---

## Motivation

SQL injection (SQLI) is a rather simple and well-recognized issue in computer security.
The first instances of such an attack were demonstrated more than [20 years ago](http://phrack.org/issues/54/8.html), and the issue was first recognized as a top 10 web vulnerability by OWASP in 2007.
It was the number 1 vulnerability in 2013, and has remained in the top 3 since. <!--Source here-->

SQLI is fundamentally a software development issue.
Database administrators can have best practices in place for securing their infrastructure, but in the end all it takes is one web application with poorly coded SQL statements to expose the entire database to an attack.
To make matters worse, the most effective preventative measures for SQL injection often involve source code analysis, so there are few avenues for auditing and securing proprietary web applications against such attacks.

Web Application Firewalls (WAFs) are often used to detect and proactively block parameters that appear to contain SQLI from reaching vulnerable web applications.
However, this approach is limited in effectiveness by the types of fields the WAF can inspect and by the detection algorithm for the fields themselves.
Since the introduction of WAFs, numerous methods have been developed to bypass their detection while still achieving SQLI.

SQLFortify takes a different approach to ensuring SQL security.
Traditional WAFs and intrusion prevention systems focus on traffic entering an insecure web application--where SQL parameters could take one of countless forms and there is no context for whether a parameter should be allowed to use certain characters or not.
SQLFortify, on the other hand, analyzes the SQL queries being sent from the web application to the database. By observing the full queries produced by the web application (rather than a potentially restricted subset of parameters being received by it), SQLFortify is able to make stronger inferrences on the kinds of patterns that would constitute a SQL injection attack in progress. From there, SQLFortify can proactively block injections and return error messages back to the web application.

## Modes of Operation

SQLFortify can be configured in one of two ways:

1. As a standalone daemon that proxies thaffic between web applications and the database, or
2. As a database plugin (NOTE: WORK IN PROGRESS) that analyzes inputs received by that database.

Many of the detection rules defined by SQLFortify can be modified by means of a configuration file.
For instance, a query that triggers intrusion prevention but that is actually benign (i.e. a false positive) may be added to the configuration file as a whitelisted query.
Subsequent queries of that form will then be accepted regardless of what rules are applied.

In the case that SQLFortify is configured as a daemon, the configuration file additionally specifies the particular SQL database being proxied, as well as encryption options if encryption between the web application and SQLFortify is desired.

## How SQLI is Detected and Blocked


For a more visual example of how SQLFortify can block suspicious queries, watch the following:

<video autoplay="autoplay" loop="loop">
    <source src="/assets/videos/sqlfortify-simple-example.webm" type="video/webm">
</video>

