# breakthelogin

This repository contains a Django web application used to demonstrate common web security vulnerabilities and how they can be fixed.

## Branches

### v1-vulnerable

This branch contains the initial version of the application, which is intentionally insecure.

It includes several vulnerabilities such as:

* weak password policies
* lack of rate limiting (brute-force attacks possible)
* user enumeration through different error messages
* insecure session handling
* flawed password reset logic (predictable tokens, no expiration, reusable)
* insecure password storage
* IDOR (users can access resources by changing IDs)

This version is used to demonstrate how these issues can be exploited.

---

### v2-secure

This branch contains the improved version of the application, where the vulnerabilities from v1 have been addressed.

Main improvements include:

* proper password validation
* rate limiting and temporary account locking
* generic error messages
* improved session security (cookie settings, session expiration, regeneration on login, invalidation on logout)
* secure password reset (random tokens, expiration, one-time use)
* password hashing with bcrypt
* protection against IDOR through ownership checks and role-based access

This version shows how the same application can be secured with relatively small changes.

---

## Purpose

The goal of this project is to better understand how common web vulnerabilities work and how they can be prevented in practice.

---
