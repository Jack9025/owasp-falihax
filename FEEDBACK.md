
[comment]: # (Generated from JSON file by generate_feedback_md.py)
[comment]: # (Intended to be read in GitHub's markdown renderer. Apologies if the plaintext formatting is messy.)

# Jack9025's OWASP Falihax Hackathon Feedback
*Marked by [CyberSoc](https://cybersoc.org.uk/?r=falihax-marking-jack9025)*

This is Jack9025's specific feedback. See below for the full vunerability list, including ones you may have missed.

[General hackathon feedback with full vulnerability list and solutions](https://github.com/CyberSoc-Newcastle/owasp-falihax/blob/main/VULNS.md)
## Summary
**Total mark:** 69

A really *outstanding* entry. You really took your time and added almost everything imaginable to this once terrible web app - you should be proud of the secure website you've created! Great work!!

## Marking Scheme Used
We used the following marking scheme to award marks for each vulnerability, where the mark awarded for the vulnerability is the highest row in the following table fulfilled by your solution. A tick means you had to have done this to get the mark, a cross means this mark does not apply if you did this, and a dash means this is ignored for this possible mark. This mark scheme was decided after the entries had been submitted and was not known to entrants during the competition, although hints were provided as to what to include for good marks.

For each vulnerability, this is how many marks we would award:
| State a valid vulnerability | Show where it is in code | Demo it | Describe how it could be mitigated | Attempt a reasonable fix | Fix works | Explain your fix | Marks |
|-----------------------------|--------------------------|---------|------------------------------------|--------------------------|-----------|------------------|-------|
| ✔                           | ❌                        | ❌       | ❌                                  | ❌                        | -         | -                | 1     |
| ✔                           | ✔                        | ❌       | ❌                                  | ❌                        | -         | -                | 2     |
| ✔                           | -                        | ✔       | ❌                                  | ❌                        | -         | -                | 3     |
| ✔                           | -                        | -       | ✔                                  | ❌                        | -         | -                | 4     |
| ✔                           | -                        | -       | -                                  | ✔                        | ❌         | -                | 4     |
| -                           | -                        | ❌       | -                                  | ✔                        | ✔         | ❌                | 5     |
| -                           | -                        | ✔       | -                                  | ✔                        | ✔         | ❌                | 6     |
| -                           | -                        | -       | -                                  | ✔                        | ✔         | ✔                | 7     |

## Vulnerabilites Found
### [A01-01: Unauthorised users are allowed to visit secure pages](https://github.com/CyberSoc-Newcastle/owasp-falihax/blob/main/VULNS.md#a01-01-unauthorised-users-are-allowed-to-visit-secure-pages)
| State | Show | Demo | Mitigate | Attempt fix | Fix works | Explain fix | Mark |
|-------|------|------|----------|-------------|-----------|-------------|------|
| ✔     | ❌    | ❌    | ❌        | ✔           | ✔         | ❌           | 5    |


### [A01-02: No access control/owner check on account page](https://github.com/CyberSoc-Newcastle/owasp-falihax/blob/main/VULNS.md#a01-02-no-access-control/owner-check-on-account-page)
| State | Show | Demo | Mitigate | Attempt fix | Fix works | Explain fix | Mark |
|-------|------|------|----------|-------------|-----------|-------------|------|
| ✔     | ❌    | ❌    | ❌        | ✔           | ✔         | ❌           | 5    |


### [A01-03: No access control on the admin page](https://github.com/CyberSoc-Newcastle/owasp-falihax/blob/main/VULNS.md#a01-03-no-access-control-on-the-admin-page)
| State | Show | Demo | Mitigate | Attempt fix | Fix works | Explain fix | Mark |
|-------|------|------|----------|-------------|-----------|-------------|------|
| ✔     | ❌    | ❌    | ❌        | ✔           | ✔         | ❌           | 5    |


### [A02-01: Unsuitable use of ROT-13 "encryption"](https://github.com/CyberSoc-Newcastle/owasp-falihax/blob/main/VULNS.md#a02-01-unsuitable-use-of-rot-13-encryption)
| State | Show | Demo | Mitigate | Attempt fix | Fix works | Explain fix | Mark |
|-------|------|------|----------|-------------|-----------|-------------|------|
| ✔     | ❌    | ❌    | ❌        | ✔           | ✔         | ❌           | 5    |


### [A03-01: SQL Injection](https://github.com/CyberSoc-Newcastle/owasp-falihax/blob/main/VULNS.md#a03-01-sql-injection)
| State | Show | Demo | Mitigate | Attempt fix | Fix works | Explain fix | Mark |
|-------|------|------|----------|-------------|-----------|-------------|------|
| ✔     | ❌    | ❌    | ❌        | ✔           | ✔         | ❌           | 5    |


### [A04-01: No CAPTCHAs Used](https://github.com/CyberSoc-Newcastle/owasp-falihax/blob/main/VULNS.md#a04-01-no-captchas-used)
| State | Show | Demo | Mitigate | Attempt fix | Fix works | Explain fix | Mark |
|-------|------|------|----------|-------------|-----------|-------------|------|
| ✔     | ❌    | ❌    | ❌        | ✔           | ✔         | ❌           | 5    |


### [A04-02: No Password Strength Checks](https://github.com/CyberSoc-Newcastle/owasp-falihax/blob/main/VULNS.md#a04-02-no-password-strength-checks)
| State | Show | Demo | Mitigate | Attempt fix | Fix works | Explain fix | Mark |
|-------|------|------|----------|-------------|-----------|-------------|------|
| ✔     | ❌    | ❌    | ❌        | ✔           | ✔         | ❌           | 5    |


### [A04-03: No Rate Limiting](https://github.com/CyberSoc-Newcastle/owasp-falihax/blob/main/VULNS.md#a04-03-no-rate-limiting)
| State | Show | Demo | Mitigate | Attempt fix | Fix works | Explain fix | Mark |
|-------|------|------|----------|-------------|-----------|-------------|------|
| ✔     | ❌    | ❌    | ❌        | ✔           | ✔         | ❌           | 5    |


### [A05-01: Flask secret key used is not secure](https://github.com/CyberSoc-Newcastle/owasp-falihax/blob/main/VULNS.md#a05-01-flask-secret-key-used-is-not-secure)
| State | Show | Demo | Mitigate | Attempt fix | Fix works | Explain fix | Mark |
|-------|------|------|----------|-------------|-----------|-------------|------|
| ✔     | ❌    | ❌    | ❌        | ✔           | ✔         | ❌           | 5    |


### [A08-01: Missing Validation for Lower Bound of Transaction Amount](https://github.com/CyberSoc-Newcastle/owasp-falihax/blob/main/VULNS.md#a08-01-missing-validation-for-lower-bound-of-transaction-amount)
| State | Show | Demo | Mitigate | Attempt fix | Fix works | Explain fix | Mark |
|-------|------|------|----------|-------------|-----------|-------------|------|
| ✔     | ❌    | ❌    | ❌        | ✔           | ✔         | ❌           | 5    |


### [B01-02: Secrets shouldn't be stored in code](https://github.com/CyberSoc-Newcastle/owasp-falihax/blob/main/VULNS.md#b01-02-secrets-shouldn't-be-stored-in-code)
| State | Show | Demo | Mitigate | Attempt fix | Fix works | Explain fix | Mark |
|-------|------|------|----------|-------------|-----------|-------------|------|
| ✔     | ❌    | ❌    | ❌        | ✔           | ✔         | ❌           | 5    |


### [B01-03: Cross-site request forgery (CSRF)](https://github.com/CyberSoc-Newcastle/owasp-falihax/blob/main/VULNS.md#b01-03-cross-site-request-forgery-csrf)
| State | Show | Demo | Mitigate | Attempt fix | Fix works | Explain fix | Mark |
|-------|------|------|----------|-------------|-----------|-------------|------|
| ✔     | ❌    | ❌    | ❌        | ✔           | ✔         | ❌           | 5    |


### [B02-01: Bad or No Input Validation (General Cases)](https://github.com/CyberSoc-Newcastle/owasp-falihax/blob/main/VULNS.md#b02-01-bad-or-no-input-validation-general-cases)
*Maximum mark of 1 for this category*
| State | Show | Demo | Mitigate | Attempt fix | Fix works | Explain fix | Mark |
|-------|------|------|----------|-------------|-----------|-------------|------|
| ✔     | ❌    | ❌    | ❌        | ✔           | ✔         | ❌           | 1    |


### [B02-02: Admin permissions are assigned based on a fixed username instead of role](https://github.com/CyberSoc-Newcastle/owasp-falihax/blob/main/VULNS.md#b02-02-admin-permissions-are-assigned-based-on-a-fixed-username-instead-of-role)
*Maximum mark of 1 for this category*
| State | Show | Demo | Mitigate | Attempt fix | Fix works | Explain fix | Mark |
|-------|------|------|----------|-------------|-----------|-------------|------|
| ✔     | ❌    | ❌    | ❌        | ✔           | ✔         | ❌           | 1    |

## Bonus marks
Bonus marks were awarded for great non-security critical things that really stood out to us, specific to your project. Each entry below gets you one bonus mark.

### Very well formatted readme
Readme file is very well formatted using markdown. It is a pleasure to read, especially with the nested bullet lists and good header hierarchy!

*+1 bonus mark awarded.*

### Create admin script
While not security critical, the script for creating an admin account is a nice touch! It helps prevent an attacker gaining access via some web control panel, as command line access to the server is required to promote a user to admin. 

*+1 bonus mark awarded.*

### Great git commits
You commit often and atomically, which is really great to see. Commit messages are concise yet descriptive, and give a good overview of the development process!

*+1 bonus mark awarded.*

### Same-account transfers
Security-wise, the only issue with allowing an account to transfer money to itself is that this could be used to fill the database disk and cause a denial of service. Theoretically. However, preventing someone accidentally transferring money to the same account is a nice touch!

*+1 bonus mark awarded.*

### Confirm/retype password on signup
Not required for security reasons, but a great addition for user experience.

*+1 bonus mark awarded.*

### Use of ORM (SQLAlchemy)
The code was purposely written without using an ORM just to see if anyone would take the relatively large amount of effort of implementing one. Unfortunately it doesn't get you a ton of points as it doesn't directly improve security, but it makes the entire project feel a lot more clean and polished! Nice work!

*+1 bonus mark awarded.*

### Added PostgreSQL support
PostgreSQL could potentially make the system *slightly* more secure with features like data encryption at rest available, however this bonus mark is just for adding it as an option!

*+1 bonus mark awarded.*

## Total mark
5 + 5 + 5 + 5 + 5 + 5 + 5 + 5 + 5 + 5 + 5 + 5 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 = 69

**Your total mark is 69**