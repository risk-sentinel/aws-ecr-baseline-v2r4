# SRG V2R4 — Batch 3/4 disposition plan (for review)

Disposition of the 179 not-yet-implemented controls, grouped by theme. Registry rules (Batch 1/2) are already `implemented`. Each `inherited` control will assert AWS-authorization evidence via `document_attestation` (the leveraged class + inputs.yml URI); each `not-applicable` gets impact 0.0 + rationale; each `alternative` gets a SAF attestation.

**Totals:** inherited 168 · not-applicable 5 · alternative 6

## AUTH/IDENTITY — `inherited` (54)
Platform principal auth = AWS IAM/STS (AWS-managed, FedRAMP-authorized); consumer IAM hygiene cross-ref cis-aws-foundations

- SV-233019 [APP-000023] The container platform must use a centralized user management solution to support account 
- SV-233020 [APP-000024] The container platform must automatically remove or disable temporary user accounts after 
- SV-233021 [APP-000025] The container platform must automatically disable accounts after a 35-day period of accoun
- SV-233031 [APP-000065] The container platform must enforce the limit of three consecutive invalid logon attempts 
- SV-233070 [APP-000133] Authentication files for the container platform must be protected.
- SV-233075 [APP-000148] The container platform must uniquely identify and authenticate users.
- SV-233076 [APP-000148] The container platform application program interface (API) must uniquely identify and auth
- SV-233077 [APP-000148] The container platform must uniquely identify and authenticate processes acting on behalf 
- SV-233078 [APP-000148] The container platform application program interface (API) must uniquely identify and auth
- SV-233079 [APP-000149] The container platform must use multifactor authentication for network access to privilege
- SV-233080 [APP-000150] The container platform must use multifactor authentication for network access to non-privi
- SV-233081 [APP-000151] The container platform must use multifactor authentication for local access to privileged 
- SV-233082 [APP-000152] The container platform must use multifactor authentication for local access to nonprivileg
- SV-233083 [APP-000153] The container platform must ensure users are authenticated with an individual authenticato
- SV-233085 [APP-000157] The container platform must implement replay-resistant authentication mechanisms for netwo
- SV-233086 [APP-000158] The container platform must uniquely identify all network-connected nodes before establish
- SV-233087 [APP-000163] The container platform must disable identifiers (individuals, groups, roles, and devices) 
- SV-233088 [APP-000164] The container platform must enforce a minimum 15-character password length.
- SV-233090 [APP-000166] The container platform must enforce password complexity by requiring that at least one upp
- SV-233091 [APP-000167] The container platform must enforce password complexity by requiring that at least one low
- SV-233092 [APP-000168] The container platform must enforce password complexity by requiring that at least one num
- SV-233093 [APP-000169] The container platform must enforce password complexity by requiring that at least one spe
- SV-233094 [APP-000170] The container platform must require the change of at least eight of the total number of ch
- SV-233097 [APP-000173] The container platform must enforce 24 hours (one day) as the minimum password lifetime.
- SV-233098 [APP-000174] The container platform must enforce a 60-day maximum password lifetime restriction.
- SV-233101 [APP-000177] The container platform must map the authenticated identity to the individual user or group
- SV-233102 [APP-000178] The container platform must obscure feedback of authentication information during the auth
- SV-233106 [APP-000185] The container platform must employ strong authenticators in the establishment of non-local
- SV-233114 [APP-000211] The container platform must separate user functionality (including user interface services
- SV-233126 [APP-000234] The container platform must never automatically remove or disable emergency accounts.
- SV-233143 [APP-000291] The container platform must notify system administrators (SAs) and the information system 
- SV-233144 [APP-000292] The container platform must notify system administrators (SAs) and the information system 
- SV-233145 [APP-000293] The container platform must notify system administrators and ISSO for account disabling ac
- SV-233146 [APP-000294] The container platform must notify system administrators and ISSO for account removal acti
- SV-233155 [APP-000317] The container platform must terminate shared/group account credentials when members leave 
- SV-233158 [APP-000320] The container platform must notify the system administrator (SA) and information system se
- SV-233162 [APP-000340] The container platform must prevent non-privileged users from executing privileged functio
- SV-233165 [APP-000345] The container platform must automatically lock an account until the locked account is rele
- SV-233193 [APP-000389] The container platform must require users to reauthenticate when organization-defined circ
- SV-233195 [APP-000391] The container platform must be configured to use multi-factor authentication for user auth
- SV-233200 [APP-000400] The container platform must prohibit the use of cached authenticators after an organizatio
- SV-233201 [APP-000401] The container platform, for PKI-based authentication, must implement a local cache of revo
- SV-233202 [APP-000402] The container platform must accept Personal Identity Verification (PIV) credentials from o
- SV-257291 [APP-000318] The container platform must enforce organization-defined circumstances and/or usage condit
- SV-263586 [APP-000705] The container platform must disable accounts when the accounts are no longer associated to
- SV-263589 [APP-000820] The container platform must implement multifactor authentication for local; network; and/o
- SV-263590 [APP-000825] The container platform must implement multifactor authentication for local; network; and/o
- SV-263591 [APP-000830] The container platform must for password-based authentication, maintain a list of commonly
- SV-263592 [APP-000835] The container platform must for password-based authentication, update the list of password
- SV-263593 [APP-000840] The container platform must for password-based authentication, update the list of password
- SV-263594 [APP-000845] The container platform must for password-based authentication, verify when users create or
- SV-263595 [APP-000855] The container platform must for password-based authentication, require immediate selection
- SV-263596 [APP-000860] The container platform must for password-based authentication, allow user selection of lon
- SV-263597 [APP-000865] The container platform must for password-based authentication, employ automated tools to a

## AUDIT — `inherited` (58)
Container-platform/control-plane audit = AWS CloudTrail + AWS-managed audit infra; CloudTrail enablement cross-ref cis-aws-foundations

- SV-233022 [APP-000026] The container platform must automatically audit account creation.
- SV-233023 [APP-000027] The container platform must automatically audit account modification.
- SV-233024 [APP-000028] The container platform must automatically audit account-disabling actions.
- SV-233025 [APP-000029] The container platform must automatically audit account removal actions.
- SV-233038 [APP-000089] The container platform must generate audit records for all DoD-defined auditable events wi
- SV-233040 [APP-000091] The container platform must generate audit records when successful/unsuccessful attempts t
- SV-233041 [APP-000092] The container platform must initiate session auditing upon startup.
- SV-233042 [APP-000095] All audit records must identify what type of event has occurred within the container platf
- SV-233043 [APP-000096] The container platform audit records must have a date and time association with all events
- SV-233044 [APP-000097] All audit records must identify where in the container platform the event occurred.
- SV-233045 [APP-000098] All audit records must identify the source of the event within the container platform.
- SV-233046 [APP-000099] All audit records must generate the event results within the container platform.
- SV-233047 [APP-000100] All audit records must identify any users associated with the event within the container p
- SV-233048 [APP-000100] All audit records must identify any containers associated with the event within the contai
- SV-233049 [APP-000101] The container platform must generate audit records containing the full-text recording of p
- SV-233052 [APP-000111] The container platform components must provide the ability to send audit logs to a central
- SV-233055 [APP-000116] The container platform must use internal system clocks to generate audit record time stamp
- SV-233056 [APP-000118] The container platform must protect audit information from any type of unauthorized read a
- SV-233057 [APP-000119] The container platform must protect audit information from unauthorized modification.
- SV-233058 [APP-000120] The container platform must protect audit information from unauthorized deletion.
- SV-233059 [APP-000121] The container platform must protect audit tools from unauthorized access.
- SV-233060 [APP-000122] The container platform must protect audit tools from unauthorized modification.
- SV-233061 [APP-000123] The container platform must protect audit tools from unauthorized deletion.
- SV-233105 [APP-000181] The container platform must provide an audit reduction capability that supports on-demand 
- SV-233142 [APP-000290] The container platform must use cryptographic mechanisms to protect the integrity of audit
- SV-233157 [APP-000319] The container platform must automatically audit account-enabling actions.
- SV-233164 [APP-000343] The container platform must audit the execution of privileged functions.
- SV-233166 [APP-000516] The container platform must provide the configuration for organization-identified individu
- SV-233168 [APP-000357] The container platform must allocate audit record storage capacity in accordance with orga
- SV-233169 [APP-000358] Audit records must be stored at a secondary location.
- SV-233170 [APP-000359] The container platform must provide an immediate warning to the SA and ISSO (at a minimum)
- SV-233171 [APP-000360] The container platform must provide an immediate real-time alert to the SA and ISSO, at a 
- SV-233181 [APP-000374] All audit records must use UTC or GMT time stamps.
- SV-233182 [APP-000375] The container platform must record time stamps for audit records that meet a granularity o
- SV-233189 [APP-000381] The container platform must enforce access restrictions and support auditing of the enforc
- SV-233206 [APP-000409] The container platform must audit non-local maintenance and diagnostic sessions' organizat
- SV-233243 [APP-000473] The container platform must perform verification of the correct operation of security func
- SV-233252 [APP-000492] The container platform must generate audit records when successful/unsuccessful attempts t
- SV-233253 [APP-000493] The container platform must generate audit records when successful/unsuccessful attempts t
- SV-233254 [APP-000494] The container platform must generate audit records when successful/unsuccessful attempts t
- SV-233255 [APP-000495] The container platform must generate audit records when successful/unsuccessful attempts t
- SV-233256 [APP-000496] The container platform must generate audit records when successful/unsuccessful attempts t
- SV-233257 [APP-000497] The container platform must generate audit records when successful/unsuccessful attempts t
- SV-233258 [APP-000498] The container platform must generate audit records when successful/unsuccessful attempts t
- SV-233259 [APP-000499] The container platform must generate audit records when successful/unsuccessful attempts t
- SV-233260 [APP-000500] The container platform must generate audit records when successful/unsuccessful attempts t
- SV-233261 [APP-000501] The container platform must generate audit records when successful/unsuccessful attempts t
- SV-233262 [APP-000502] The container platform must generate audit records when successful/unsuccessful attempts t
- SV-233263 [APP-000503] The container platform must generate audit records when successful/unsuccessful logon atte
- SV-233264 [APP-000504] The container platform must generate audit record for privileged activities.
- SV-233265 [APP-000505] The container platform audit records must record user access start and end times.
- SV-233266 [APP-000506] The container platform must generate audit records when concurrent logons from different w
- SV-233267 [APP-000507] The container platform runtime must generate audit records when successful/unsuccessful at
- SV-233268 [APP-000508] Direct access to the container platform must generate audit records.
- SV-233269 [APP-000509] The container platform must generate audit records for all account creations, modification
- SV-233270 [APP-000510] The container runtime must generate audit records for all container execution, shutdown, r
- SV-263587 [APP-000745] The container platform must implement the capability to centrally review and analyze audit
- SV-263588 [APP-000795] The container platform must alert organization-defined personnel or roles upon detection o

## CRYPTO — `inherited` (20)
AWS FIPS 140-2/3 validated modules / KMS / TLS endpoints — AWS-managed + authorized

- SV-233015 [APP-000014] The container platform must use TLS 1.2 or greater for secure container image transport fr
- SV-233016 [APP-000014] The container platform must use TLS 1.2 or greater for secure communication.
- SV-233028 [APP-000033] Least privilege access and need-to-know must be required to access the container platform 
- SV-233063 [APP-000126] The container platform must use FIPS validated cryptographic mechanisms to protect the int
- SV-233068 [APP-000133] The container platform must limit privileges to the container platform keystore.
- SV-233084 [APP-000156] The container platform must use FIPS-validated SHA-1 or higher hash function to provide re
- SV-233095 [APP-000171] For container platform using password authentication, the application must store only cryp
- SV-233096 [APP-000172] For accounts using password authentication, the container platform must use FIPS-validated
- SV-233118 [APP-000219] The container platform must protect authenticity of communications sessions with the use o
- SV-233207 [APP-000411] Container platform applications and Application Program Interfaces (API) used for nonlocal
- SV-233208 [APP-000412] The container platform must configure web management tools and Application Program Interfa
- SV-233211 [APP-000416] The container platform must implement NSA-approved cryptography to protect classified info
- SV-233220 [APP-000429] The container platform keystore must implement encryption to prevent unauthorized disclosu
- SV-233224 [APP-000439] The application must protect the confidentiality and integrity of transmitted information.
- SV-233271 [APP-000514] The container platform must use a valid FIPS 140-2 or FIPS 140-3 approved cryptographic mo
- SV-233276 [APP-000560] The container platform must prohibit communication using TLS versions 1.0 and 1.1, and SSL
- SV-233284 [APP-000605] The container platform must validate certificates used for Transport Layer Security (TLS) 
- SV-233289 [APP-000635] The container platform must use a FIPS-validated cryptographic module to implement encrypt
- SV-233290 [APP-000645] The container platform must prohibit or restrict the use of protocols that transmit unencr
- SV-263600 [APP-000915] The container platform must provide protected storage for cryptographic keys with organiza

## RUNTIME — `inherited` (9)
Fargate microVM runtime/isolation is AWS-managed

- SV-233027 [APP-000033] Least privilege access and need-to-know must be required to access the container platform 
- SV-233067 [APP-000133] The container platform must limit privileges to the container platform runtime.
- SV-233073 [APP-000142] The container platform runtime must enforce ports, protocols, and services that adhere to 
- SV-233074 [APP-000142] The container platform runtime must enforce the use of ports that are non-privileged.
- SV-233122 [APP-000225] The container platform runtime must fail to a secure state if system initialization fails,
- SV-233125 [APP-000233] The container platform runtime must isolate security functions from non-security functions
- SV-233185 [APP-000378] The container platform runtime must prohibit the instantiation of container images without
- SV-233221 [APP-000431] The container platform runtime must maintain separate execution domains for each container
- SV-233234 [APP-000456] The container platform runtime must have security-relevant software updates installed with

## PATCH/MAINT — `inherited` (5)
AWS patches/maintains the managed platform (FedRAMP/DoD ATO)

- SV-233184 [APP-000378] The container platform must prohibit the installation of patches and updates without expli
- SV-233188 [APP-000380] The container platform must enforce access restrictions for container platform configurati
- SV-233230 [APP-000454] The container platform must remove old components after updated versions have been install
- SV-263598 [APP-000880] The container platform must protect nonlocal maintenance sessions by separating the mainte
- SV-278968 [APP-001035] The container platform must be a version supported by the vendor.

## PLATFORM-CONFIG — `inherited` (22)
AWS-managed platform configuration/behavior (essential components, ports/protocols, notifications, predictable behavior)

- SV-233029 [APP-000038] The container platform must enforce approved authorizations for controlling the flow of in
- SV-233030 [APP-000039] The container platform must enforce approved authorizations for controlling the flow of in
- SV-233065 [APP-000131] The container platform must verify container images.
- SV-233069 [APP-000133] Configuration files for the container platform must be protected.
- SV-233071 [APP-000141] The container platform must be configured with only essential configurations.
- SV-233108 [APP-000190] The application must terminate all network connections associated with a communications se
- SV-233123 [APP-000226] The container platform must preserve any information necessary to determine the cause of t
- SV-233127 [APP-000243] The container platform must prohibit containers from accessing privileged resources.
- SV-233128 [APP-000243] The container platform must prevent unauthorized and unintended information transfer via s
- SV-233133 [APP-000266] The container platform must generate error messages that provide information necessary for
- SV-233190 [APP-000383] All non-essential, unnecessary, and unsecure DoD ports, protocols, and services must be di
- SV-233191 [APP-000384] The container platform must prevent component execution in accordance with organization-de
- SV-233222 [APP-000435] The container platform must protect against or limit the effects of all types of denial-of
- SV-233226 [APP-000441] The container platform must maintain the confidentiality and integrity of information duri
- SV-233227 [APP-000442] The container platform must maintain the confidentiality and integrity of information duri
- SV-233228 [APP-000447] The container platform must behave in a predictable and documented manner that reflects or
- SV-233229 [APP-000450] The container platform must implement organization-defined security safeguards to protect 
- SV-233244 [APP-000474] The container platform must provide system notifications to the system administrator and o
- SV-233273 [APP-000516] Container platform components must be configured in accordance with the security configura
- SV-233274 [APP-000516] The container platform must be able to store and instantiate industry standard container i
- SV-263601 [APP-000920] The container platform must synchronize system clocks within and between systems or system
- SV-270876 [APP-000380] The container root filesystem must be mounted as read-only.

## BANNER — `N/A` (3)
No platform-provided interactive user session/console UI; AWS Console banner is AWS-governed

- SV-233032 [APP-000068] The container platform must display the Standard Mandatory DoD Notice and Consent Banner b
- SV-233033 [APP-000069] The container platform must retain the Standard Mandatory DoD Notice and Consent Banner on
- SV-233149 [APP-000297] Access to the container platform must display an explicit logout message to user indicatin

## TASK-DEF — `N/A` (2)
Task-definition control — covered by aws-ecs-fargate-baseline

- SV-233163 [APP-000342] Container images instantiated by the container platform must execute using least privilege
- SV-270875 [APP-000247] The container must have resource request limits set.

## BUILD/SIGN — `alternative` (3)
Image build/signing provenance = consumer CI pipeline, API-opaque from ECR -> SAF attestation

- SV-233064 [APP-000131] The container platform must be built from verified packages.
- SV-233285 [APP-000610] The container platform must use FIPS-validated SHA-2 or higher hash function for digital s
- SV-263599 [APP-000910] The container platform must include only approved trust anchors in trust stores or certifi

## GOVERNANCE — `alternative` (3)
Organizational/governance fact -> SAF attestation

- SV-233039 [APP-000090] The container platform must allow only the ISSM (or individuals or roles appointed by the 
- SV-233129 [APP-000246] The container platform must restrict individuals' ability to launch organizationally defin
- SV-233242 [APP-000472] The organization-defined role must verify correct operation of security functions in the c

