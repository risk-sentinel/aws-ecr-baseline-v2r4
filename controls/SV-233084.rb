control 'SV-233084' do
 title 'The container platform must use FIPS-validated SHA-1 or higher hash function to
 provide replay-resistant authentication mechanisms for network access to privileged
 accounts.'
 desc 'A replay attack may enable an unauthorized user to
 gain access to the application. Authentication sessions between the authenticator
 and the application validating the user credentials must not be vulnerable to a
 replay attack. Anti-replay is a cryptographically based mechanism; thus, it must use
 FIPS-approved algorithms. An authentication process resists replay attacks if it is
 impractical to achieve a successful authentication by recording and replaying a
 previous authentication message. Note that the anti-replay service is implicit when
 data contains monotonically increasing sequence numbers and data integrity is
 assured. Use of organization PKI is inherently compliant with this requirement for user and
 device access. Use of Transport Layer Security (TLS), including application
 protocols such as HTTPS and DNSSEC, that use TLS/SSL as the underlying security
 protocol is also compliant. Configure the information system to use the hash message
 authentication code (HMAC) algorithm for authentication services to Kerberos, SSH,
 web management tool, and any other access
 method.'
 desc 'check', 'Review the container platform configuration to determine if the
 container platform is configured to use FIPS-validated SHA-1 or higher hash
 function to provide replay-resistant authentication mechanisms for network
 access to privileged accounts. If the container platform is not configured to
 use FIPS-validated SHA-1 or higher hash function to provide replay-resistant
 authentication mechanisms for network access to privileged accounts, this is a
 finding.'
 desc 'fix', 'Configure the container platform to use
 FIPS-validated SHA-1 or higher hash function to provide replay-resistant
 authentication mechanisms for network access to privileged accounts.'
 impact 0.5
 tag check_id: 'C-36020r601716_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233084'
 tag rid: 'SV-233084r960993_rule'
 tag stig_id: 'SRG-APP-000156-CTR-000380'
 tag gtitle: 'SRG-APP-000156'
 tag fix_id: 'F-35988r600740_fix'
 tag 'documentable'
 tag cci: ['CCI-001941']
 tag nist: ['IA-2 (8)']
 tag ksi:  ['KSI-IAM-APM']
 tag nist_r4: ['IA-2 (8)']
 tag implementation_status: 'inherited'
 tag inherited_from: 'aws-shared-responsibility'

 # AWS-managed container-platform layer (runtime/host/control-plane/crypto-module/audit-
 # infra). Evidence = the leveraged the cloud-provider authorization manifest; Skip (not a
 # vacuous pass) until the consumer configures leveraged_evidence_base/inherited_evidence_uri.
 ev = input('inherited_evidence_uri', value: '')
 ev = attestation_uri(:leveraged, 'aws-container-platform-authorization', ext: 'json') if ev.to_s.empty?
 max_age = input('leveraged_evidence_max_age_days', value: 365)
 impact 0.5
 if ev.to_s.empty?
 describe 'AWS-inherited authorization evidence' do
 skip 'inherited-from-aws: AWS-managed layer; set leveraged_evidence_base / inherited_evidence_uri to the cloud-provider authorization manifest, or supply a SAF attestation.'
 end
 else
 doc = document_attestation(ev, max_age_days: max_age)
 describe "AWS authorization evidence (#{ev})" do
 it('exists') { expect(doc.exists?).to eq(true) }
 it('current') { expect(doc.current?(max_age)).to eq(true) }
 end
 end
end
