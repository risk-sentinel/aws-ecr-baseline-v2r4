control 'SV-233208' do
 title 'The container platform must configure web management tools and Application
 Program Interfaces (API) with FIPS-validated Advanced Encryption Standard (AES)
 cipher block algorithm to protect the confidentiality of maintenance and diagnostic
 communications for nonlocal maintenance sessions.'
 desc 'Without confidentiality protection mechanisms,
 unauthorized individuals may gain access to sensitive information via a remote
 access session. Nonlocal maintenance and diagnostic activities are activities
 conducted by individuals communicating through either an external network (e.g., the
 internet) or an internal
 network.'
 desc 'check', 'Validate the container platform web management tools and Application
 Program Interfaces (API) are configured to use FIPS-validated Advanced
 Encryption Standard (AES) cipher block algorithms to protect the confidentiality
 of maintenance and diagnostic communications for nonlocal maintenance sessions.
 If the web management tools and API are not configured to use FIPS-validated
 Advanced Encryption Standard (AES) cipher block algorithms, this is a finding.'
 desc 'fix', 'Configure the container platform web management
 tools and Application Program Interfaces (API) with FIPS-validated Advanced
 Encryption Standard (AES) cipher block algorithm to protect the confidentiality of
 maintenance and diagnostic communications for nonlocal maintenance sessions.'
 impact 0.5
 tag check_id: 'C-36144r855392_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233208'
 tag rid: 'SV-233208r961557_rule'
 tag stig_id: 'SRG-APP-000412-CTR-001000'
 tag gtitle: 'SRG-APP-000412'
 tag fix_id: 'F-36112r878094_fix'
 tag 'documentable'
 tag cci: ['CCI-003123']
 tag nist: ['MA-4 (6)']
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
