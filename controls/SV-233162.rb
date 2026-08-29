control 'SV-233162' do
 title 'The container platform must prevent non-privileged users from executing
 privileged functions to include disabling, circumventing, or altering implemented
 security safeguards/countermeasures.'
 desc 'Controlling what users can perform privileged
 functions prevents unauthorized users from performing tasks that may expose data or
 degrade the container platform. When users are not segregated into privileged and
 non-privileged users, unauthorized individuals may perform tasks such as deploying
 containers, pulling images into the register, and modify keys in the keystore. These
 actions can introduce malicious containers and cause denial-of-service (DoS) attacks
 and undermine the container platform integrity. The enforcement may take place at
 the container platform and can be implemented within each container platform
 component (e.g. runtime, registry, and
 keystore).'
 desc 'check', 'Review documentation to obtain the definition of the container
 platform functionality considered privileged in the context of the information
 system in question. Review the container platform security configuration and/or
 other means used to protect privileged functionality from unauthorized use. If
 the configuration does not protect all of the actions defined as privileged,
 this is a finding.'
 desc 'fix', 'Configure the container platform to security to
 protect all privileged functionality. Assigning roles that limit what actions a
 particular user can perform are the most common means of meeting this requirement.'
 impact 0.5
 tag check_id: 'C-36098r601762_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233162'
 tag rid: 'SV-233162r961353_rule'
 tag stig_id: 'SRG-APP-000340-CTR-000770'
 tag gtitle: 'SRG-APP-000340'
 tag fix_id: 'F-36066r600974_fix'
 tag 'documentable'
 tag cci: ['CCI-002235']
 tag nist: ['AC-6 (10)']
 tag ksi:  ['KSI-IAM-JIT']
 tag nist_r4: ['AC-6 (10)']
 tag implementation_status: 'inherited'
 tag inherited_from: 'aws-shared-responsibility'

 # AWS-managed: IAM identity internals / Fargate runtime / platform config (the cloud-provider authorization).
 ev = input('inherited_evidence_uri', value: '')
 ev = attestation_uri(:leveraged, 'aws-container-platform-authorization', ext: 'json') if ev.to_s.empty?
 max_age = input('leveraged_evidence_max_age_days', value: 365)
 impact 0.5
 if ev.to_s.empty?
 describe 'AWS-inherited authorization evidence' do
 skip 'inherited-from-aws: AWS-managed layer; set leveraged_evidence_base/inherited_evidence_uri to the cloud-provider authorization manifest, or supply a SAF attestation.'
 end
 else
 doc = document_attestation(ev, max_age_days: max_age)
 describe "AWS authorization evidence (#{ev})" do
 it('exists') { expect(doc.exists?).to eq(true) }
 it('current') { expect(doc.current?(max_age)).to eq(true) }
 end
 end
end
