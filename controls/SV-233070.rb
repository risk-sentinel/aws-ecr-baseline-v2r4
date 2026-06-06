control 'SV-233070' do
 title 'Authentication files for the container platform must be protected.'
 desc 'The secure configuration of the container platform
 must be protected by disallowing changing to be implemented by non-privileged users.
 Changes to the container platform can introduce security risks and stability issues
 and undermine change management procedures. To secure authentication files from
 non-privileged user modification can be enforced using file ownership and
 permissions. Examples of authentication files are keys, certificates, and
 tokens.'
 desc 'check', 'Review the container platform to verify that authentication files
 cannot be modified by non-privileged users. If non-privileged users can modify
 key and certificate files, this is a finding.'
 desc 'fix', 'Configure the container platform to only allow
 authentication file modifications by privileged users.'
 impact 0.5
 tag check_id: 'C-36006r600697_chk'
 tag severity: 'medium'
 tag gid: 'V-233070'
 tag rid: 'SV-233070r960960_rule'
 tag stig_id: 'SRG-APP-000133-CTR-000310'
 tag gtitle: 'SRG-APP-000133'
 tag fix_id: 'F-35974r600698_fix'
 tag 'documentable'
 tag cci: ['CCI-001499']
 tag nist: ['CM-5 (6)']
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
