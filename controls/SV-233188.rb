control 'SV-233188' do
 title 'The container platform must enforce access restrictions for container platform
 configuration changes.'
 desc 'Configuration changes cause the container platform to
 change the way it operates. These changes can be used to improve the system with
 added features or performance, but these configuration changes can also be used to
 introduce malicious features and degrade performance. To control the configuration
 changes made to the container platform, it is important that only authorized users
 are allowed, through container platform enforcement, to make configuration
 changes.'
 desc 'check', 'Review documentation and configuration settings to determine if the
 container platform enforces access restrictions associated with changes to
 container platform components configuration. If the container platform does not
 enforce such access restrictions, this is a finding.'
 desc 'fix', 'Configure the container platform to enforce access
 restrictions associated with changes to the container platform components
 configuration.'
 impact 0.5
 tag check_id: 'C-36124r601793_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233188'
 tag rid: 'SV-233188r961461_rule'
 tag stig_id: 'SRG-APP-000380-CTR-000900'
 tag gtitle: 'SRG-APP-000380'
 tag fix_id: 'F-36092r601880_fix'
 tag 'documentable'
 tag cci: ['CCI-001813']
 tag nist: ['CM-5 (1) (a)']
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
